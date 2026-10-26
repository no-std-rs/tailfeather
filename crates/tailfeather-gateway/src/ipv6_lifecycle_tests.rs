//! Behavioral coverage for delivery-committed IPv6 flow lifecycle state.

use super::tests::{address, tcp, udp};
use super::*;

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const FIN: u8 = 0x01;
const RST: u8 = 0x04;

fn endpoints() -> (Ipv6Addr, Ipv6Addr, Ipv6Addr) {
    (
        address("fd7a:115c:a1e0::1"),
        address("2001:db8::2"),
        address("2001:db8::1"),
    )
}

#[allow(clippy::too_many_arguments)]
fn segment(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    source_port: u16,
    destination_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
) -> [u8; 64] {
    let mut packet = tcp(source, destination, source_port, destination_port);
    packet[44..48].copy_from_slice(&sequence.to_be_bytes());
    packet[48..52].copy_from_slice(&acknowledgement.to_be_bytes());
    packet[53] = flags;
    update_checksum(&mut packet);
    Packet::parse(&packet).unwrap();
    packet
}

fn client_segment(port: u16, sequence: u32, acknowledgement: u32, flags: u8) -> [u8; 64] {
    let (client, server, _) = endpoints();
    segment(client, server, port, 443, sequence, acknowledgement, flags)
}

fn server_segment(port: u16, sequence: u32, acknowledgement: u32, flags: u8) -> [u8; 64] {
    let (_, server, uplink) = endpoints();
    segment(server, uplink, 443, port, sequence, acknowledgement, flags)
}

fn deliver(gateway: &mut Gateway, packet: &mut [u8], uplink: Ipv6Addr, now: u64) -> u16 {
    let original = Packet::parse(packet).unwrap();
    let source = original.source;
    let destination = original.destination;
    let prepared = gateway
        .prepare_outbound(packet, source, uplink, now)
        .unwrap();
    assert_eq!(prepared.destination(), destination);
    prepared.commit(now);
    Packet::parse(packet).unwrap().source_port
}

fn establish(gateway: &mut Gateway, client_port: u16, now: u64) -> u16 {
    let (client, _, uplink) = endpoints();
    let external = deliver(
        gateway,
        &mut client_segment(client_port, 100, 0, SYN),
        uplink,
        now,
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 500, 101, SYN | ACK),
            uplink,
            now + 1,
        ),
        Ok(client)
    );
    assert_eq!(
        deliver(
            gateway,
            &mut client_segment(client_port, 101, 501, ACK),
            uplink,
            now + 2,
        ),
        external
    );
    external
}

fn close(gateway: &mut Gateway, client_port: u16, external: u16, now: u64) {
    let (client, _, uplink) = endpoints();
    deliver(
        gateway,
        &mut client_segment(client_port, 101, 501, FIN | ACK),
        uplink,
        now,
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 102, FIN | ACK),
            uplink,
            now + 1,
        ),
        Ok(client)
    );
}

#[test]
fn discarded_new_preparations_do_not_consume_any_flow_slots() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let mut discarded_port = 0;
    for index in 0..SLOTS {
        let cursor = gateway.next_port;
        let released = gateway.last_tcp_release_ms;
        let mut packet = udp(client, server, 1_000 + index as u16, 443);
        let prepared = gateway
            .prepare_outbound(&mut packet, client, uplink, 0)
            .unwrap();
        assert_eq!(prepared.destination(), server);
        drop(prepared);
        assert_eq!(gateway.next_port, cursor);
        assert_eq!(gateway.last_tcp_release_ms, released);
        if index == 0 {
            discarded_port = Packet::parse(&packet).unwrap().source_port;
        }
    }
    assert_eq!(
        gateway.inbound(&mut udp(server, uplink, 443, discarded_port), uplink, 1),
        Err(Error::Unsolicited)
    );
    for index in 0..SLOTS {
        deliver(
            &mut gateway,
            &mut udp(client, server, 2_000 + index as u16, 443),
            uplink,
            2,
        );
    }
    assert!(matches!(
        gateway.prepare_outbound(&mut udp(client, server, 3_000, 443), client, uplink, 3),
        Err(Error::Capacity)
    ));
}

#[test]
fn discarded_address_change_preserves_the_existing_configuration() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = deliver(
        &mut gateway,
        &mut udp(client, server, 1_000, 443),
        uplink,
        0,
    );
    let mut packet = udp(client, server, 2_000, 443);
    drop(
        gateway
            .prepare_outbound(&mut packet, client, address("2001:db8::9"), 1)
            .unwrap(),
    );
    assert_eq!(
        gateway.inbound(&mut udp(server, uplink, 443, external), uplink, 2),
        Ok(client)
    );
}

#[test]
fn discarded_existing_preparation_does_not_refresh_udp_idle_time() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = deliver(
        &mut gateway,
        &mut udp(client, server, 1_000, 443),
        uplink,
        0,
    );
    let mut packet = udp(client, server, 1_000, 443);
    drop(
        gateway
            .prepare_outbound(&mut packet, client, uplink, IDLE_MS - 1)
            .unwrap(),
    );
    assert_eq!(
        gateway.inbound(&mut udp(server, uplink, 443, external), uplink, IDLE_MS),
        Err(Error::Unsolicited)
    );
}

#[test]
fn mapping_idle_time_starts_at_successful_delivery_commit() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let mut packet = udp(client, server, 1_000, 443);
    let prepared = gateway
        .prepare_outbound(&mut packet, client, uplink, 0)
        .unwrap();
    prepared.commit(1_000);
    let external = Packet::parse(&packet).unwrap().source_port;
    assert_eq!(
        gateway.inbound(&mut udp(server, uplink, 443, external), uplink, IDLE_MS),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut udp(server, uplink, 443, external), uplink, IDLE_MS * 2),
        Err(Error::Unsolicited)
    );
}

#[test]
fn final_fin_grace_starts_at_delivery_commit_and_later_ack_does_not_extend_it() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, FIN | ACK),
            uplink,
            3,
        ),
        Ok(client)
    );
    let mut fin = client_segment(1_000, 101, 502, FIN | ACK);
    let prepared = gateway
        .prepare_outbound(&mut fin, client, uplink, 4)
        .unwrap();
    prepared.commit(1_004);
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 2_004),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 3_004),
        Err(Error::Unsolicited)
    );
}

#[test]
fn discarded_tcp_fin_does_not_advance_sequence_or_complete_close() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let mut fin = client_segment(1_000, 101, 501, FIN | ACK);
    drop(
        gateway
            .prepare_outbound(&mut fin, client, uplink, 10)
            .unwrap(),
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, FIN | ACK),
            uplink,
            11,
        ),
        Ok(client)
    );
    // The server's FIN alone must remain active past the short closed grace.
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 502, ACK),
        uplink,
        2_011,
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 502, FIN | ACK),
        uplink,
        2_012,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 4_012),
        Err(Error::Unsolicited)
    );
}

#[test]
fn discarded_tcp_rst_does_not_retire_the_mapping() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let cursor = gateway.next_port;
    let released = gateway.last_tcp_release_ms;
    let mut rst = client_segment(1_000, 101, 501, RST | ACK);
    drop(
        gateway
            .prepare_outbound(&mut rst, client, uplink, 10)
            .unwrap(),
    );
    assert_eq!(gateway.next_port, cursor);
    assert_eq!(gateway.last_tcp_release_ms, released);
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 11),
        Ok(client)
    );
}

#[test]
fn discarded_tcp_payload_does_not_advance_the_expected_reset_sequence() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let mut payload = [0; 68];
    payload[..64].copy_from_slice(&client_segment(1_000, 101, 501, ACK));
    payload[4..6].copy_from_slice(&28u16.to_be_bytes());
    payload[64..].copy_from_slice(b"data");
    update_checksum(&mut payload);
    drop(
        gateway
            .prepare_outbound(&mut payload, client, uplink, 10)
            .unwrap(),
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 501, RST | ACK),
        uplink,
        11,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 12),
        Err(Error::Unsolicited)
    );
}

#[test]
fn initial_refusal_reset_requires_ack_of_the_client_syn() {
    let (client, _, uplink) = endpoints();
    for (sequence, acknowledgement, flags) in [(0, 0, RST), (0, 100, RST | ACK)] {
        let mut gateway = Gateway::new();
        let external = deliver(
            &mut gateway,
            &mut client_segment(1_000, 100, 0, SYN),
            uplink,
            0,
        );
        let _ = gateway.inbound(
            &mut server_segment(external, sequence, acknowledgement, flags),
            uplink,
            1,
        );
        assert_eq!(
            gateway.inbound(
                &mut server_segment(external, 500, 101, SYN | ACK),
                uplink,
                2,
            ),
            Ok(client),
            "an invalid initial RST must leave the SYN mapping alive"
        );
    }
    let mut gateway = Gateway::new();
    let external = deliver(
        &mut gateway,
        &mut client_segment(1_000, 100, 0, SYN),
        uplink,
        0,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 0, 101, RST | ACK), uplink, 1),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 500, 101, SYN | ACK),
            uplink,
            2,
        ),
        Err(Error::Unsolicited)
    );
}

#[test]
fn established_server_reset_requires_the_exact_server_next_sequence() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let _ = gateway.inbound(
        &mut server_segment(external, 500, 101, RST | ACK),
        uplink,
        3,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 4),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, RST | ACK),
            uplink,
            5
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 6),
        Err(Error::Unsolicited)
    );
}

#[test]
fn established_client_reset_requires_the_exact_client_next_sequence() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let mut invalid = client_segment(1_000, 100, 501, RST | ACK);
    if let Ok(prepared) = gateway.prepare_outbound(&mut invalid, client, uplink, 3) {
        prepared.commit(3);
    }
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 4),
        Ok(client)
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 501, RST | ACK),
        uplink,
        5,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 6),
        Err(Error::Unsolicited)
    );
}

#[test]
fn invalid_client_fin_cannot_complete_the_servers_one_sided_close() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let mut invalid = client_segment(1_000, 100, 501, FIN | ACK);
    if let Ok(prepared) = gateway.prepare_outbound(&mut invalid, client, uplink, 3) {
        prepared.commit(3);
    }
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, FIN | ACK),
            uplink,
            4,
        ),
        Ok(client)
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 502, FIN | ACK),
        uplink,
        2_004,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 4_004),
        Err(Error::Unsolicited)
    );
}

#[test]
fn invalid_server_fin_cannot_complete_the_clients_one_sided_close() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let _ = gateway.inbound(
        &mut server_segment(external, 500, 101, FIN | ACK),
        uplink,
        3,
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 501, FIN | ACK),
        uplink,
        4,
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 102, FIN | ACK),
            uplink,
            2_004,
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 4_004),
        Err(Error::Unsolicited)
    );
}

#[test]
fn one_sided_fin_remains_active_under_capacity_pressure() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let mut first = 0;
    for index in 0..SLOTS {
        let port = 1_000 + index as u16;
        let external = establish(&mut gateway, port, index as u64 * 10);
        if index == 0 {
            first = external;
        }
        deliver(
            &mut gateway,
            &mut client_segment(port, 101, 501, FIN | ACK),
            uplink,
            index as u64 * 10 + 3,
        );
    }
    let mut next = client_segment(2_000, 100, 0, SYN);
    assert!(matches!(
        gateway.prepare_outbound(&mut next, client, uplink, 2_500),
        Err(Error::Capacity)
    ));
    assert_eq!(
        gateway.inbound(&mut server_segment(first, 501, 102, ACK), uplink, 2_501),
        Ok(client)
    );
}

#[test]
fn thirty_three_sequential_closed_sessions_reclaim_capacity_and_rotate_ports() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let mut oldest = 0;
    for index in 0..=SLOTS {
        let port = 1_000 + index as u16;
        let now = index as u64 * 10;
        let external = establish(&mut gateway, port, now);
        if index == 0 {
            oldest = external;
        } else {
            assert_ne!(external, oldest);
        }
        close(&mut gateway, port, external, now + 3);
    }
    // All sessions completed within 325ms: reuse occurred under pressure,
    // without waiting for the normal two-second closed grace.
    assert_eq!(
        gateway.inbound(&mut server_segment(oldest, 502, 102, ACK), uplink, 400),
        Err(Error::Unsolicited)
    );
    let mut next = client_segment(2_000, 100, 0, SYN);
    let external = deliver(&mut gateway, &mut next, uplink, 401);
    assert_ne!(external, oldest);
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 500, 101, SYN | ACK),
            uplink,
            402,
        ),
        Ok(client)
    );
}

#[test]
fn late_ack_and_fin_retransmissions_do_not_extend_the_first_closed_grace() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    close(&mut gateway, 1_000, external, 3); // Fully closed at t=4.
    for (now, sequence, flags) in [(1_000, 102, ACK), (1_500, 101, FIN | ACK)] {
        deliver(
            &mut gateway,
            &mut client_segment(1_000, sequence, 502, flags),
            uplink,
            now,
        );
    }
    for (now, sequence, flags) in [(1_750, 502, ACK), (1_900, 501, FIN | ACK)] {
        assert_eq!(
            gateway.inbound(
                &mut server_segment(external, sequence, 102, flags),
                uplink,
                now,
            ),
            Ok(client)
        );
    }
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 2_004),
        Err(Error::Unsolicited)
    );
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 102, 502, ACK),
            client,
            uplink,
            2_004,
        ),
        Err(Error::Unsolicited)
    ));
}

#[test]
fn committed_uplink_change_and_owner_clear_reject_stale_returns() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let old = deliver(
        &mut gateway,
        &mut udp(client, server, 1_000, 443),
        uplink,
        0,
    );
    let replacement = address("2001:db8::9");
    let fresh = deliver(
        &mut gateway,
        &mut udp(client, server, 1_000, 443),
        replacement,
        1,
    );
    assert_ne!(fresh, old);
    assert_eq!(
        gateway.inbound(&mut udp(server, replacement, 443, old), replacement, 2),
        Err(Error::Unsolicited)
    );
    assert_eq!(
        gateway.inbound(&mut udp(server, replacement, 443, fresh), replacement, 3),
        Ok(client)
    );
    gateway.clear(2);
    let reassigned = deliver(
        &mut gateway,
        &mut udp(client, server, 1_000, 443),
        replacement,
        4,
    );
    assert_ne!(reassigned, fresh);
    assert_eq!(
        gateway.inbound(&mut udp(server, replacement, 443, fresh), replacement, 5),
        Err(Error::Unsolicited)
    );
    assert_eq!(
        gateway.inbound(
            &mut udp(server, replacement, 443, reassigned),
            replacement,
            6
        ),
        Ok(client)
    );
}

#[test]
fn discarded_closed_slot_replacement_does_not_advance_cursor_or_release_time() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    close(&mut gateway, 1_000, external, 3);
    let cursor = gateway.next_port;
    let released = gateway.last_tcp_release_ms;
    assert_eq!(released, Some(4));
    let mut packet = client_segment(1_000, 900, 0, SYN);
    drop(
        gateway
            .prepare_outbound(&mut packet, client, uplink, 1_000)
            .unwrap(),
    );
    assert_eq!(gateway.next_port, cursor);
    assert_eq!(gateway.last_tcp_release_ms, released);
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 1_001),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 502, 102, ACK), uplink, 2_004),
        Err(Error::Unsolicited)
    );
}

#[test]
fn actual_twenty_thousand_and_one_tcp_releases_quarantine_port_cursor_wrap() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let count = u32::from(65_000 - PORT_BASE) + 1;
    assert_eq!(count, 20_001);
    for index in 0..count {
        let now = u64::from(index) * 2;
        let external = deliver(
            &mut gateway,
            &mut client_segment(1_000, 100, 0, SYN),
            uplink,
            now,
        );
        assert_eq!(u32::from(external), u32::from(PORT_BASE) + index);
        assert_eq!(
            gateway.inbound(
                &mut server_segment(external, 0, 101, RST | ACK),
                uplink,
                now + 1
            ),
            Ok(client)
        );
    }
    let last_release = u64::from(count - 1) * 2 + 1;
    assert!(last_release < TCP_PORT_REUSE_MS);
    assert_eq!(gateway.next_port, 0, "cursor must remain wrap-pending");
    assert_eq!(gateway.last_tcp_release_ms, Some(last_release));
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 900, 0, SYN),
            client,
            uplink,
            last_release + 1,
        ),
        Err(Error::Capacity)
    ));
    let before_safe = last_release + TCP_PORT_REUSE_MS - 1;
    assert_eq!(
        gateway.inbound(
            &mut server_segment(PORT_BASE, 500, 101, SYN | ACK),
            uplink,
            before_safe,
        ),
        Err(Error::Unsolicited),
        "an old return must not find a newly recycled external tuple"
    );
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 900, 0, SYN),
            client,
            uplink,
            before_safe,
        ),
        Err(Error::Capacity)
    ));
    let external = deliver(
        &mut gateway,
        &mut client_segment(1_000, 900, 0, SYN),
        uplink,
        last_release + TCP_PORT_REUSE_MS,
    );
    assert_eq!(external, PORT_BASE);
}

#[test]
fn tcp_wrap_quarantine_starts_at_recent_release_not_the_old_open_time() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let old = deliver(
        &mut gateway,
        &mut client_segment(1_000, 100, 0, SYN),
        uplink,
        0,
    );
    // The ring churn itself is covered above. Put this independent case at
    // the wrap boundary while the long-opened mapping is still active.
    gateway.next_port = 0;
    let released = 100_000;
    assert!(released > TCP_PORT_REUSE_MS && released < IDLE_MS);
    assert_eq!(
        gateway.inbound(
            &mut server_segment(old, 0, 101, RST | ACK),
            uplink,
            released
        ),
        Ok(client)
    );
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 900, 0, SYN),
            client,
            uplink,
            released + TCP_PORT_REUSE_MS - 1,
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(
        deliver(
            &mut gateway,
            &mut client_segment(1_000, 900, 0, SYN),
            uplink,
            released + TCP_PORT_REUSE_MS,
        ),
        PORT_BASE
    );
}

#[test]
fn owner_clear_quarantines_recently_released_tcp_ports_before_cursor_wrap() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let old = deliver(
        &mut gateway,
        &mut client_segment(1_000, 100, 0, SYN),
        uplink,
        0,
    );
    gateway.next_port = 0;
    let cleared = 100_000;
    gateway.clear(cleared);
    assert_eq!(gateway.last_tcp_release_ms, Some(cleared));
    assert_eq!(
        gateway.inbound(
            &mut server_segment(old, 500, 101, SYN | ACK),
            uplink,
            cleared + 1
        ),
        Err(Error::Unsolicited)
    );
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 900, 0, SYN),
            client,
            uplink,
            cleared + TCP_PORT_REUSE_MS - 1,
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(
        deliver(
            &mut gateway,
            &mut client_segment(1_000, 900, 0, SYN),
            uplink,
            cleared + TCP_PORT_REUSE_MS,
        ),
        PORT_BASE
    );
}

#[test]
fn releasing_an_old_flow_ahead_of_or_equal_to_the_wrapped_cursor_restarts_quarantine() {
    let (client, _, uplink) = endpoints();
    for old_port in [60_000, PORT_BASE + 1] {
        let mut gateway = Gateway::new();
        gateway.next_port = old_port;
        let old = establish(&mut gateway, 1_000, 0);
        assert_eq!(old, old_port);
        // Keep this old TCP flow alive while allowing a new cycle to begin.
        gateway.next_port = 0;
        assert_eq!(
            deliver(
                &mut gateway,
                &mut client_segment(2_000, 100, 0, SYN),
                uplink,
                60_000,
            ),
            PORT_BASE
        );
        assert_eq!(gateway.next_port, PORT_BASE + 1);
        assert!(old >= gateway.next_port);

        // A failed enqueue cannot release the surviving old-cycle flow or
        // restart quarantine, even though committing this RST would do so.
        let cursor = gateway.next_port;
        let released = gateway.last_tcp_release_ms;
        let mut rst = client_segment(1_000, 101, 501, RST | ACK);
        drop(
            gateway
                .prepare_outbound(&mut rst, client, uplink, 60_001)
                .unwrap(),
        );
        assert_eq!(gateway.next_port, cursor);
        assert_eq!(gateway.last_tcp_release_ms, released);
        assert_eq!(
            gateway.inbound(&mut server_segment(old, 501, 101, ACK), uplink, 60_002),
            Ok(client)
        );
        let released_at = 60_003;
        assert_eq!(
            gateway.inbound(
                &mut server_segment(old, 501, 101, RST | ACK),
                uplink,
                released_at,
            ),
            Ok(client)
        );
        assert_eq!(gateway.last_tcp_release_ms, Some(released_at));
        assert_eq!(gateway.next_port, 0);
        assert_eq!(
            gateway.inbound(
                &mut server_segment(old, 501, 101, ACK),
                uplink,
                released_at + TCP_PORT_REUSE_MS - 1,
            ),
            Err(Error::Unsolicited)
        );
        assert!(matches!(
            gateway.prepare_outbound(
                &mut client_segment(3_000, 100, 0, SYN),
                client,
                uplink,
                released_at + TCP_PORT_REUSE_MS - 1,
            ),
            Err(Error::Capacity)
        ));
        // The current-cycle PORT_BASE mapping remains live and is skipped.
        assert_eq!(
            deliver(
                &mut gateway,
                &mut client_segment(3_000, 100, 0, SYN),
                uplink,
                released_at + TCP_PORT_REUSE_MS,
            ),
            PORT_BASE + 1
        );
    }
}

#[test]
fn skipping_occupied_port_65000_cannot_bypass_the_wrap_quarantine() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    gateway.next_port = 65_000;
    let occupied = deliver(
        &mut gateway,
        &mut client_segment(1_000, 100, 0, SYN),
        uplink,
        0,
    );
    assert_eq!(occupied, 65_000);
    let other = deliver(
        &mut gateway,
        &mut client_segment(2_000, 100, 0, SYN),
        uplink,
        0,
    );
    assert_eq!(other, PORT_BASE);
    assert_eq!(
        gateway.inbound(&mut server_segment(other, 0, 101, RST | ACK), uplink, 1),
        Ok(client)
    );
    gateway.next_port = 65_000;
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(3_000, 100, 0, SYN),
            client,
            uplink,
            TCP_PORT_REUSE_MS,
        ),
        Err(Error::Capacity)
    ));
    assert_eq!(
        gateway.next_port, 65_000,
        "failed scan cannot advance the cursor"
    );
    assert_eq!(
        deliver(
            &mut gateway,
            &mut client_segment(3_000, 100, 0, SYN),
            uplink,
            TCP_PORT_REUSE_MS + 1,
        ),
        PORT_BASE
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(occupied, 500, 101, SYN | ACK),
            uplink,
            TCP_PORT_REUSE_MS + 2,
        ),
        Ok(client)
    );
}

#[test]
fn reclaiming_an_old_tcp_port_ahead_of_the_cursor_preserves_commit_quarantine() {
    let (client, server, uplink) = endpoints();
    let mut gateway = Gateway::new();
    gateway.next_port = 60_000;
    let old = establish(&mut gateway, 1_000, 0);
    close(&mut gateway, 1_000, old, 3);
    assert_eq!(gateway.last_tcp_release_ms, Some(4));
    gateway.next_port = 0;
    let wrapped_at = 4 + TCP_PORT_REUSE_MS;
    // Fill every other slot after the old close's release quarantine passes.
    // The closed TCP entry remains stored until pressure actually reclaims it.
    for index in 0..SLOTS - 1 {
        deliver(
            &mut gateway,
            &mut udp(client, server, 2_000 + index as u16, 443),
            uplink,
            wrapped_at,
        );
    }
    let cursor = gateway.next_port;
    assert_eq!(cursor, PORT_BASE + SLOTS as u16 - 1);
    assert!(old > cursor);
    let mut discarded = udp(client, server, 3_000, 443);
    drop(
        gateway
            .prepare_outbound(&mut discarded, client, uplink, wrapped_at + 1)
            .unwrap(),
    );
    assert_eq!(gateway.next_port, cursor);
    assert_eq!(gateway.last_tcp_release_ms, Some(4));
    let external = deliver(
        &mut gateway,
        &mut udp(client, server, 3_000, 443),
        uplink,
        wrapped_at + 1,
    );
    assert_eq!(external, cursor);
    assert_eq!(gateway.last_tcp_release_ms, Some(wrapped_at + 1));
    assert_eq!(
        gateway.next_port, 0,
        "commit must retain the quarantine from the reclaimed OLD TCP port"
    );
    assert_eq!(
        gateway.inbound(
            &mut udp(server, uplink, 443, external),
            uplink,
            wrapped_at + 2
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(old, 502, 102, ACK),
            uplink,
            wrapped_at + 2
        ),
        Err(Error::Unsolicited)
    );
}

#[test]
fn expired_tcp_requires_a_new_syn_and_resets_sequence_validation() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let old = establish(&mut gateway, 1_000, 0);
    let now = IDLE_MS + 2;
    assert_eq!(
        gateway.inbound(&mut server_segment(old, 501, 101, ACK), uplink, now),
        Err(Error::Unsolicited)
    );
    assert!(matches!(
        gateway.prepare_outbound(
            &mut client_segment(1_000, 101, 501, ACK),
            client,
            uplink,
            now,
        ),
        Err(Error::Unsolicited)
    ));
    let fresh = deliver(
        &mut gateway,
        &mut client_segment(1_000, 900, 0, SYN),
        uplink,
        now + 1,
    );
    assert_ne!(fresh, old);
    assert_eq!(
        gateway.inbound(&mut server_segment(old, 501, 101, ACK), uplink, now + 2),
        Err(Error::Unsolicited)
    );
    let _ = gateway.inbound(
        &mut server_segment(fresh, 0, 101, RST | ACK),
        uplink,
        now + 3,
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(fresh, 0, 901, RST | ACK),
            uplink,
            now + 4,
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(fresh, 500, 901, SYN | ACK),
            uplink,
            now + 5,
        ),
        Err(Error::Unsolicited)
    );
}

#[test]
fn same_tuple_fresh_syn_resets_old_sequence_and_fin_state_only_on_commit() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    let mut discarded = client_segment(1_000, 900, 0, SYN);
    drop(
        gateway
            .prepare_outbound(&mut discarded, client, uplink, 3)
            .unwrap(),
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, RST | ACK),
            uplink,
            4
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 5),
        Err(Error::Unsolicited),
        "discarding a new SYN must preserve the old exact reset sequence"
    );

    let mut gateway = Gateway::new();
    let _ = establish(&mut gateway, 1_000, 0);
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 101, 501, FIN | ACK),
        uplink,
        3,
    );
    // An endpoint can reuse the tuple after a reset was lost in transit.
    let fresh = deliver(
        &mut gateway,
        &mut client_segment(1_000, 900, 0, SYN),
        uplink,
        4,
    );
    let _ = gateway.inbound(&mut server_segment(fresh, 0, 101, RST | ACK), uplink, 5);
    assert_eq!(
        gateway.inbound(&mut server_segment(fresh, 800, 901, SYN | ACK), uplink, 6,),
        Ok(client)
    );
    let _ = gateway.inbound(&mut server_segment(fresh, 501, 901, RST | ACK), uplink, 7);
    assert_eq!(
        gateway.inbound(&mut server_segment(fresh, 801, 901, FIN | ACK), uplink, 8,),
        Ok(client)
    );
    // The previous client's FIN must not combine with this session's FIN.
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 901, 802, ACK),
        uplink,
        2_008,
    );
    deliver(
        &mut gateway,
        &mut client_segment(1_000, 901, 802, FIN | ACK),
        uplink,
        2_009,
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(fresh, 802, 902, ACK), uplink, 4_009),
        Err(Error::Unsolicited)
    );
}

#[test]
fn retransmitted_initial_syn_preserves_the_known_server_reset_sequence() {
    let (client, _, uplink) = endpoints();
    let mut gateway = Gateway::new();
    let external = establish(&mut gateway, 1_000, 0);
    assert_eq!(
        deliver(
            &mut gateway,
            &mut client_segment(1_000, 100, 0, SYN),
            uplink,
            3,
        ),
        external
    );
    let _ = gateway.inbound(&mut server_segment(external, 0, 101, RST | ACK), uplink, 4);
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 5),
        Ok(client),
        "a retransmitted SYN must not restore the initial-refusal RST exception"
    );
    assert_eq!(
        gateway.inbound(
            &mut server_segment(external, 501, 101, RST | ACK),
            uplink,
            6
        ),
        Ok(client)
    );
    assert_eq!(
        gateway.inbound(&mut server_segment(external, 501, 101, ACK), uplink, 7),
        Err(Error::Unsolicited)
    );
}

#[test]
fn zero_next_sequence_after_wrap_is_known_for_fin_and_reset_validation() {
    let (client, _, uplink) = endpoints();
    // Exercise both reset directions and both FIN directions after SYNs wrap.
    for ending in [0, 1, 2] {
        let mut gateway = Gateway::new();
        let external = deliver(
            &mut gateway,
            &mut client_segment(1_000, u32::MAX, 0, SYN),
            uplink,
            0,
        );
        assert_eq!(
            gateway.inbound(
                &mut server_segment(external, u32::MAX, 0, SYN | ACK),
                uplink,
                1,
            ),
            Ok(client)
        );
        deliver(
            &mut gateway,
            &mut client_segment(1_000, 0, 0, ACK),
            uplink,
            2,
        );
        let _ = gateway.inbound(
            &mut server_segment(external, u32::MAX, 0, RST | ACK),
            uplink,
            3,
        );
        assert_eq!(
            gateway.inbound(&mut server_segment(external, 0, 0, ACK), uplink, 4),
            Ok(client)
        );
        if ending == 0 {
            deliver(
                &mut gateway,
                &mut client_segment(1_000, 0, 0, FIN | ACK),
                uplink,
                5,
            );
            assert_eq!(
                gateway.inbound(&mut server_segment(external, 0, 1, FIN | ACK), uplink, 6),
                Ok(client)
            );
            assert_eq!(
                gateway.inbound(&mut server_segment(external, 1, 1, ACK), uplink, 2_006),
                Err(Error::Unsolicited)
            );
        } else {
            if ending == 1 {
                deliver(
                    &mut gateway,
                    &mut client_segment(1_000, 0, 0, RST | ACK),
                    uplink,
                    5,
                );
            } else {
                assert_eq!(
                    gateway.inbound(&mut server_segment(external, 0, 0, RST | ACK), uplink, 5),
                    Ok(client)
                );
            }
            assert_eq!(
                gateway.inbound(&mut server_segment(external, 0, 0, ACK), uplink, 6),
                Err(Error::Unsolicited)
            );
        }
    }
}

fn echo(source: Ipv6Addr, destination: Ipv6Addr, identifier: u16, reply: bool) -> [u8; 48] {
    let mut packet = [0; 48];
    packet[0] = 0x60;
    packet[4..6].copy_from_slice(&8u16.to_be_bytes());
    packet[6] = 58;
    packet[7] = 64;
    packet[8..24].copy_from_slice(&source.octets());
    packet[24..40].copy_from_slice(&destination.octets());
    packet[40] = if reply { 129 } else { 128 };
    packet[44..46].copy_from_slice(&identifier.to_be_bytes());
    packet[46..48].copy_from_slice(&1u16.to_be_bytes());
    update_checksum(&mut packet);
    packet
}

#[test]
fn udp_and_echo_retain_their_120_second_idle_timeout() {
    let (client, server, uplink) = endpoints();
    for protocol in [17, 58] {
        let mut gateway = Gateway::new();
        let external = if protocol == 17 {
            deliver(
                &mut gateway,
                &mut udp(client, server, 1_000, 443),
                uplink,
                0,
            )
        } else {
            deliver(
                &mut gateway,
                &mut echo(client, server, 1_000, false),
                uplink,
                0,
            )
        };
        if protocol == 17 {
            assert_eq!(
                gateway.inbound(&mut udp(server, uplink, 443, external), uplink, IDLE_MS - 1),
                Ok(client)
            );
            assert_eq!(
                gateway.inbound(
                    &mut udp(server, uplink, 443, external),
                    uplink,
                    IDLE_MS * 2 - 1,
                ),
                Err(Error::Unsolicited)
            );
        } else {
            assert_eq!(
                gateway.inbound(
                    &mut echo(server, uplink, external, true),
                    uplink,
                    IDLE_MS - 1
                ),
                Ok(client)
            );
            assert_eq!(
                gateway.inbound(
                    &mut echo(server, uplink, external, true),
                    uplink,
                    IDLE_MS * 2 - 1,
                ),
                Err(Error::Unsolicited)
            );
        }
    }
}
