//! Allocation-free packet processing shared by the ESP firmware and the bare
//! interoperability harness.
//!
//! This crate deliberately owns no sockets or runtime. It only parses and
//! rewrites packets and maintains fixed-capacity flow state, so firmware and
//! Linux-none tests exercise the exact same gateway implementation.

#![no_std]

mod inner;
pub mod ipv6;
pub mod nat;
pub mod peerapi;
pub mod policy;

pub use inner::{checksum, icmp_echo_reply};

#[cfg(test)]
mod tests {
    use super::{checksum, nat};

    fn udp_packet(payload: &[u8]) -> [u8; 128] {
        let mut packet = [0u8; 128];
        let len = nat::build_udp4(
            [100, 64, 0, 2],
            12345,
            [192, 0, 2, 10],
            5353,
            payload,
            &mut packet,
        )
        .unwrap();
        packet[len..].fill(0xcc);
        packet
    }

    #[test]
    fn in_place_udp_construction_matches_the_two_buffer_builder() {
        let payload = b"in-place reply";
        let expected = udp_packet(payload);
        let mut packet = [0u8; 128];
        packet[..payload.len()].copy_from_slice(payload);
        let len = nat::build_udp4_in_place(
            [100, 64, 0, 2],
            12345,
            [192, 0, 2, 10],
            5353,
            payload.len(),
            &mut packet,
        )
        .unwrap();
        assert_eq!(&packet[..len], &expected[..len]);
    }

    fn tcp_packet(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> [u8; 44] {
        let mut packet = [0u8; 44];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&44u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20..22].copy_from_slice(&src_port.to_be_bytes());
        packet[22..24].copy_from_slice(&dst_port.to_be_bytes());
        packet[32] = 0x60; // 24-byte TCP header
        packet[33] = 0x02; // SYN
        packet[34..36].copy_from_slice(&4096u16.to_be_bytes());
        packet[40..44].copy_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460

        packet[10..12].fill(0);
        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());

        write_tcp_checksum(&mut packet);
        packet
    }

    fn tcp_packet_with_options(options: [u8; 8]) -> [u8; 48] {
        let mut packet = [0u8; 48];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&48u16.to_be_bytes());
        packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
        packet[16..20].copy_from_slice(&[192, 0, 2, 10]);
        packet[20..22].copy_from_slice(&12345u16.to_be_bytes());
        packet[22..24].copy_from_slice(&443u16.to_be_bytes());
        packet[32] = 0x70; // 28-byte TCP header
        packet[33] = 0x02; // SYN
        packet[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
        packet[40..48].copy_from_slice(&options);

        let ip_sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        write_tcp_checksum(&mut packet);
        packet
    }

    fn write_tcp_checksum(packet: &mut [u8]) {
        let tcp_len = packet.len() - 20;
        packet[36..38].fill(0);
        let mut pseudo = [0u8; 1600];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo[12..12 + tcp_len].copy_from_slice(&packet[20..]);
        let tcp_sum = checksum(&pseudo[..12 + tcp_len]);
        packet[36..38].copy_from_slice(&tcp_sum.to_be_bytes());
    }

    fn tcp_checksum_valid(packet: &[u8]) -> bool {
        let tcp_len = packet.len() - 20;
        let mut pseudo = [0u8; 1600];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 6;
        pseudo[10..12].copy_from_slice(&(tcp_len as u16).to_be_bytes());
        pseudo[12..12 + tcp_len].copy_from_slice(&packet[20..]);
        checksum(&pseudo[..12 + tcp_len]) == 0
    }

    fn udp_checksum_valid(packet: &[u8]) -> bool {
        let udp_len = packet.len() - 20;
        let mut pseudo = [0u8; 1600];
        pseudo[..4].copy_from_slice(&packet[12..16]);
        pseudo[4..8].copy_from_slice(&packet[16..20]);
        pseudo[9] = 17;
        pseudo[10..12].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pseudo[12..12 + udp_len].copy_from_slice(&packet[20..]);
        checksum(&pseudo[..12 + udp_len]) == 0
    }

    fn icmp_packet(kind: u8, src: [u8; 4], dst: [u8; 4], identifier: u16) -> [u8; 32] {
        let mut packet = [0u8; 32];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&32u16.to_be_bytes());
        packet[8] = 64;
        packet[9] = 1;
        packet[12..16].copy_from_slice(&src);
        packet[16..20].copy_from_slice(&dst);
        packet[20] = kind;
        packet[24..26].copy_from_slice(&identifier.to_be_bytes());
        packet[28..32].copy_from_slice(b"ping");
        let sum = checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&sum.to_be_bytes());
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());
        packet
    }

    #[test]
    fn icmp_echo_translation_round_trips_and_rejects_wrong_servers() {
        let client = [100, 64, 0, 2];
        let server = [1, 1, 1, 1];
        let uplink = [192, 0, 2, 5];
        let mut table = nat::IcmpTable::new();
        let mut request = icmp_packet(8, client, server, 0x1234);
        let slot = table
            .slot_for(&nat::parse_icmp4(&request).unwrap(), 0)
            .unwrap();
        assert!(nat::rewrite_icmp_outbound(&mut request, uplink, slot));
        assert_eq!(&request[12..16], &uplink);
        assert_eq!(checksum(&request[..20]), 0);
        assert_eq!(checksum(&request[20..]), 0);

        let mut wrong = icmp_packet(0, [1, 0, 0, 1], uplink, nat::ICMP_ID_BASE + slot as u16);
        assert!(
            table
                .reverse(&nat::parse_icmp4(&wrong).unwrap(), uplink, 1)
                .is_none()
        );

        let mut reply = icmp_packet(0, server, uplink, nat::ICMP_ID_BASE + slot as u16);
        let flow = table
            .reverse(&nat::parse_icmp4(&reply).unwrap(), uplink, 1)
            .unwrap();
        assert!(nat::rewrite_icmp_inbound(&mut reply, flow));
        assert_eq!(&reply[16..20], &client);
        assert_eq!(&reply[24..26], &0x1234u16.to_be_bytes());
        assert_eq!(checksum(&reply[..20]), 0);
        assert_eq!(checksum(&reply[20..]), 0);

        // Keep this mutable so accidental API changes do not turn this test
        // into a construction-only check.
        wrong[0] = 0;
        assert!(nat::parse_icmp4(&wrong).is_none());

        let mut corrupt = icmp_packet(8, client, server, 0x1234);
        corrupt[28] ^= 1;
        assert!(nat::parse_icmp4(&corrupt).is_none());
    }

    #[test]
    fn uncommitted_icmp_slots_do_not_exhaust_the_table() {
        let mut table = nat::IcmpTable::new();
        for identifier in 0..nat::ICMP_SLOTS as u16 {
            let request = icmp_packet(8, [100, 64, 0, 2], [1, 1, 1, 1], identifier);
            let info = nat::parse_icmp4(&request).unwrap();
            assert_eq!(table.slot_for_packet(&info, identifier as u64), Some(0));
        }

        let request = icmp_packet(8, [100, 64, 0, 2], [8, 8, 8, 8], 99);
        let info = nat::parse_icmp4(&request).unwrap();
        let slot = table.slot_for_packet(&info, 10).unwrap();
        assert_eq!(slot, 0);
        table.observe_outbound(slot, &info, 10);

        let next = icmp_packet(8, [100, 64, 0, 2], [9, 9, 9, 9], 100);
        assert_eq!(
            table.slot_for_packet(&nat::parse_icmp4(&next).unwrap(), 11),
            Some(1)
        );
    }

    #[test]
    fn udp_table_reuses_flows_expires_oldest_and_never_evicts_live_entries() {
        let mut table = nat::Table::new();
        for slot in 0..nat::SLOTS {
            assert_eq!(
                table.slot_for(
                    [1, 1, 1, slot as u8],
                    1000 + slot as u16,
                    [2, 2, 2, 2],
                    53,
                    0
                ),
                Some(slot)
            );
        }
        assert_eq!(table.slot_for([9; 4], 9, [8; 4], 8, 1), None);
        assert_eq!(
            table.slot_for([1, 1, 1, 2], 1002, [2, 2, 2, 2], 53, 2),
            Some(2)
        );
        assert_eq!(
            table.slot_for([9; 4], 9, [8; 4], 8, nat::IDLE_TIMEOUT_MS),
            Some(0)
        );
    }

    #[test]
    fn tcp_table_scales_to_48_and_expires_idle_entries() {
        let mut table = nat::TcpTable::new();
        let slot = table.slot_for([1; 4], 111, [2; 4], 222, 0).unwrap();
        table.release(slot, 0);
        assert!(table.get(slot).is_none());
        for index in 0..nat::TCP_SLOTS {
            assert!(
                table
                    .slot_for([3, 3, 3, index as u8], index as u16, [4; 4], 443, 0)
                    .is_some()
            );
        }
        assert!(table.slot_for([5; 4], 5, [6; 4], 6, 1).is_none());
        assert!(
            table
                .slot_for([5; 4], 5, [6; 4], 6, nat::TCP_IDLE_TIMEOUT_MS)
                .is_some()
        );
    }

    #[test]
    fn tcp_mapping_allocation_requires_an_initial_syn() {
        let mut table = nat::TcpTable::new();
        for index in 0..nat::TCP_SLOTS {
            let mut packet = tcp_packet([1, 1, 1, index as u8], [2; 4], 1000 + index as u16, 443);
            packet[33] = if index % 2 == 0 { 0x10 } else { 0x11 }; // ACK or FIN|ACK
            write_tcp_checksum(&mut packet);
            assert!(
                table
                    .slot_for_packet(&nat::parse_tcp4(&packet).unwrap(), index as u64)
                    .is_none()
            );
        }

        let mut syn_ack = tcp_packet([3; 4], [4; 4], 3000, 443);
        syn_ack[33] = 0x12;
        write_tcp_checksum(&mut syn_ack);
        assert!(
            table
                .slot_for_packet(&nat::parse_tcp4(&syn_ack).unwrap(), 20)
                .is_none()
        );
        let mut syn_fin = syn_ack;
        syn_fin[33] = 0x03;
        write_tcp_checksum(&mut syn_fin);
        assert!(
            table
                .slot_for_packet(&nat::parse_tcp4(&syn_fin).unwrap(), 20)
                .is_none()
        );

        let syn = tcp_packet([5; 4], [6; 4], 5000, 443);
        let syn = nat::parse_tcp4(&syn).unwrap();
        let slot = table.slot_for_packet(&syn, 21).unwrap();
        let mut ack = tcp_packet([5; 4], [6; 4], 5000, 443);
        ack[33] = 0x10;
        write_tcp_checksum(&mut ack);
        assert!(
            table
                .slot_for_packet(&nat::parse_tcp4(&ack).unwrap(), 22)
                .is_none()
        );
        table.observe_outbound(slot, &syn, 21);
        assert_eq!(
            table.slot_for_packet(&nat::parse_tcp4(&ack).unwrap(), 22),
            Some(slot)
        );
    }

    #[test]
    fn uncommitted_tcp_syns_do_not_exhaust_the_table() {
        let mut table = nat::TcpTable::new();
        for index in 0..nat::TCP_SLOTS {
            let syn = tcp_packet(
                [100, 64, 0, index as u8],
                [192, 0, 2, 1],
                1000 + index as u16,
                443,
            );
            assert_eq!(
                table.slot_for_packet(&nat::parse_tcp4(&syn).unwrap(), index as u64),
                Some(0)
            );
        }
        let valid = tcp_packet([100, 64, 0, 99], [198, 51, 100, 1], 9999, 443);
        assert_eq!(
            table.slot_for_packet(&nat::parse_tcp4(&valid).unwrap(), 20),
            Some(0)
        );
    }

    #[test]
    fn tcp_parser_rejects_invalid_data_offsets() {
        let mut packet = tcp_packet([1; 4], [2; 4], 1000, 443);
        packet[32] = 0x40;
        assert!(nat::parse_tcp4(&packet).is_none());
        packet[32] = 0xf0;
        assert!(nat::parse_tcp4(&packet).is_none());
    }

    #[test]
    fn tcp_fin_closure_has_a_grace_period() {
        let mut table = nat::TcpTable::new();
        let slot = table.slot_for([1; 4], 111, [2; 4], 222, 0).unwrap();
        let mut outbound = tcp_packet([1; 4], [2; 4], 111, 222);
        outbound[33] = 0x11; // FIN|ACK
        write_tcp_checksum(&mut outbound);
        table.observe_outbound(slot, &nat::parse_tcp4(&outbound).unwrap(), 10);
        assert_eq!(table.closure(slot), Some((true, false, None)));

        let mut inbound = tcp_packet([2; 4], [9; 4], 222, nat::TCP_EXT_PORT_BASE);
        inbound[33] = 0x11;
        inbound[28..32].copy_from_slice(&2u32.to_be_bytes());
        write_tcp_checksum(&mut inbound);
        table.observe_inbound(slot, &nat::parse_tcp4(&inbound).unwrap(), 20);
        assert_eq!(table.closure(slot), Some((true, false, None)));

        inbound[28..32].copy_from_slice(&1u32.to_be_bytes());
        write_tcp_checksum(&mut inbound);
        table.observe_inbound(slot, &nat::parse_tcp4(&inbound).unwrap(), 20);
        assert_eq!(table.closure(slot), Some((true, true, Some(20))));

        for index in 1..nat::TCP_SLOTS {
            table
                .slot_for([3, 3, 3, index as u8], index as u16, [4; 4], 443, 20)
                .unwrap();
        }
        let reused = table.slot_for([8; 4], 8, [9; 4], 9, 21).unwrap();
        assert_eq!(reused, slot);
        assert_eq!(table.slot_for_external_port(nat::TCP_EXT_PORT_BASE), None);
        assert_eq!(
            table.slot_for_external_port(nat::TCP_EXT_PORT_BASE + nat::TCP_SLOTS as u16),
            Some(slot)
        );

        let mut reopened_table = nat::TcpTable::new();
        let reopened_slot = reopened_table
            .slot_for([1; 4], 111, [2; 4], 222, 0)
            .unwrap();
        reopened_table.observe_outbound(reopened_slot, &nat::parse_tcp4(&outbound).unwrap(), 10);
        reopened_table.observe_inbound(reopened_slot, &nat::parse_tcp4(&inbound).unwrap(), 20);
        let mut syn = tcp_packet([1; 4], [2; 4], 111, 222);
        syn[33] = 0x02;
        write_tcp_checksum(&mut syn);
        let syn = nat::parse_tcp4(&syn).unwrap();
        assert_eq!(
            reopened_table.slot_for_packet(&syn, 20 + nat::TCP_CLOSED_GRACE_MS - 1),
            Some(reopened_slot)
        );
        assert_eq!(
            reopened_table.external_port_for_packet(reopened_slot, &syn, 20),
            Some(nat::TCP_EXT_PORT_BASE + nat::TCP_SLOTS as u16)
        );
        assert_eq!(
            reopened_table.slot_for_packet(&syn, 20 + nat::TCP_CLOSED_GRACE_MS),
            Some(reopened_slot)
        );
        reopened_table.observe_outbound(reopened_slot, &syn, 20 + nat::TCP_CLOSED_GRACE_MS - 1);
        assert_eq!(
            reopened_table.slot_for_external_port(nat::TCP_EXT_PORT_BASE),
            None
        );
        assert_eq!(
            reopened_table.slot_for_external_port(nat::TCP_EXT_PORT_BASE + nat::TCP_SLOTS as u16),
            Some(reopened_slot)
        );
        assert_eq!(
            reopened_table.closure(reopened_slot),
            Some((false, false, None))
        );
        for index in 1..nat::TCP_SLOTS {
            reopened_table
                .slot_for(
                    [3, 3, 3, index as u8],
                    index as u16,
                    [4; 4],
                    443,
                    20 + nat::TCP_CLOSED_GRACE_MS,
                )
                .unwrap();
        }
        assert!(
            reopened_table
                .slot_for([8; 4], 8, [9; 4], 9, 20 + nat::TCP_CLOSED_GRACE_MS + 1,)
                .is_none()
        );
    }

    #[test]
    fn tcp_rst_requires_sequence_validation_before_releasing_a_mapping() {
        let client = [100, 64, 0, 2];
        let uplink = [198, 51, 100, 2];
        let server = [192, 0, 2, 9];
        let mut table = nat::TcpTable::new();
        let syn = tcp_packet(client, server, 1234, 443);
        let syn = nat::parse_tcp4(&syn).unwrap();
        let slot = table.slot_for_packet(&syn, 0).unwrap();
        table.observe_outbound(slot, &syn, 0);

        let mut reset = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE + slot as u16);
        reset[33] = 0x14; // RST|ACK
        reset[28..32].copy_from_slice(&2u32.to_be_bytes());
        write_tcp_checksum(&mut reset);
        let reset = nat::parse_tcp4(&reset).unwrap();
        assert!(table.reverse_tcp(&reset, uplink).is_some());
        table.observe_inbound(slot, &reset, 1);
        assert!(table.get(slot).is_some());

        let mut reset = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE + slot as u16);
        reset[33] = 0x14;
        reset[28..32].copy_from_slice(&1u32.to_be_bytes());
        write_tcp_checksum(&mut reset);
        let reset = nat::parse_tcp4(&reset).unwrap();
        assert!(table.reverse_tcp(&reset, uplink).is_some());
        table.observe_inbound(slot, &reset, 2);
        assert!(table.get(slot).is_none());

        let mut stray = tcp_packet(client, server, 4321, 443);
        stray[33] = 0x04;
        write_tcp_checksum(&mut stray);
        assert!(
            table
                .slot_for_packet(&nat::parse_tcp4(&stray).unwrap(), 3)
                .is_none()
        );

        let mut table = nat::TcpTable::new();
        let slot = table.slot_for_packet(&syn, 4).unwrap();
        table.observe_outbound(slot, &syn, 4);
        let mut syn_ack = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE + slot as u16);
        syn_ack[24..28].copy_from_slice(&100u32.to_be_bytes());
        syn_ack[28..32].copy_from_slice(&1u32.to_be_bytes());
        syn_ack[33] = 0x12; // SYN|ACK
        write_tcp_checksum(&mut syn_ack);
        table.observe_inbound(slot, &nat::parse_tcp4(&syn_ack).unwrap(), 5);

        let mut reset = syn_ack;
        reset[24..28].copy_from_slice(&102u32.to_be_bytes());
        reset[33] = 0x04;
        write_tcp_checksum(&mut reset);
        table.observe_inbound(slot, &nat::parse_tcp4(&reset).unwrap(), 6);
        assert!(table.get(slot).is_some());

        reset[24..28].copy_from_slice(&101u32.to_be_bytes());
        write_tcp_checksum(&mut reset);
        table.observe_inbound(slot, &nat::parse_tcp4(&reset).unwrap(), 7);
        assert!(table.get(slot).is_none());
    }

    #[test]
    fn forwarding_decrements_ttl_and_drops_expired_packets() {
        let mut packet = udp_packet(b"ttl");
        packet[8] = 2;
        packet[10..12].fill(0);
        let sum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        assert!(nat::ipv4_ttl_is_forwardable(&packet));
        assert!(nat::decrement_ipv4_ttl(&mut packet));
        assert_eq!(packet[8], 1);
        assert_eq!(checksum(&packet[..20]), 0);

        assert!(!nat::ipv4_ttl_is_forwardable(&packet));
        assert!(!nat::decrement_ipv4_ttl(&mut packet));
        assert_eq!(packet[8], 1);
        assert_eq!(checksum(&packet[..20]), 0);
    }

    #[test]
    fn udp_roundtrip_construction_has_valid_checksums() {
        let payload = b"exact challenge";
        let packet = udp_packet(payload);
        let parsed = nat::parse_udp4(&packet[..28 + payload.len()]).unwrap();
        assert_eq!(parsed.src_ip, [100, 64, 0, 2]);
        assert_eq!(parsed.dst_port, 5353);
        assert_eq!(parsed.payload, payload);
        assert_eq!(checksum(&packet[..20]), 0);
        assert!(udp_checksum_valid(&packet[..28 + payload.len()]));
    }

    #[test]
    fn udp_rejects_fragments_bad_lengths_and_short_packets() {
        let mut packet = udp_packet(b"x");
        packet[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(nat::parse_udp4(&packet[..29]).is_none());
        packet[6..8].fill(0);
        packet[24..26].copy_from_slice(&99u16.to_be_bytes());
        assert!(nat::parse_udp4(&packet[..29]).is_none());
        assert!(nat::parse_udp4(&packet[..12]).is_none());
    }

    #[test]
    fn udp_rejects_invalid_nonzero_checksums_but_allows_omission() {
        let payload = b"checksum";
        let mut packet = udp_packet(payload);
        let len = 28 + payload.len();
        packet[28] ^= 0xff;
        assert!(nat::parse_udp4(&packet[..len]).is_none());

        packet[26..28].fill(0);
        assert!(nat::parse_udp4(&packet[..len]).is_some());
    }

    #[test]
    fn reverse_udp_requires_the_complete_translated_tuple() {
        let mut table = nat::Table::new();
        let slot = table
            .slot_for([100, 64, 0, 2], 1234, [192, 0, 2, 9], 53, 0)
            .unwrap();
        let mut packet = [0u8; 128];
        let len = nat::build_udp4(
            [192, 0, 2, 9],
            53,
            [198, 51, 100, 2],
            nat::EXT_PORT_BASE + slot as u16,
            b"reply",
            &mut packet,
        )
        .unwrap();
        let parsed = nat::parse_udp4(&packet[..len]).unwrap();
        assert!(table.reverse_udp(&parsed, [198, 51, 100, 2], 1).is_some());

        // These cases exercise tuple matching, so omit the optional IPv4 UDP
        // checksum before deliberately changing tuple fields below.
        packet[26..28].fill(0);

        let mut rejects = |packet: &[u8], uplink| {
            let parsed = nat::parse_udp4(packet).unwrap();
            assert!(table.reverse_udp(&parsed, uplink, 2).is_none());
        };
        rejects(&packet[..len], [198, 51, 100, 3]);

        let mut wrong = packet;
        wrong[12..16].copy_from_slice(&[192, 0, 2, 10]);
        wrong[10..12].fill(0);
        let ip_sum = checksum(&wrong[..20]);
        wrong[10..12].copy_from_slice(&ip_sum.to_be_bytes());
        rejects(&wrong[..len], [198, 51, 100, 2]);

        let mut wrong = packet;
        wrong[20..22].copy_from_slice(&54u16.to_be_bytes());
        rejects(&wrong[..len], [198, 51, 100, 2]);

        let mut wrong = packet;
        wrong[22..24].copy_from_slice(&(nat::EXT_PORT_BASE + 1).to_be_bytes());
        rejects(&wrong[..len], [198, 51, 100, 2]);

        let mut wrong = packet;
        wrong[22..24].copy_from_slice(&(nat::EXT_PORT_BASE - 1).to_be_bytes());
        rejects(&wrong[..len], [198, 51, 100, 2]);

        let mut wrong = packet;
        wrong[22..24].copy_from_slice(&(nat::EXT_PORT_BASE + nat::SLOTS as u16).to_be_bytes());
        rejects(&wrong[..len], [198, 51, 100, 2]);
    }

    #[test]
    fn reverse_tcp_requires_the_complete_translated_tuple() {
        let uplink = [198, 51, 100, 2];
        let server = [192, 0, 2, 9];
        let mut table = nat::TcpTable::new();
        let slot = table
            .slot_for([100, 64, 0, 2], 1234, server, 443, 0)
            .unwrap();
        let packet = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE + slot as u16);
        let parsed = nat::parse_tcp4(&packet).unwrap();
        assert!(table.reverse_tcp(&parsed, uplink).is_some());

        let rejects = |packet: &[u8], expected_uplink| {
            let parsed = nat::parse_tcp4(packet).unwrap();
            assert!(table.reverse_tcp(&parsed, expected_uplink).is_none());
        };
        rejects(&packet, [198, 51, 100, 3]);

        let wrong = tcp_packet(
            [192, 0, 2, 10],
            uplink,
            443,
            nat::TCP_EXT_PORT_BASE + slot as u16,
        );
        rejects(&wrong, uplink);

        let wrong = tcp_packet(server, uplink, 444, nat::TCP_EXT_PORT_BASE + slot as u16);
        rejects(&wrong, uplink);

        let wrong = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE + 1);
        rejects(&wrong, uplink);

        let wrong = tcp_packet(server, uplink, 443, nat::TCP_EXT_PORT_BASE - 1);
        rejects(&wrong, uplink);

        let wrong = tcp_packet(
            server,
            uplink,
            443,
            nat::TCP_EXT_PORT_BASE + nat::TCP_SLOTS as u16,
        );
        rejects(&wrong, uplink);
    }

    #[test]
    fn tcp_parser_rejects_invalid_checksums() {
        let mut packet = tcp_packet([1; 4], [2; 4], 1000, 443);
        packet[38] ^= 0xff;
        assert!(nat::parse_tcp4(&packet).is_none());
    }

    #[test]
    fn parsers_reject_invalid_ipv4_header_checksums() {
        let mut udp = udp_packet(b"udp");
        udp[8] ^= 1;
        assert!(nat::parse_udp4(&udp[..31]).is_none());
        assert!(!nat::ipv4_ttl_is_forwardable(&udp));
        assert!(!nat::decrement_ipv4_ttl(&mut udp));

        let mut tcp = tcp_packet([1; 4], [2; 4], 1000, 443);
        tcp[8] ^= 1;
        assert!(nat::parse_tcp4(&tcp).is_none());
        assert!(!nat::rewrite_tcp_outbound(&mut tcp, [3; 4], 3000));
    }

    #[test]
    fn tcp_translation_and_mss_clamping_preserve_checksums() {
        let mut packet = tcp_packet([100, 64, 0, 2], [192, 0, 2, 10], 12345, 443);
        let parsed = nat::parse_tcp4(&packet).unwrap();
        assert_eq!(parsed.sequence, 0);
        assert_eq!(parsed.acknowledgement, 0);
        assert!(parsed.is_syn);
        assert!(!parsed.is_fin);
        assert!(parsed.payload.is_empty());
        assert!(tcp_checksum_valid(&packet));
        nat::clamp_mss(&mut packet);
        assert_eq!(nat::MAX_MSS, 1160);
        assert_eq!(
            60 + 60 + usize::from(nat::MAX_MSS),
            wirefeather::budget::INNER_MTU
        );
        assert_eq!(u16::from_be_bytes([packet[42], packet[43]]), nat::MAX_MSS);
        assert!(tcp_checksum_valid(&packet));
        assert!(nat::rewrite_tcp_outbound(
            &mut packet,
            [198, 51, 100, 2],
            41000
        ));
        assert_eq!(&packet[12..16], &[198, 51, 100, 2]);
        assert_eq!(&packet[20..22], &41000u16.to_be_bytes());
        assert_eq!(checksum(&packet[..20]), 0);
        assert!(tcp_checksum_valid(&packet));
        assert!(nat::rewrite_tcp_inbound(
            &mut packet,
            [100, 64, 0, 2],
            12345
        ));
        assert!(tcp_checksum_valid(&packet));
    }

    #[test]
    fn tcp_receive_window_clamping_composes_with_mss_and_window_scale() {
        let mut packet = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        nat::clamp_mss(&mut packet);
        nat::clamp_tcp_receive_window(&mut packet, 4 * nat::MAX_MSS);

        let parsed = nat::parse_tcp4(&packet).unwrap();
        assert_eq!(parsed.mss, Some(nat::MAX_MSS));
        assert_eq!(parsed.window, 4 * nat::MAX_MSS);
        assert_eq!(packet[47], 0);
        assert!(tcp_checksum_valid(&packet));
    }

    #[test]
    fn tcp_receive_window_preserves_zero_and_only_scales_handshakes() {
        let mut zero = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        zero[33] = 0x12; // SYN|ACK
        zero[34..36].fill(0);
        write_tcp_checksum(&mut zero);
        nat::clamp_tcp_receive_window(&mut zero, nat::MAX_MSS);
        assert_eq!(nat::parse_tcp4(&zero).unwrap().window, 0);
        assert_eq!(zero[47], 0);
        assert!(tcp_checksum_valid(&zero));

        let mut established = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        established[33] = 0x10; // ACK
        write_tcp_checksum(&mut established);
        nat::clamp_tcp_receive_window(&mut established, nat::MAX_MSS);
        assert_eq!(nat::parse_tcp4(&established).unwrap().window, nat::MAX_MSS);
        assert_eq!(established[47], 7);
        assert!(tcp_checksum_valid(&established));
    }

    #[test]
    fn tcp_receive_window_is_a_noop_below_cap_and_on_malformed_options() {
        let mut below_cap = tcp_packet([1; 4], [2; 4], 1000, 443);
        let before = below_cap;
        nat::clamp_tcp_receive_window(&mut below_cap, 4 * nat::MAX_MSS);
        assert_eq!(below_cap, before);

        // The malformed Window Scale follows a valid MSS, proving that the
        // complete option list is validated before either helper mutates it.
        let mut malformed = tcp_packet_with_options([2, 4, 0x05, 0xb4, 3, 1, 7, 0]);
        let before = malformed;
        assert!(nat::parse_tcp4(&malformed).is_none());
        nat::clamp_mss(&mut malformed);
        nat::clamp_tcp_receive_window(&mut malformed, nat::MAX_MSS);
        assert_eq!(malformed, before);
    }

    #[test]
    fn scaled_tcp_receive_windows_are_normalized_before_capping() {
        let mut capped = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        capped[33] = 0x10; // ACK
        capped[34..36].copy_from_slice(&16u16.to_be_bytes());
        write_tcp_checksum(&mut capped);
        nat::clamp_tcp_receive_window_scaled(&mut capped, nat::MAX_MSS, 7);
        assert_eq!(nat::parse_tcp4(&capped).unwrap().window, nat::MAX_MSS);
        assert!(tcp_checksum_valid(&capped));

        let mut below_cap = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        below_cap[33] = 0x10; // ACK
        below_cap[34..36].copy_from_slice(&8u16.to_be_bytes());
        write_tcp_checksum(&mut below_cap);
        nat::clamp_tcp_receive_window_scaled(&mut below_cap, nat::MAX_MSS, 7);
        assert_eq!(nat::parse_tcp4(&below_cap).unwrap().window, 1024);
        assert!(tcp_checksum_valid(&below_cap));
    }

    #[test]
    fn tcp_table_remembers_each_endpoints_original_window_scale() {
        let client_syn = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        let client = nat::parse_tcp4(&client_syn).unwrap();
        assert_eq!(client.window_scale, Some(7));

        let mut table = nat::TcpTable::new();
        let slot = table.slot_for_packet(&client, 1).unwrap();
        table.observe_outbound(slot, &client, 1);
        // Scaling is not in effect until the server answers with its own
        // option, so nothing may be expanded by the offered exponent yet.
        assert_eq!(table.window_scale(slot, true), 0);

        let mut server_syn_ack = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 12]);
        server_syn_ack[33] = 0x12; // SYN|ACK
        write_tcp_checksum(&mut server_syn_ack);
        let server = nat::parse_tcp4(&server_syn_ack).unwrap();
        table.observe_inbound(slot, &server, 2);
        assert_eq!(table.window_scale(slot, true), 7);
        assert_eq!(table.window_scale(slot, false), 12);
    }

    /// A client that never sees its SYN-ACK acknowledged retransmits the SYN.
    /// That is the same handshake, so the server's negotiated exponent has to
    /// survive it — forgetting it reads every later server window as unscaled
    /// and throttles the download to a fraction of the real window.
    #[test]
    fn a_retransmitted_syn_keeps_the_servers_window_scale() {
        let client_syn = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        let client = nat::parse_tcp4(&client_syn).unwrap();

        let mut table = nat::TcpTable::new();
        let slot = table.slot_for_packet(&client, 1).unwrap();
        table.observe_outbound(slot, &client, 1);

        let mut server_syn_ack = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 12]);
        server_syn_ack[33] = 0x12; // SYN|ACK
        write_tcp_checksum(&mut server_syn_ack);
        let server = nat::parse_tcp4(&server_syn_ack).unwrap();
        table.observe_inbound(slot, &server, 2);

        // The duplicate carries the same sequence, which is what marks it as a
        // retransmission rather than a new connection on the same tuple.
        table.observe_outbound(slot, &client, 3);
        assert_eq!(table.window_scale(slot, true), 7);
        assert_eq!(table.window_scale(slot, false), 12);
    }

    /// Wrapping a slot's port sequence back to its first port must wait out the
    /// TIME_WAIT grace, or delayed segments from the previous use of that port
    /// are attributed to the new flow.
    #[test]
    fn the_port_sequence_does_not_wrap_inside_the_time_wait_grace() {
        let mut table = nat::TcpTable::new();
        // Every other slot stays live, so each new connection can only land on
        // the one slot being cycled.
        let cycled = table.slot_for([1; 4], 111, [2; 4], 222, 0).unwrap();
        for index in 1..nat::TCP_SLOTS {
            table
                .slot_for([3, 3, 3, index as u8], index as u16, [4; 4], 443, 0)
                .unwrap();
        }

        let close = |table: &mut nat::TcpTable, client_port: u16, now_ms: u64| {
            let mut outbound = tcp_packet([1; 4], [2; 4], client_port, 222);
            outbound[33] = 0x11; // FIN|ACK
            write_tcp_checksum(&mut outbound);
            table.observe_outbound(cycled, &nat::parse_tcp4(&outbound).unwrap(), now_ms);
            let mut inbound = tcp_packet([2; 4], [9; 4], 222, nat::TCP_EXT_PORT_BASE);
            inbound[33] = 0x11;
            inbound[28..32].copy_from_slice(&1u32.to_be_bytes());
            write_tcp_checksum(&mut inbound);
            table.observe_inbound(cycled, &nat::parse_tcp4(&inbound).unwrap(), now_ms);
            assert_eq!(table.closure(cycled), Some((true, true, Some(now_ms))));
        };

        // The first port was opened long ago but only just closed. Burn through
        // the remaining generations without advancing the clock: wrapping must
        // still be refused because the old tuple, not its original allocation,
        // remains inside the remote's TIME_WAIT grace.
        let recent_close = nat::TCP_CLOSED_GRACE_MS + 1;
        let mut client_port = 111;
        let mut lifetimes = 0;
        loop {
            close(&mut table, client_port, recent_close);
            client_port += 1;
            lifetimes += 1;
            assert!(
                lifetimes < 10_000,
                "the sequence should run out before this"
            );
            if table
                .slot_for([1; 4], client_port, [2; 4], 222, recent_close)
                .is_none()
            {
                break;
            }
        }
        assert!(lifetimes > 1, "the sequence must yield more than one port");

        // Once the first port has aged out, the slot is allocatable again.
        let reusable_at = recent_close + nat::TCP_CLOSED_GRACE_MS;
        for slot in 1..nat::TCP_SLOTS {
            table.touch(slot, reusable_at);
        }
        assert_eq!(
            table.slot_for([1; 4], client_port, [2; 4], 222, reusable_at,),
            Some(cycled)
        );
    }

    /// Explicit release also starts the first port's TIME_WAIT grace. Without
    /// that timestamp, wrapping the generation sequence strands the slot.
    #[test]
    fn explicitly_released_first_port_can_wrap_after_grace() {
        let mut table = nat::TcpTable::new();
        let cycled = table.slot_for([1; 4], 111, [2; 4], 222, 0).unwrap();
        for slot in 1..nat::TCP_SLOTS {
            table
                .slot_for([3, 3, 3, slot as u8], slot as u16, [4; 4], 443, 0)
                .unwrap();
        }
        let released_at = nat::TCP_CLOSED_GRACE_MS + 1;
        table.release(cycled, released_at);
        let mut client_port = 112;
        loop {
            if table
                .slot_for([1; 4], client_port, [2; 4], 222, released_at)
                .is_none()
            {
                break;
            }
            table.release(cycled, released_at);
            client_port += 1;
        }
        let reusable_at = released_at + nat::TCP_CLOSED_GRACE_MS;
        for slot in 1..nat::TCP_SLOTS {
            table.touch(slot, reusable_at);
        }
        assert_eq!(
            table.slot_for([1; 4], client_port, [2; 4], 222, reusable_at),
            Some(cycled)
        );
    }

    /// RFC 7323: an endpoint that offered Window Scale must fall back to
    /// unscaled windows when the other side's SYN omits the option.
    #[test]
    fn tcp_window_scaling_stays_off_when_only_one_side_offers_it() {
        let client_syn = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 3, 3, 7]);
        let client = nat::parse_tcp4(&client_syn).unwrap();

        let mut table = nat::TcpTable::new();
        let slot = table.slot_for_packet(&client, 1).unwrap();
        table.observe_outbound(slot, &client, 1);

        // SYN-ACK with MSS only: the trailing NOPs keep the header length the
        // same while dropping the Window Scale option.
        let mut server_syn_ack = tcp_packet_with_options([2, 4, 0x05, 0xb4, 1, 1, 1, 1]);
        server_syn_ack[33] = 0x12; // SYN|ACK
        write_tcp_checksum(&mut server_syn_ack);
        let server = nat::parse_tcp4(&server_syn_ack).unwrap();
        assert_eq!(server.window_scale, None);
        table.observe_inbound(slot, &server, 2);

        assert_eq!(table.window_scale(slot, true), 0);
        assert_eq!(table.window_scale(slot, false), 0);
    }

    #[test]
    fn malformed_tcp_is_rejected_without_mutation() {
        let mut packet = [0u8; 20];
        let before = packet;
        assert!(nat::parse_tcp4(&packet).is_none());
        assert!(!nat::rewrite_tcp_outbound(&mut packet, [1; 4], 1));
        nat::clamp_mss(&mut packet);
        nat::clamp_tcp_receive_window(&mut packet, nat::MAX_MSS);
        assert_eq!(packet, before);

        let mut invalid_ihl = tcp_packet([1; 4], [2; 4], 1, 2);
        invalid_ihl[0] = 0x44;
        assert!(nat::parse_tcp4(&invalid_ihl).is_none());
        assert!(!nat::rewrite_tcp_outbound(&mut invalid_ihl, [3; 4], 3));

        let mut fragment = tcp_packet([1; 4], [2; 4], 1, 2);
        fragment[6..8].copy_from_slice(&0x2000u16.to_be_bytes());
        assert!(nat::parse_tcp4(&fragment).is_none());
    }
}
