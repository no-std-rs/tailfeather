//! Bounded TCP/HTTP state for the exit-node peer API.
//!
//! The firmware supplies authenticated WireGuard packets; the ACL decision
//! itself is [`client_may_resolve`], here, so every caller asks the same
//! question. This module terminates at most four short HTTP/1.1 connections,
//! accepts RFC 8484 GET and POST requests, and retains exactly one 1280-byte
//! request-or-DNS-response buffer per connection.

use crate::nat::{self, TcpInfo};

pub const PORT: u16 = 5254;
pub const CONNECTIONS: usize = 4;
pub const CONNECTION_STORAGE: usize = 1280;
pub const DNS_FAILOVER_MS: u64 = 2_000;
pub const DNS_TIMEOUT_MS: u64 = 5_000;
const CONNECTION_IDLE_MS: u64 = 10_000;
const CLOSE_GRACE_MS: u64 = 2_000;
const RETRANSMIT_MS: u64 = 1_000;
const IPV4_DEFAULT_MSS: u16 = 536;
const FLAG_FIN: u8 = 0x01;
const FLAG_SYN: u8 = 0x02;
const FLAG_RST: u8 = 0x04;
const FLAG_ACK: u8 = 0x10;

/// Whether the tailnet policy lets this client resolve names through the exit
/// node.
///
/// `allows_dns_from` asks the packet filter whether `client_ip` can send UDP
/// port 53 to any IPv4 destination. Callers pass their own filter — the
/// firmware's live netmap policy, the harness's configured one — and the
/// decision built on top of it stays here, in one place.
///
/// The check deliberately does *not* involve the upstream resolver's address.
/// The resolver is reached from the gateway's own uplink, as itself — the
/// client never sends a packet there and the filter has nothing to say about
/// that hop. Filtering on it was actively wrong: the resolvers come from DHCP
/// and are almost always RFC1918, while the common `autogroup:internet` exit
/// grant excludes private ranges, so every resolver was rejected and a client
/// that routes all its DNS through this proxy got nothing but 500s.
///
/// What is authorized here is the client's use of the exit node's DNS proxy,
/// represented by any UDP/53 grant. The gateway's selected uplink resolver is
/// not a destination on the client's policy path.
pub fn client_may_resolve(
    client_ip: [u8; 4],
    mut allows_dns_from: impl FnMut([u8; 4]) -> bool,
) -> bool {
    allows_dns_from(client_ip)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    SynReceived,
    Request,
    AwaitDns,
    Responding,
    Closing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseKind {
    Dns,
    Head,
    BadRequest,
    DnsFailure,
}

#[derive(Clone, Copy)]
struct Connection {
    state: State,
    client_ip: [u8; 4],
    client_port: u16,
    client_next: u32,
    server_isn: u32,
    server_next: u32,
    peer_mss: u16,
    peer_window: u16,
    client_fin: bool,
    buffer: [u8; CONNECTION_STORAGE],
    len: usize,
    last_used_ms: u64,
    dns_id: u16,
    dns_started_ms: u64,
    dns_sent_ms: u64,
    dns_resolver: usize,
    response: ResponseKind,
    response_sequence: u32,
    response_acked: usize,
    outstanding_payload: usize,
    outstanding_fin: bool,
    last_tx_ms: u64,
}

impl Connection {
    const fn empty() -> Self {
        Self {
            state: State::Free,
            client_ip: [0; 4],
            client_port: 0,
            client_next: 0,
            server_isn: 0,
            server_next: 0,
            peer_mss: nat::MAX_MSS,
            peer_window: 0,
            client_fin: false,
            buffer: [0; CONNECTION_STORAGE],
            len: 0,
            last_used_ms: 0,
            dns_id: 0,
            dns_started_ms: 0,
            dns_sent_ms: 0,
            dns_resolver: 0,
            response: ResponseKind::BadRequest,
            response_sequence: 0,
            response_acked: 0,
            outstanding_payload: 0,
            outstanding_fin: false,
            last_tx_ms: 0,
        }
    }

    fn reset(&mut self) {
        *self = Self::empty();
    }

    fn begin_response(&mut self, response: ResponseKind) {
        self.state = State::Responding;
        self.response = response;
        self.response_sequence = self.server_next;
        self.response_acked = 0;
        self.outstanding_payload = 0;
        self.outstanding_fin = false;
    }

    fn response_body_len(&self) -> usize {
        if self.response == ResponseKind::Dns {
            self.len
        } else {
            0
        }
    }
}

pub struct Server {
    connections: [Connection; CONNECTIONS],
    next_isn: u32,
    next_dns_generation: u16,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Receive {
    pub slot: Option<usize>,
    pub send_ack: bool,
    pub send_response: bool,
    pub dns_query: bool,
    pub capacity_drop: bool,
    pub close_after_ack: bool,
    /// Answer with a reset built by [`build_reset`], because the connection was
    /// torn down under the client rather than closed with it.
    pub send_reset: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsTimer {
    Send { slot: usize, resolver: usize },
    Failed { slot: usize },
}

impl Server {
    pub const fn new(isn_seed: u32) -> Self {
        Self {
            connections: [Connection::empty(); CONNECTIONS],
            next_isn: isn_seed,
            next_dns_generation: 0,
        }
    }

    /// Consume one segment addressed to the peer API. `authorized` is the
    /// caller's TCP/53 `autogroup:internet`-equivalent ACL result.
    pub fn receive(&mut self, packet: &TcpInfo<'_>, authorized: bool, now_ms: u64) -> Receive {
        let mut result = Receive::default();
        let found = self.connections.iter().position(|connection| {
            connection.state != State::Free
                && connection.client_ip == packet.src_ip
                && connection.client_port == packet.src_port
        });

        if packet.is_rst {
            if let Some(slot) = found {
                let connection = &self.connections[slot];
                let acceptable = match connection.state {
                    State::SynReceived => {
                        (packet.is_ack && packet.acknowledgement == connection.server_next)
                            || (!packet.is_ack && packet.sequence == connection.client_next)
                    }
                    State::Free => false,
                    _ => packet.sequence == connection.client_next,
                };
                if acceptable {
                    self.connections[slot].reset();
                    result.slot = Some(slot);
                }
            }
            return result;
        }

        // Authorization is live control-plane state, not a property of the
        // handshake. Tear down any partial request as soon as access is
        // revoked so it cannot resume if a later fragment arrives.
        if !authorized {
            if let Some(slot) = found {
                self.connections[slot].reset();
                // Say so. Dropping the state silently left the client holding
                // an open socket against nothing, waiting out its own timeout
                // for a request that was never going to be answered.
                result.send_reset = true;
            }
            return result;
        }

        let slot = if packet.is_syn && !packet.is_ack && !packet.is_fin && !packet.is_rst {
            if let Some(slot) = found {
                let connection = &self.connections[slot];
                if !reusable(connection, now_ms) {
                    result.slot = Some(slot);
                    result.send_ack = true; // retransmit the current acknowledgement
                    return result;
                }
            }
            let Some(slot) = found.or_else(|| {
                self.connections
                    .iter()
                    .position(|connection| reusable(connection, now_ms))
            }) else {
                result.capacity_drop = true;
                return result;
            };
            self.next_isn = self.next_isn.wrapping_add(64_013);
            self.connections[slot] = Connection {
                state: State::SynReceived,
                client_ip: packet.src_ip,
                client_port: packet.src_port,
                client_next: packet.sequence.wrapping_add(1),
                server_isn: self.next_isn,
                server_next: self.next_isn.wrapping_add(1),
                peer_mss: packet
                    .mss
                    .unwrap_or(IPV4_DEFAULT_MSS)
                    .clamp(1, nat::MAX_MSS),
                peer_window: packet.window,
                last_used_ms: now_ms,
                ..Connection::empty()
            };
            result.slot = Some(slot);
            result.send_ack = true;
            return result;
        } else if let Some(slot) = found {
            slot
        } else {
            return result;
        };

        result.slot = Some(slot);
        let connection = &mut self.connections[slot];
        connection.last_used_ms = now_ms;
        // A delayed duplicate ACK can carry an older (including zero) window.
        // Do not let it replace the window that belongs to the already-acked
        // response prefix.
        let response_ack = connection
            .response_sequence
            .wrapping_add(connection.response_acked as u32);
        if connection.state != State::Responding
            || !packet.is_ack
            || !sequence_before(packet.acknowledgement, response_ack)
        {
            connection.peer_window = packet.window;
        }

        if connection.state == State::SynReceived {
            if !packet.is_ack || packet.acknowledgement != connection.server_next {
                result.send_ack = true;
                return result;
            }
            connection.state = State::Request;
        }

        if connection.state == State::Responding && packet.is_ack {
            if response_acknowledged(connection, packet.acknowledgement) {
                connection.state = State::Closing;
                connection.server_next = packet.acknowledgement;
                // A FIN carried with the already-complete request was
                // acknowledged before the response. Its ACK of our FIN now
                // completes both directions, so the bounded slot can return
                // to the pool immediately after the final acknowledgement.
                result.close_after_ack = connection.client_fin;
                if packet.is_fin {
                    if packet.sequence == connection.client_next {
                        connection.client_next = connection.client_next.wrapping_add(1);
                        connection.client_fin = true;
                    }
                    result.send_ack = true;
                    result.close_after_ack = true;
                }
                return result;
            }
            if connection.outstanding_payload == 0 && !connection.outstanding_fin {
                result.send_response = true;
            } else if packet.acknowledgement
                == connection
                    .response_sequence
                    .wrapping_add(connection.response_acked as u32)
            {
                // A duplicate ACK is a useful retransmission signal.
                result.send_response = true;
            }
        }

        if connection.state == State::Closing {
            if packet.is_fin {
                if packet.sequence == connection.client_next {
                    connection.client_next = connection.client_next.wrapping_add(1);
                }
                connection.client_fin = true;
                result.send_ack = true;
                result.close_after_ack = true;
            }
            return result;
        }

        if connection.state != State::Request {
            if !packet.payload.is_empty() {
                // The request's final ACK may have been lost after the DNS
                // query was dispatched. Do not append or dispatch it again,
                // but repeat the cumulative ACK so the client can advance.
                result.send_ack = true;
            }
            if packet.is_fin {
                if packet.sequence == connection.client_next {
                    connection.client_next = connection.client_next.wrapping_add(1);
                    connection.client_fin = true;
                }
                result.send_ack = true;
            }
            return result;
        }

        let mut appended = false;
        if !packet.payload.is_empty() {
            let overlap = connection.client_next.wrapping_sub(packet.sequence) as usize;
            if packet.sequence == connection.client_next {
                appended = append(connection, packet.payload);
            } else if sequence_before(packet.sequence, connection.client_next)
                && overlap < packet.payload.len()
            {
                appended = append(connection, &packet.payload[overlap..]);
            }
            result.send_ack = true;
        }
        let fin_consumed = packet.is_fin
            && packet.sequence.wrapping_add(packet.payload.len() as u32) == connection.client_next;
        if packet.is_fin {
            result.send_ack = true;
        }
        if fin_consumed {
            connection.client_next = connection.client_next.wrapping_add(1);
            connection.client_fin = true;
        }

        if appended || fin_consumed || connection.len == CONNECTION_STORAGE {
            match parse_request(&connection.buffer[..connection.len]) {
                Ok(Some(Parsed::Head)) => {
                    connection.len = 0;
                    connection.begin_response(ResponseKind::Head);
                    result.send_response = true;
                }
                Ok(Some(Parsed::Dns {
                    start,
                    end,
                    encoded,
                })) => {
                    let query_len = if encoded {
                        match decode_base64url_in_place(&mut connection.buffer, start, end) {
                            Some(len) => len,
                            None => {
                                connection.len = 0;
                                connection.begin_response(ResponseKind::BadRequest);
                                result.send_response = true;
                                return result;
                            }
                        }
                    } else {
                        let len = end - start;
                        connection.buffer.copy_within(start..end, 0);
                        len
                    };
                    if !valid_dns_query(&connection.buffer[..query_len]) {
                        connection.len = 0;
                        connection.begin_response(ResponseKind::BadRequest);
                        result.send_response = true;
                    } else {
                        connection.len = query_len;
                        clamp_edns_payload_size(&mut connection.buffer[..query_len]);
                        connection.dns_id =
                            u16::from_be_bytes([connection.buffer[0], connection.buffer[1]]);
                        // Reserve the top two bits for the slot, while a
                        // monotonic 14-bit generation distinguishes later
                        // occupants of that slot from delayed replies.
                        self.next_dns_generation = self.next_dns_generation.wrapping_add(1);
                        let upstream_id =
                            (self.next_dns_generation & 0x3fff) | ((slot as u16) << 14);
                        connection.buffer[..2].copy_from_slice(&upstream_id.to_be_bytes());
                        connection.dns_started_ms = now_ms;
                        connection.dns_sent_ms = now_ms;
                        connection.dns_resolver = 0;
                        connection.state = State::AwaitDns;
                        result.dns_query = true;
                    }
                }
                Ok(None) if connection.len < CONNECTION_STORAGE && !fin_consumed => {}
                Ok(None) | Err(()) => {
                    connection.len = 0;
                    connection.begin_response(ResponseKind::BadRequest);
                    result.send_response = true;
                }
            }
        }
        result
    }

    pub fn query(&self, slot: usize) -> Option<&[u8]> {
        let connection = self.connections.get(slot)?;
        (connection.state == State::AwaitDns).then_some(&connection.buffer[..connection.len])
    }

    pub fn client_ip(&self, slot: usize) -> Option<[u8; 4]> {
        let connection = self.connections.get(slot)?;
        (connection.state != State::Free).then_some(connection.client_ip)
    }

    pub fn release(&mut self, slot: usize) {
        if let Some(connection) = self.connections.get_mut(slot) {
            connection.reset();
        }
    }

    pub fn note_dns_sent(&mut self, slot: usize, resolver: usize, now_ms: u64) {
        if let Some(connection) = self.connections.get_mut(slot)
            && connection.state == State::AwaitDns
        {
            connection.dns_resolver = resolver;
            connection.dns_sent_ms = now_ms;
        }
    }

    /// Keep an unqueued query eligible for a retry on the same resolver.
    pub fn note_dns_unsent(&mut self, slot: usize) {
        if let Some(connection) = self.connections.get_mut(slot)
            && connection.state == State::AwaitDns
        {
            connection.dns_sent_ms = 0;
        }
    }

    /// Accept a reply from any resolver already attempted for this connection.
    /// The source resolver and DNS transaction ID both have to match.
    pub fn complete_dns(&mut self, resolver: usize, message: &[u8], now_ms: u64) -> Option<usize> {
        if message.len() < 12 || message.len() > CONNECTION_STORAGE || message[2] & 0x80 == 0 {
            return None;
        }
        let slot = self.connections.iter().position(|connection| {
            connection.state == State::AwaitDns
                && resolver <= connection.dns_resolver
                && connection.buffer[..2] == message[..2]
                && dns_questions_match(&connection.buffer[..connection.len], message)
        })?;
        let connection = &mut self.connections[slot];
        connection.buffer[..message.len()].copy_from_slice(message);
        connection.buffer[..2].copy_from_slice(&connection.dns_id.to_be_bytes());
        connection.len = message.len();
        connection.last_used_ms = now_ms;
        connection.begin_response(ResponseKind::Dns);
        Some(slot)
    }

    pub fn fail_dns(&mut self, slot: usize) -> bool {
        let Some(connection) = self.connections.get_mut(slot) else {
            return false;
        };
        if connection.state != State::AwaitDns {
            return false;
        }
        connection.len = 0;
        connection.begin_response(ResponseKind::DnsFailure);
        true
    }

    pub fn poll_dns(&mut self, now_ms: u64, resolver_count: usize) -> Option<DnsTimer> {
        for (slot, connection) in self.connections.iter_mut().enumerate() {
            if connection.state != State::AwaitDns {
                continue;
            }
            if now_ms.saturating_sub(connection.dns_started_ms) >= DNS_TIMEOUT_MS {
                connection.len = 0;
                connection.begin_response(ResponseKind::DnsFailure);
                return Some(DnsTimer::Failed { slot });
            }
            if connection.dns_sent_ms == 0 {
                return Some(DnsTimer::Send {
                    slot,
                    resolver: connection.dns_resolver,
                });
            }
            if now_ms.saturating_sub(connection.dns_sent_ms) >= DNS_FAILOVER_MS
                && connection.dns_resolver + 1 < resolver_count
            {
                connection.dns_resolver += 1;
                connection.dns_sent_ms = now_ms;
                return Some(DnsTimer::Send {
                    slot,
                    resolver: connection.dns_resolver,
                });
            }
        }
        None
    }

    pub fn retransmit_due(&mut self, now_ms: u64) -> Option<usize> {
        for (slot, connection) in self.connections.iter_mut().enumerate() {
            if connection.state != State::Responding {
                continue;
            }
            if now_ms.saturating_sub(connection.last_used_ms) >= CONNECTION_IDLE_MS {
                connection.reset();
                continue;
            }
            if (connection.outstanding_payload != 0
                || connection.outstanding_fin
                || (connection.peer_window == 0
                    && connection.response_acked < response_len(connection)))
                && now_ms.saturating_sub(connection.last_tx_ms) >= RETRANSMIT_MS
            {
                return Some(slot);
            }
        }
        None
    }

    pub fn build_ack(&self, slot: usize, local_ip: [u8; 4], out: &mut [u8]) -> Option<usize> {
        let connection = self.connections.get(slot)?;
        if connection.state == State::Free {
            return None;
        }
        let syn = connection.state == State::SynReceived;
        nat::build_tcp4(
            local_ip,
            PORT,
            connection.client_ip,
            connection.client_port,
            if syn {
                connection.server_isn
            } else {
                connection.server_next
            },
            connection.client_next,
            FLAG_ACK | if syn { FLAG_SYN } else { 0 },
            &[],
            out,
        )
    }

    /// Build or retransmit the next stop-and-wait response segment.
    pub fn build_response(
        &mut self,
        slot: usize,
        local_ip: [u8; 4],
        payload_out: &mut [u8],
        packet_out: &mut [u8],
        now_ms: u64,
    ) -> Option<usize> {
        let connection = self.connections.get_mut(slot)?;
        if connection.state != State::Responding {
            return None;
        }
        let body_len = connection.response_body_len();
        let mut header = [0u8; 128];
        let header_len = response_header(connection.response, body_len, &mut header)?;
        let total = header_len + body_len;
        let offset = connection.response_acked;
        let retransmit = connection.outstanding_payload != 0 || connection.outstanding_fin;
        // The advertised window starts at the acknowledgement number, which
        // is also the sequence of an outstanding stop-and-wait segment.
        // Therefore retransmissions are capped by the window itself, rather
        // than subtracting bytes already in flight a second time.
        let available_window = usize::from(connection.peer_window);
        // A one-byte persist probe is valid both before the first response
        // segment and while one is outstanding.  In the latter case it keeps
        // the original in-flight extent intact for cumulative ACK validation.
        let zero_window_probe = available_window == 0 && offset < total;
        if available_window == 0 && !zero_window_probe {
            return None;
        }
        let payload_len = if zero_window_probe {
            1
        } else if retransmit {
            connection.outstanding_payload.min(available_window)
        } else {
            total
                .saturating_sub(offset)
                .min(payload_out.len())
                .min(usize::from(connection.peer_mss))
                .min(available_window)
        };
        if payload_len > payload_out.len() {
            return None;
        }
        if offset + payload_len > total {
            return None;
        }
        copy_virtual_response(
            connection,
            &header[..header_len],
            offset,
            &mut payload_out[..payload_len],
        );
        let final_segment = offset + payload_len == total;
        let fin = if zero_window_probe {
            false
        } else if retransmit {
            connection.outstanding_fin && payload_len == connection.outstanding_payload
        } else {
            final_segment && available_window > payload_len
        };
        // A retransmission may be shorter than the original packet if the
        // peer's window shrank. Keep the original in-flight extent for ACK
        // validation: the original segment can still have arrived in full.
        if !retransmit && !zero_window_probe {
            connection.outstanding_payload = payload_len;
            connection.outstanding_fin = fin;
        }
        connection.last_tx_ms = now_ms;
        nat::build_tcp4(
            local_ip,
            PORT,
            connection.client_ip,
            connection.client_port,
            connection.response_sequence.wrapping_add(offset as u32),
            connection.client_next,
            FLAG_ACK | if fin { FLAG_FIN } else { 0 },
            &payload_out[..payload_len],
            packet_out,
        )
    }
}

/// Build a reset for a segment whose connection no longer exists.
///
/// Derived from the segment rather than from connection state, because by the
/// time this is called the slot has already been released. The sequence
/// numbering follows RFC 793: mirror the peer's acknowledgement if it sent one,
/// otherwise acknowledge what it sent and reset from zero.
pub fn build_reset(packet: &TcpInfo<'_>, local_ip: [u8; 4], out: &mut [u8]) -> Option<usize> {
    let consumed =
        packet.payload.len() as u32 + u32::from(packet.is_syn) + u32::from(packet.is_fin);
    let (sequence, acknowledgement, flags) = if packet.is_ack {
        (packet.acknowledgement, 0, FLAG_RST)
    } else {
        (
            0,
            packet.sequence.wrapping_add(consumed),
            FLAG_RST | FLAG_ACK,
        )
    };
    nat::build_tcp4(
        local_ip,
        PORT,
        packet.src_ip,
        packet.src_port,
        sequence,
        acknowledgement,
        flags,
        &[],
        out,
    )
}

fn reusable(connection: &Connection, now_ms: u64) -> bool {
    connection.state == State::Free
        || (connection.state == State::Closing
            && now_ms.saturating_sub(connection.last_used_ms) >= CLOSE_GRACE_MS)
        || now_ms.saturating_sub(connection.last_used_ms) >= CONNECTION_IDLE_MS
}

fn response_len(connection: &Connection) -> usize {
    let mut header = [0u8; 128];
    response_header(
        connection.response,
        connection.response_body_len(),
        &mut header,
    )
    .map_or(0, |header_len| header_len + connection.response_body_len())
}

fn append(connection: &mut Connection, payload: &[u8]) -> bool {
    let Some(end) = connection.len.checked_add(payload.len()) else {
        connection.len = CONNECTION_STORAGE;
        return true;
    };
    if end > CONNECTION_STORAGE {
        connection.len = CONNECTION_STORAGE;
        return true;
    }
    connection.buffer[connection.len..end].copy_from_slice(payload);
    connection.len = end;
    connection.client_next = connection.client_next.wrapping_add(payload.len() as u32);
    true
}

fn sequence_before(left: u32, right: u32) -> bool {
    (left.wrapping_sub(right) as i32) < 0
}

fn response_acknowledged(connection: &mut Connection, acknowledgement: u32) -> bool {
    let relative = acknowledgement.wrapping_sub(connection.response_sequence) as usize;
    let sent = connection.response_acked
        + connection.outstanding_payload
        + usize::from(connection.outstanding_fin);
    if relative <= connection.response_acked || relative > sent {
        return false;
    }
    let body_len = connection.response_body_len();
    let mut header = [0u8; 128];
    let Some(header_len) = response_header(connection.response, body_len, &mut header) else {
        return false;
    };
    let total = header_len + body_len;
    let payload_end = connection.response_acked + connection.outstanding_payload;
    connection.response_acked = relative.min(payload_end);
    connection.outstanding_payload = payload_end - connection.response_acked;
    let fin_acked = relative > total;
    if fin_acked {
        connection.outstanding_fin = false;
    }
    fin_acked
}

fn copy_virtual_response(connection: &Connection, header: &[u8], offset: usize, out: &mut [u8]) {
    for (index, byte) in out.iter_mut().enumerate() {
        let source = offset + index;
        *byte = if source < header.len() {
            header[source]
        } else {
            connection.buffer[source - header.len()]
        };
    }
}

fn response_header(kind: ResponseKind, body_len: usize, out: &mut [u8]) -> Option<usize> {
    let (status, content_type) = match kind {
        ResponseKind::Dns => (
            b"HTTP/1.1 200 OK\r\n".as_slice(),
            Some(b"application/dns-message".as_slice()),
        ),
        ResponseKind::Head => (b"HTTP/1.1 200 OK\r\n".as_slice(), None),
        ResponseKind::BadRequest => (b"HTTP/1.1 400 Bad Request\r\n".as_slice(), None),
        ResponseKind::DnsFailure => (b"HTTP/1.1 500 Internal Server Error\r\n".as_slice(), None),
    };
    let mut len = 0;
    push(out, &mut len, status)?;
    if let Some(content_type) = content_type {
        push(out, &mut len, b"Content-Type: ")?;
        push(out, &mut len, content_type)?;
        push(out, &mut len, b"\r\n")?;
    }
    push(out, &mut len, b"Content-Length: ")?;
    let mut digits = [0u8; 20];
    let digits = decimal(body_len, &mut digits);
    push(out, &mut len, digits)?;
    push(out, &mut len, b"\r\nConnection: close\r\n\r\n")?;
    Some(len)
}

fn push(out: &mut [u8], len: &mut usize, bytes: &[u8]) -> Option<()> {
    let end = len.checked_add(bytes.len())?;
    out.get_mut(*len..end)?.copy_from_slice(bytes);
    *len = end;
    Some(())
}

fn decimal(mut value: usize, out: &mut [u8; 20]) -> &[u8] {
    let mut start = out.len();
    loop {
        start -= 1;
        out[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            return &out[start..];
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Parsed {
    Head,
    Dns {
        start: usize,
        end: usize,
        encoded: bool,
    },
}

fn parse_request(bytes: &[u8]) -> Result<Option<Parsed>, ()> {
    let Some(headers_end) = find(bytes, b"\r\n\r\n").map(|at| at + 4) else {
        return Ok(None);
    };
    let line_end = find(bytes, b"\r\n").ok_or(())?;
    let line = &bytes[..line_end];
    if line == b"HEAD / HTTP/1.1" || line == b"HEAD / HTTP/1.0" {
        return Ok(Some(Parsed::Head));
    }
    if let Some(rest) = line.strip_prefix(b"GET /dns-query?dns=") {
        let encoded_len = rest
            .iter()
            .position(|byte| *byte == b'&' || *byte == b' ')
            .ok_or(())?;
        if encoded_len == 0 {
            return Err(());
        }
        let start = line.len() - rest.len();
        return Ok(Some(Parsed::Dns {
            start,
            end: start + encoded_len,
            encoded: true,
        }));
    }
    if line != b"POST /dns-query HTTP/1.1" && line != b"POST /dns-query HTTP/1.0" {
        return Err(());
    }

    let mut content_type = false;
    let mut content_length = None;
    let mut cursor = line_end + 2;
    while cursor + 2 <= headers_end {
        let relative = find(&bytes[cursor..headers_end], b"\r\n").ok_or(())?;
        if relative == 0 {
            break;
        }
        let line = &bytes[cursor..cursor + relative];
        if let Some(value) = header_value(line, b"content-type") {
            content_type = ascii_eq(value, b"application/dns-message");
        } else if let Some(value) = header_value(line, b"content-length") {
            content_length = Some(parse_decimal(value)?);
        }
        cursor += relative + 2;
    }
    if !content_type {
        return Err(());
    }
    let content_length = content_length.ok_or(())?;
    let end = headers_end.checked_add(content_length).ok_or(())?;
    if end > CONNECTION_STORAGE {
        return Err(());
    }
    if bytes.len() < end {
        return Ok(None);
    }
    if bytes.len() != end {
        return Err(());
    }
    Ok(Some(Parsed::Dns {
        start: headers_end,
        end,
        encoded: false,
    }))
}

fn header_value<'a>(line: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let colon = line.iter().position(|byte| *byte == b':')?;
    if !ascii_eq(&line[..colon], name) {
        return None;
    }
    let mut value = &line[colon + 1..];
    while value.first() == Some(&b' ') || value.first() == Some(&b'\t') {
        value = &value[1..];
    }
    while value.last() == Some(&b' ') || value.last() == Some(&b'\t') {
        value = &value[..value.len() - 1];
    }
    Some(value)
}

fn ascii_eq(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

fn parse_decimal(bytes: &[u8]) -> Result<usize, ()> {
    if bytes.is_empty() {
        return Err(());
    }
    let mut value = 0usize;
    for byte in bytes {
        if !byte.is_ascii_digit() {
            return Err(());
        }
        value = value.checked_mul(10).ok_or(())?;
        value = value.checked_add(usize::from(*byte - b'0')).ok_or(())?;
    }
    Ok(value)
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

fn decode_base64url_in_place(buffer: &mut [u8], start: usize, end: usize) -> Option<usize> {
    let input_len = end.checked_sub(start)?;
    if input_len == 0 || input_len % 4 == 1 {
        return None;
    }
    let mut accumulator = 0u32;
    let mut bits = 0u8;
    let mut written = 0usize;
    for index in start..end {
        let value = match buffer[index] {
            b'A'..=b'Z' => buffer[index] - b'A',
            b'a'..=b'z' => buffer[index] - b'a' + 26,
            b'0'..=b'9' => buffer[index] - b'0' + 52,
            b'-' => 62,
            b'_' => 63,
            _ => return None,
        };
        accumulator = (accumulator << 6) | u32::from(value);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            buffer[written] = (accumulator >> bits) as u8;
            written += 1;
            accumulator &= (1u32 << bits) - 1;
        }
    }
    if accumulator != 0 {
        return None;
    }
    Some(written)
}

fn valid_dns_query(message: &[u8]) -> bool {
    message.len() >= 12 && message[2] & 0x80 == 0 && dns_question_end(message).is_some()
}

fn dns_questions_match(query: &[u8], response: &[u8]) -> bool {
    if query.len() < 12 || response.len() < 12 || query[4..6] != response[4..6] {
        return false;
    }
    let count = usize::from(u16::from_be_bytes([query[4], query[5]]));
    if count == 0 {
        return false;
    }
    let mut query_cursor = 12usize;
    let mut response_cursor = 12usize;
    for _ in 0..count {
        loop {
            let Some(&query_len) = query.get(query_cursor) else {
                return false;
            };
            let Some(&response_len) = response.get(response_cursor) else {
                return false;
            };
            if query_len != response_len || query_len > 63 {
                return false;
            }
            query_cursor += 1;
            response_cursor += 1;
            if query_len == 0 {
                break;
            }
            let length = usize::from(query_len);
            let Some(query_label) = query.get(query_cursor..query_cursor + length) else {
                return false;
            };
            let Some(response_label) = response.get(response_cursor..response_cursor + length)
            else {
                return false;
            };
            if !ascii_eq(query_label, response_label) {
                return false;
            }
            query_cursor += length;
            response_cursor += length;
        }
        let Some(query_tail) = query.get(query_cursor..query_cursor + 4) else {
            return false;
        };
        let Some(response_tail) = response.get(response_cursor..response_cursor + 4) else {
            return false;
        };
        if query_tail != response_tail {
            return false;
        }
        query_cursor += 4;
        response_cursor += 4;
    }
    true
}

/// The largest reply this proxy can hold, announced to upstream resolvers.
///
/// A resolver answers up to whatever the query's EDNS0 record asks for, and
/// clients routinely ask for 4096 — far past [`CONNECTION_STORAGE`]. Such a
/// reply used to arrive, fail the length check in [`Server::complete_dns`],
/// and vanish; the client then waited out the whole deadline for a 500.
/// Lowering the announced size makes the resolver truncate and set TC=1
/// instead, which is a defined answer the client's stub knows what to do with.
///
/// 1232 is the usual conservative choice and leaves headroom under the buffer.
pub const MAX_UPSTREAM_UDP_PAYLOAD: u16 = 1232;

const DNS_TYPE_OPT: u16 = 41;

/// Lower the EDNS0 requestor payload size in a query to what we can actually
/// receive, leaving the rest of the message untouched.
///
/// Returns whether a record was rewritten. A query carrying no OPT record needs
/// none: the resolver then assumes the classic 512-byte limit, already within
/// budget.
fn clamp_edns_payload_size(message: &mut [u8]) -> bool {
    let Some(mut cursor) = dns_question_end(message) else {
        return false;
    };
    let count =
        |offset: usize| usize::from(u16::from_be_bytes([message[offset], message[offset + 1]]));
    let records = count(6) + count(8) + count(10);
    for _ in 0..records {
        // Walk the owner name. A query's OPT record always carries the root
        // name, but answer and authority records are stepped over here too.
        loop {
            let Some(&length) = message.get(cursor) else {
                return false;
            };
            if length & 0xc0 == 0xc0 {
                // A compression pointer ends the name and is two bytes wide.
                cursor += 2;
                break;
            }
            if length > 63 {
                return false;
            }
            cursor += 1;
            if length == 0 {
                break;
            }
            cursor += usize::from(length);
        }
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2)
        let Some(header) = message.get(cursor..cursor + 10) else {
            return false;
        };
        let kind = u16::from_be_bytes([header[0], header[1]]);
        if kind == DNS_TYPE_OPT {
            // In an OPT record the CLASS field is not a class: it is the
            // sender's advertised UDP payload size.
            let announced = u16::from_be_bytes([header[2], header[3]]);
            if announced > MAX_UPSTREAM_UDP_PAYLOAD {
                message[cursor + 2..cursor + 4]
                    .copy_from_slice(&MAX_UPSTREAM_UDP_PAYLOAD.to_be_bytes());
                return true;
            }
            return false;
        }
        let rdlength = usize::from(u16::from_be_bytes([header[8], header[9]]));
        cursor += 10 + rdlength;
    }
    false
}

/// Locate the end of every question while rejecting compression pointers in
/// queries. Responses normally repeat questions uncompressed, which also
/// prevents an ID collision from being accepted for a different request.
fn dns_question_end(message: &[u8]) -> Option<usize> {
    if message.len() < 12 {
        return None;
    }
    let count = usize::from(u16::from_be_bytes([message[4], message[5]]));
    if count == 0 {
        return None;
    }
    let mut cursor = 12usize;
    for _ in 0..count {
        loop {
            let length = usize::from(*message.get(cursor)?);
            cursor += 1;
            if length == 0 {
                break;
            }
            if length > 63 {
                return None;
            }
            cursor = cursor.checked_add(length)?;
            if cursor > message.len() {
                return None;
            }
        }
        cursor = cursor.checked_add(4)?;
        if cursor > message.len() {
            return None;
        }
    }
    Some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The packet-policy query provides the authorization directly, so this
    /// layer only carries the client identity into that decision.
    #[test]
    fn a_dns_grant_authorizes_the_client() {
        let client = [100, 64, 0, 2];
        assert!(client_may_resolve(client, |source| source == client));

        let no_dns_grant = |_: [u8; 4]| false;
        assert!(!client_may_resolve(client, no_dns_grant));
    }

    fn dns_query() -> [u8; 17] {
        [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1,
        ]
    }

    fn parsed_segment<'a>(
        storage: &'a mut [u8; 1400],
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> TcpInfo<'a> {
        parsed_segment_from(
            storage,
            [100, 64, 0, 2],
            40000,
            sequence,
            acknowledgement,
            flags,
            payload,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn parsed_segment_from<'a>(
        storage: &'a mut [u8; 1400],
        client_ip: [u8; 4],
        client_port: u16,
        sequence: u32,
        acknowledgement: u32,
        flags: u8,
        payload: &[u8],
    ) -> TcpInfo<'a> {
        let len = nat::build_tcp4(
            client_ip,
            client_port,
            [100, 64, 0, 1],
            PORT,
            sequence,
            acknowledgement,
            flags,
            payload,
            storage,
        )
        .unwrap();
        nat::parse_tcp4(&storage[..len]).unwrap()
    }

    fn establish(server: &mut Server, client_sequence: u32) -> (usize, u32) {
        establish_from(server, [100, 64, 0, 2], 40000, client_sequence)
    }

    fn establish_from(
        server: &mut Server,
        client_ip: [u8; 4],
        client_port: u16,
        client_sequence: u32,
    ) -> (usize, u32) {
        let mut packet = [0; 1400];
        let syn = parsed_segment_from(
            &mut packet,
            client_ip,
            client_port,
            client_sequence,
            0,
            FLAG_SYN,
            &[],
        );
        let received = server.receive(&syn, true, 0);
        let slot = received.slot.unwrap();
        assert!(received.send_ack);
        let server_next = server.connections[slot].server_next;
        let mut packet = [0; 1400];
        let ack = parsed_segment_from(
            &mut packet,
            client_ip,
            client_port,
            client_sequence + 1,
            server_next,
            FLAG_ACK,
            &[],
        );
        server.receive(&ack, true, 1);
        (slot, server_next)
    }

    fn start_dns(server: &mut Server, client_sequence: u32, now_ms: u64) -> (usize, u32, [u8; 17]) {
        let (slot, server_next) = establish(server, client_sequence);
        let query = dns_query();
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let mut request = [0u8; 256];
        request[..header.len()].copy_from_slice(header);
        request[header.len()..header.len() + query.len()].copy_from_slice(&query);
        let mut packet = [0; 1400];
        let segment = parsed_segment(
            &mut packet,
            client_sequence + 1,
            server_next,
            FLAG_ACK,
            &request[..header.len() + query.len()],
        );
        assert!(server.receive(&segment, true, now_ms).dns_query);
        let upstream = server.query(slot).unwrap().try_into().unwrap();
        (slot, server_next, upstream)
    }

    /// A query that asks for 4096 bytes gets answers this proxy cannot hold,
    /// and a reply that does not fit is a reply the client never sees. Asking
    /// for less turns that silent loss into an ordinary truncated answer.
    #[test]
    fn an_ednso_query_is_forwarded_asking_for_a_size_the_buffer_can_hold() {
        // One question, one additional: the root-named OPT record tailscaled
        // attaches, advertising 4096.
        let mut query = [
            0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x01, // header, ARCOUNT=1
            0x00, 0x00, 0x01, 0x00, 0x01, // root question, A/IN
            0x00, // OPT owner name: root
            0x00, 0x29, // TYPE = 41 (OPT)
            0x10, 0x00, // CLASS = advertised payload size = 4096
            0x00, 0x00, 0x00, 0x00, // TTL
            0x00, 0x00, // RDLENGTH
        ];
        assert!(clamp_edns_payload_size(&mut query));
        assert_eq!(
            u16::from_be_bytes([query[20], query[21]]),
            MAX_UPSTREAM_UDP_PAYLOAD
        );
        assert!(MAX_UPSTREAM_UDP_PAYLOAD as usize <= CONNECTION_STORAGE);
        // Everything else is left exactly as the client wrote it.
        assert_eq!(
            &query[..17],
            &[
                0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 1
            ]
        );

        // Already modest, or absent entirely: nothing to do either way.
        query[20..22].copy_from_slice(&512u16.to_be_bytes());
        assert!(!clamp_edns_payload_size(&mut query));
        assert!(!clamp_edns_payload_size(&mut dns_query()));
    }

    #[test]
    fn parses_rfc8484_get_and_post_without_interpreting_dns_records() {
        let query = dns_query();
        let get = b"GET /dns-query?dns=EjQBAAABAAAAAAAAAQAB HTTP/1.1\r\nHost: peer\r\n\r\n";
        assert!(matches!(
            parse_request(get),
            Ok(Some(Parsed::Dns { encoded: true, .. }))
        ));

        let mut post = [0u8; 256];
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        post[..header.len()].copy_from_slice(header);
        post[header.len()..header.len() + query.len()].copy_from_slice(&query);
        assert_eq!(
            parse_request(&post[..header.len() + query.len()]),
            Ok(Some(Parsed::Dns {
                start: header.len(),
                end: header.len() + query.len(),
                encoded: false,
            }))
        );
    }

    #[test]
    fn parses_post_headers_with_trailing_optional_whitespace() {
        let query = dns_query();
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message \t\r\nContent-Length: 17\t \r\n\r\n";
        let mut post = [0u8; 256];
        post[..header.len()].copy_from_slice(header);
        post[header.len()..header.len() + query.len()].copy_from_slice(&query);
        assert!(matches!(
            parse_request(&post[..header.len() + query.len()]),
            Ok(Some(Parsed::Dns { encoded: false, .. }))
        ));
    }

    #[test]
    fn segmented_request_retransmission_is_in_order_and_emits_one_query() {
        let mut server = Server::new(7);
        let (slot, server_next) = establish(&mut server, 100);
        let query = dns_query();
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let split = 41;
        let mut packet = [0; 1400];
        let first = parsed_segment(&mut packet, 101, server_next, FLAG_ACK, &header[..split]);
        let first_result = server.receive(&first, true, 2);
        assert!(first_result.send_ack);
        assert!(!first_result.dns_query);

        let mut packet = [0; 1400];
        let duplicate = parsed_segment(&mut packet, 101, server_next, FLAG_ACK, &header[..split]);
        assert!(!server.receive(&duplicate, true, 3).dns_query);

        let mut remainder = [0u8; 256];
        let rest = &header[split..];
        remainder[..rest.len()].copy_from_slice(rest);
        remainder[rest.len()..rest.len() + query.len()].copy_from_slice(&query);
        let mut packet = [0; 1400];
        let second = parsed_segment(
            &mut packet,
            101 + split as u32,
            server_next,
            FLAG_ACK,
            &remainder[..rest.len() + query.len()],
        );
        let result = server.receive(&second, true, 4);
        assert_eq!(result.slot, Some(slot));
        assert!(result.dns_query);
        let upstream = server.query(slot).unwrap();
        assert_ne!(upstream[..2], query[..2]);
        assert_eq!(upstream[2..], query[2..]);
    }

    #[test]
    fn capacity_acl_malformed_and_oversized_requests_fail_closed() {
        let mut denied = Server::new(1);
        let mut packet = [0; 1400];
        let syn = parsed_segment(&mut packet, 10, 0, FLAG_SYN, &[]);
        assert_eq!(denied.receive(&syn, false, 0), Receive::default());

        let mut server = Server::new(1);
        for index in 0..CONNECTIONS {
            let mut packet = [0; 1400];
            let syn = nat::build_tcp4(
                [100, 64, 0, index as u8 + 2],
                40000 + index as u16,
                [100, 64, 0, 1],
                PORT,
                10,
                0,
                FLAG_SYN,
                &[],
                &mut packet,
            )
            .unwrap();
            assert!(
                server
                    .receive(&nat::parse_tcp4(&packet[..syn]).unwrap(), true, 0)
                    .slot
                    .is_some()
            );
        }
        let mut packet = [0; 1400];
        let syn = nat::build_tcp4(
            [100, 64, 0, 99],
            49999,
            [100, 64, 0, 1],
            PORT,
            10,
            0,
            FLAG_SYN,
            &[],
            &mut packet,
        )
        .unwrap();
        assert!(
            server
                .receive(&nat::parse_tcp4(&packet[..syn]).unwrap(), true, 1)
                .capacity_drop
        );

        assert_eq!(parse_request(b"PUT /dns-query HTTP/1.1\r\n\r\n"), Err(()));
        let oversized = [b'x'; CONNECTION_STORAGE];
        assert_eq!(parse_request(&oversized), Ok(None));
    }

    #[test]
    fn authorization_revocation_discards_an_in_flight_request() {
        let mut server = Server::new(2);
        let (slot, server_next) = establish(&mut server, 50);
        let query = dns_query();
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let mut request = [0u8; 256];
        request[..header.len()].copy_from_slice(header);
        request[header.len()..header.len() + query.len()].copy_from_slice(&query);
        let mut packet = [0; 1400];
        let segment = parsed_segment(
            &mut packet,
            51,
            server_next,
            FLAG_ACK,
            &request[..header.len() + query.len()],
        );

        assert_eq!(
            server.receive(&segment, false, 2),
            Receive {
                send_reset: true,
                ..Receive::default()
            }
        );
        assert_eq!(server.connections[slot].state, State::Free);
        assert_eq!(server.query(slot), None);

        // The client is told, rather than left waiting out its own timeout on
        // a socket the other end has already forgotten.
        let mut reset = [0u8; 1400];
        let len = build_reset(&segment, [100, 64, 0, 1], &mut reset).unwrap();
        let parsed = nat::parse_tcp4(&reset[..len]).unwrap();
        assert!(parsed.is_rst);
        assert_eq!(parsed.dst_ip, [100, 64, 0, 2]);
        assert_eq!(parsed.dst_port, 40000);
        // The segment carried an ACK, so the reset takes its sequence from it.
        assert_eq!(parsed.sequence, server_next);
    }

    #[test]
    fn upstream_ids_disambiguate_equal_client_ids_and_questions() {
        let mut server = Server::new(5);
        let first_client = [100, 64, 0, 2];
        let second_client = [100, 64, 0, 3];
        let (first_slot, first_server_next) = establish_from(&mut server, first_client, 40000, 100);
        let (second_slot, second_server_next) =
            establish_from(&mut server, second_client, 40001, 200);
        assert_ne!(first_slot, second_slot);

        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let first_query = dns_query();
        let mut second_query = dns_query();
        second_query[3] |= 0x10; // Same ID/question, different DNS flags.
        for (client_ip, client_port, sequence, server_next, query) in [
            (first_client, 40000, 101, first_server_next, first_query),
            (second_client, 40001, 201, second_server_next, second_query),
        ] {
            let mut request = [0u8; 256];
            request[..header.len()].copy_from_slice(header);
            request[header.len()..header.len() + query.len()].copy_from_slice(&query);
            let mut packet = [0; 1400];
            let segment = parsed_segment_from(
                &mut packet,
                client_ip,
                client_port,
                sequence,
                server_next,
                FLAG_ACK,
                &request[..header.len() + query.len()],
            );
            assert!(server.receive(&segment, true, 2).dns_query);
        }

        let first_upstream_id: [u8; 2] = server.query(first_slot).unwrap()[..2].try_into().unwrap();
        let second_upstream_id: [u8; 2] =
            server.query(second_slot).unwrap()[..2].try_into().unwrap();
        assert_ne!(first_upstream_id, second_upstream_id);

        let mut second_reply = [0u8; 17];
        second_reply.copy_from_slice(server.query(second_slot).unwrap());
        second_reply[2] |= 0x80;
        assert_eq!(server.complete_dns(0, &second_reply, 3), Some(second_slot));
        assert_eq!(server.connections[first_slot].state, State::AwaitDns);
        assert_eq!(server.connections[second_slot].buffer[..2], [0x12, 0x34]);
    }

    #[test]
    fn reused_slots_get_new_dns_generations_and_reject_delayed_replies() {
        let mut server = Server::new(9);
        let (slot, _, mut delayed_reply) = start_dns(&mut server, 100, 2);
        server.release(slot);

        let (reused, _, current_query) = start_dns(&mut server, 200, 3);
        assert_eq!(reused, slot);
        assert_ne!(delayed_reply[..2], current_query[..2]);
        delayed_reply[2] |= 0x80;
        assert_eq!(server.complete_dns(0, &delayed_reply, 4), None);
        assert_eq!(server.connections[reused].state, State::AwaitDns);
    }

    #[test]
    fn dns_question_names_compare_ascii_case_insensitively() {
        let mut query = [0u8; 29];
        query[..12].copy_from_slice(&[0x12, 0x34, 0x01, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
        query[12..].copy_from_slice(b"\x07Example\x03COM\0\0\x01\0\x01");
        let mut response = query;
        response[2] |= 0x80;
        response[13..20].copy_from_slice(b"eXAMPLE");
        response[21..24].copy_from_slice(b"com");
        assert!(dns_questions_match(&query, &response));
        response[27] = 0x1c;
        assert!(!dns_questions_match(&query, &response));
    }

    #[test]
    fn awaiting_dns_reacks_retransmitted_request_payload() {
        let mut server = Server::new(10);
        let (slot, server_next, _) = start_dns(&mut server, 300, 2);
        let mut packet = [0; 1400];
        let retransmit = parsed_segment(
            &mut packet,
            301,
            server_next,
            FLAG_ACK,
            b"retransmitted request bytes",
        );
        let received = server.receive(&retransmit, true, 3);
        assert_eq!(received.slot, Some(slot));
        assert!(received.send_ack);
        assert!(!received.dns_query);
        assert_eq!(server.connections[slot].state, State::AwaitDns);
    }

    #[test]
    fn response_segments_honor_the_clients_mss() {
        let mut server = Server::new(6);
        let syn = TcpInfo {
            src_port: 40000,
            dst_port: PORT,
            src_ip: [100, 64, 0, 2],
            dst_ip: [100, 64, 0, 1],
            sequence: 300,
            acknowledgement: 0,
            is_syn: true,
            is_fin: false,
            is_rst: false,
            is_ack: false,
            mss: Some(64),
            window_scale: None,
            window: 4096,
            payload: &[],
        };
        let slot = server.receive(&syn, true, 0).slot.unwrap();
        let connection = &mut server.connections[slot];
        connection.buffer[..200].fill(0x5a);
        connection.len = 200;
        connection.begin_response(ResponseKind::Dns);

        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 64);
    }

    #[test]
    fn response_segments_use_the_ipv4_default_when_the_client_omits_mss() {
        let mut server = Server::new(6);
        let syn = TcpInfo {
            src_port: 40000,
            dst_port: PORT,
            src_ip: [100, 64, 0, 2],
            dst_ip: [100, 64, 0, 1],
            sequence: 300,
            acknowledgement: 0,
            is_syn: true,
            is_fin: false,
            is_rst: false,
            is_ack: false,
            mss: None,
            window_scale: None,
            window: 4096,
            payload: &[],
        };
        let slot = server.receive(&syn, true, 0).slot.unwrap();
        let connection = &mut server.connections[slot];
        connection.buffer[..700].fill(0x5a);
        connection.len = 700;
        connection.begin_response(ResponseKind::Dns);

        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        assert_eq!(
            nat::parse_tcp4(&packet[..len]).unwrap().payload.len(),
            usize::from(IPV4_DEFAULT_MSS)
        );
    }

    #[test]
    fn response_probes_a_zero_window_and_caps_to_an_open_window() {
        let mut server = Server::new(6);
        let syn = TcpInfo {
            src_port: 40000,
            dst_port: PORT,
            src_ip: [100, 64, 0, 2],
            dst_ip: [100, 64, 0, 1],
            sequence: 300,
            acknowledgement: 0,
            is_syn: true,
            is_fin: false,
            is_rst: false,
            is_ack: false,
            mss: Some(64),
            window_scale: None,
            window: 0,
            payload: &[],
        };
        let slot = server.receive(&syn, true, 0).slot.unwrap();
        let connection = &mut server.connections[slot];
        connection.buffer[..200].fill(0x5a);
        connection.len = 200;
        connection.begin_response(ResponseKind::Dns);

        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 1);
        assert_eq!(server.connections[slot].outstanding_payload, 0);
        assert_eq!(server.retransmit_due(1 + RETRANSMIT_MS), Some(slot));

        server.connections[slot].peer_window = 32;
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 2)
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 32);
    }

    #[test]
    fn response_probes_a_zero_window_with_an_outstanding_segment() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        let connection = &mut server.connections[slot];
        connection.buffer[..200].fill(0x5a);
        connection.len = 200;
        connection.begin_response(ResponseKind::Dns);
        connection.peer_window = 64;

        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 64);
        assert_eq!(server.connections[slot].outstanding_payload, 64);

        server.connections[slot].peer_window = 0;
        let len = server
            .build_response(
                slot,
                [100, 64, 0, 1],
                &mut payload,
                &mut packet,
                1 + RETRANSMIT_MS,
            )
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 1);
        assert_eq!(server.connections[slot].outstanding_payload, 64);
    }

    #[test]
    fn response_rejects_a_zero_window_probe_without_payload_space() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        server.connections[slot].begin_response(ResponseKind::Head);
        server.connections[slot].peer_window = 0;

        let mut payload = [];
        let mut packet = [0; 1280];
        assert_eq!(
            server.build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1),
            None
        );
    }

    #[test]
    fn a_short_window_retransmission_preserves_the_original_ack_extent() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        let connection = &mut server.connections[slot];
        connection.buffer[..600].fill(0x5a);
        connection.len = 600;
        connection.begin_response(ResponseKind::Dns);
        connection.outstanding_payload = 500;
        connection.peer_window = 100;
        let sequence = connection.response_sequence;

        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        assert_eq!(nat::parse_tcp4(&packet[..len]).unwrap().payload.len(), 100);
        assert_eq!(server.connections[slot].outstanding_payload, 500);
        assert!(!response_acknowledged(
            &mut server.connections[slot],
            sequence.wrapping_add(500)
        ));
        assert_eq!(server.connections[slot].response_acked, 500);
    }

    #[test]
    fn a_partial_ack_keeps_the_remaining_in_flight_extent() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        let connection = &mut server.connections[slot];
        connection.buffer[..600].fill(0x5a);
        connection.len = 600;
        connection.begin_response(ResponseKind::Dns);
        connection.outstanding_payload = 500;
        let sequence = connection.response_sequence;

        assert!(!response_acknowledged(
            connection,
            sequence.wrapping_add(100)
        ));
        assert_eq!(connection.response_acked, 100);
        assert_eq!(connection.outstanding_payload, 400);
        assert!(!response_acknowledged(
            connection,
            sequence.wrapping_add(500)
        ));
        assert_eq!(connection.response_acked, 500);
        assert_eq!(connection.outstanding_payload, 0);
    }

    #[test]
    fn stale_ack_does_not_replace_the_current_receive_window() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        let connection = &mut server.connections[slot];
        connection.begin_response(ResponseKind::Head);
        connection.response_acked = 10;
        connection.peer_window = 100;
        let stale_ack = TcpInfo {
            src_port: connection.client_port,
            dst_port: PORT,
            src_ip: connection.client_ip,
            dst_ip: [100, 64, 0, 1],
            sequence: connection.client_next,
            acknowledgement: connection.response_sequence.wrapping_add(9),
            is_syn: false,
            is_fin: false,
            is_rst: false,
            is_ack: true,
            mss: None,
            window_scale: None,
            window: 0,
            payload: &[],
        };
        server.receive(&stale_ack, true, 1);
        assert_eq!(server.connections[slot].peer_window, 100);
    }

    #[test]
    fn only_a_bare_syn_can_allocate_a_connection() {
        let mut server = Server::new(6);
        let invalid_syn = TcpInfo {
            src_port: 40000,
            dst_port: PORT,
            src_ip: [100, 64, 0, 2],
            dst_ip: [100, 64, 0, 1],
            sequence: 300,
            acknowledgement: 1,
            is_syn: true,
            is_fin: false,
            is_rst: false,
            is_ack: true,
            mss: Some(64),
            window_scale: None,
            window: 4096,
            payload: &[],
        };
        assert_eq!(server.receive(&invalid_syn, true, 0), Receive::default());
        assert_eq!(server.connections[0].state, State::Free);
    }

    #[test]
    fn acknowledged_response_releases_a_previously_half_closed_request() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        server.connections[slot].client_fin = true;
        server.connections[slot].begin_response(ResponseKind::Head);
        let client_next = server.connections[slot].client_next;
        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();
        let response = nat::parse_tcp4(&packet[..len]).unwrap();
        let acknowledgement = response.sequence + response.payload.len() as u32 + 1;

        let mut packet = [0; 1400];
        let ack = parsed_segment(&mut packet, client_next, acknowledgement, FLAG_ACK, &[]);
        let received = server.receive(&ack, true, 2);
        assert!(received.close_after_ack);
    }

    #[test]
    fn abandoned_response_stops_retransmitting_at_the_idle_deadline() {
        let mut server = Server::new(6);
        let (slot, _) = establish(&mut server, 300);
        server.connections[slot].begin_response(ResponseKind::Head);
        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 1)
            .unwrap();

        assert_eq!(server.retransmit_due(300 + CONNECTION_IDLE_MS), None);
        assert_eq!(server.connections[slot].state, State::Free);
    }

    #[test]
    fn an_in_order_fin_turns_a_truncated_request_into_bad_request() {
        let mut server = Server::new(6);
        let (slot, server_next) = establish(&mut server, 100);
        let partial = b"GET /dns-query?dns=";
        let mut packet = [0; 1400];
        let request = parsed_segment(&mut packet, 101, server_next, FLAG_ACK, partial);
        let received = server.receive(&request, true, 2);
        assert!(received.send_ack);
        assert!(!received.send_response);

        let mut packet = [0; 1400];
        let fin = parsed_segment(
            &mut packet,
            101 + partial.len() as u32,
            server_next,
            FLAG_ACK | FLAG_FIN,
            &[],
        );
        let received = server.receive(&fin, true, 3);
        assert_eq!(received.slot, Some(slot));
        assert!(received.send_ack);
        assert!(received.send_response);
        assert_eq!(server.connections[slot].state, State::Responding);
        assert_eq!(server.connections[slot].response, ResponseKind::BadRequest);
    }

    #[test]
    fn an_expired_same_tuple_syn_starts_a_new_connection() {
        let mut server = Server::new(7);
        let (slot, old_server_next) = establish(&mut server, 400);
        server.connections[slot].last_used_ms = 0;

        let mut packet = [0; 1400];
        let syn = parsed_segment(&mut packet, 900, 0, FLAG_SYN, &[]);
        let received = server.receive(&syn, true, CONNECTION_IDLE_MS);
        assert_eq!(received.slot, Some(slot));
        assert!(received.send_ack);
        assert_eq!(server.connections[slot].state, State::SynReceived);
        assert_eq!(server.connections[slot].client_next, 901);
        assert_ne!(server.connections[slot].server_next, old_server_next);

        let mut ack = [0; 1280];
        let len = server.build_ack(slot, [100, 64, 0, 1], &mut ack).unwrap();
        assert!(nat::parse_tcp4(&ack[..len]).unwrap().is_syn);

        let new_server_next = server.connections[slot].server_next;
        let mut packet = [0; 1400];
        let handshake_ack = parsed_segment(&mut packet, 901, new_server_next, FLAG_ACK, &[]);
        server.receive(&handshake_ack, true, CONNECTION_IDLE_MS + 1);
        assert_eq!(server.connections[slot].state, State::Request);

        let mut packet = [0; 1400];
        let stale_rst = parsed_segment(&mut packet, 401, old_server_next, FLAG_RST | FLAG_ACK, &[]);
        assert_eq!(
            server.receive(&stale_rst, true, CONNECTION_IDLE_MS + 2),
            Receive::default()
        );
        assert_eq!(server.connections[slot].state, State::Request);

        let mut packet = [0; 1400];
        let current_rst =
            parsed_segment(&mut packet, 901, new_server_next, FLAG_RST | FLAG_ACK, &[]);
        assert_eq!(
            server
                .receive(&current_rst, true, CONNECTION_IDLE_MS + 3)
                .slot,
            Some(slot)
        );
        assert_eq!(server.connections[slot].state, State::Free);
    }

    #[test]
    fn a_retransmitted_fin_consumes_one_sequence_number() {
        let mut server = Server::new(8);
        let (slot, server_next) = establish(&mut server, 500);
        server.connections[slot].state = State::AwaitDns;
        let expected = server.connections[slot].client_next;

        for now_ms in [2, 3] {
            let mut packet = [0; 1400];
            let fin = parsed_segment(&mut packet, expected, server_next, FLAG_ACK | FLAG_FIN, &[]);
            assert!(server.receive(&fin, true, now_ms).send_ack);
        }
        assert_eq!(server.connections[slot].client_next, expected + 1);
    }

    #[test]
    fn resolver_failover_timeout_and_response_closure_are_bounded() {
        let mut server = Server::new(3);
        let (slot, server_next) = establish(&mut server, 20);
        let query = dns_query();
        let header = b"POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: 17\r\n\r\n";
        let mut request = [0u8; 256];
        request[..header.len()].copy_from_slice(header);
        request[header.len()..header.len() + query.len()].copy_from_slice(&query);
        let mut packet = [0; 1400];
        let segment = parsed_segment(
            &mut packet,
            21,
            server_next,
            FLAG_ACK,
            &request[..header.len() + query.len()],
        );
        assert!(server.receive(&segment, true, 10).dns_query);
        assert_eq!(
            server.poll_dns(10 + DNS_FAILOVER_MS, 2),
            Some(DnsTimer::Send { slot, resolver: 1 })
        );

        let mut reply: [u8; 17] = server.query(slot).unwrap().try_into().unwrap();
        reply[2] |= 0x80;
        reply[7] = 1; // Answer counts differ from queries and are not question identity.
        assert_eq!(server.complete_dns(0, &reply, 2_500), Some(slot));
        let mut client_reply = query;
        client_reply[2] |= 0x80;
        client_reply[7] = 1;
        let mut payload = [0; 1240];
        let mut packet = [0; 1280];
        let len = server
            .build_response(slot, [100, 64, 0, 1], &mut payload, &mut packet, 2_500)
            .unwrap();
        let response = nat::parse_tcp4(&packet[..len]).unwrap();
        assert!(response.is_fin);
        assert!(response.payload.starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(response.payload.ends_with(&client_reply));

        let acknowledgement = response.sequence + response.payload.len() as u32 + 1;
        let mut packet = [0; 1400];
        let ack = parsed_segment(
            &mut packet,
            21 + request.len() as u32,
            acknowledgement,
            FLAG_ACK,
            &[],
        );
        server.receive(&ack, true, 2_600);
        assert_eq!(server.connections[slot].state, State::Closing);
        let mut packet = [0; 1400];
        let fin = parsed_segment(
            &mut packet,
            21 + request.len() as u32,
            acknowledgement,
            FLAG_ACK | FLAG_FIN,
            &[],
        );
        let closed = server.receive(&fin, true, 2_601);
        assert!(closed.send_ack);
        assert!(closed.close_after_ack);
        server.release(slot);
        assert_eq!(server.connections[slot].state, State::Free);

        let mut timed_out = Server::new(4);
        let (slot, _) = establish(&mut timed_out, 30);
        timed_out.connections[slot].state = State::AwaitDns;
        timed_out.connections[slot].dns_started_ms = 1;
        assert_eq!(
            timed_out.poll_dns(1 + DNS_TIMEOUT_MS, 1),
            Some(DnsTimer::Failed { slot })
        );
    }
}
