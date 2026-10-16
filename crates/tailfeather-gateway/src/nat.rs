//! Allocation-free source NAT state and packet rewriting for UDP and TCP.
//!
//! Socket ownership stays with the caller: firmware uses embassy-net while the
//! bare harness uses Linux directly. Keeping parsing, fixed-capacity flow
//! allocation, checksum rewriting, fragmentation policy, and MSS clamping here
//! ensures both environments execute the same production packet core.

use crate::checksum;

/// Concurrent UDP flows. All mappings share one raw socket, so entries cost
/// only tuple state rather than a separately buffered socket.
pub const SLOTS: usize = 32;

/// External ports are assigned one per slot, so a reply's destination port
/// identifies its flow before the table is consulted.
pub const EXT_PORT_BASE: u16 = 40000;

/// Drop a flow that has been idle this long, freeing its slot.
pub const IDLE_TIMEOUT_MS: u64 = 30_000;

const PROTO_UDP: u8 = 17;
const PROTO_ICMP: u8 = 1;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

/// Concurrent ICMP echo translations. Identifiers, rather than ports, select
/// the reverse mapping.
pub const ICMP_SLOTS: usize = 4;
pub const ICMP_ID_BASE: u16 = 0x4000;
pub const ICMP_IDLE_TIMEOUT_MS: u64 = 30_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Icmp4 {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub identifier: u16,
    pub is_request: bool,
    pub is_reply: bool,
}

#[derive(Clone, Copy)]
pub struct IcmpFlow {
    pub client_ip: [u8; 4],
    pub server_ip: [u8; 4],
    pub client_identifier: u16,
    pub last_used_ms: u64,
}

#[derive(Default)]
pub struct IcmpTable {
    flows: [Option<IcmpFlow>; ICMP_SLOTS],
}

impl IcmpTable {
    pub const fn new() -> Self {
        Self {
            flows: [None; ICMP_SLOTS],
        }
    }

    pub fn slot_for(&mut self, packet: &Icmp4, now_ms: u64) -> Option<usize> {
        let slot = self.slot_for_packet(packet, now_ms)?;
        self.observe_outbound(slot, packet, now_ms);
        Some(slot)
    }

    /// Select a translation slot without changing the table.
    ///
    /// Raw-socket callers use this before attempting a nonblocking enqueue,
    /// then commit with [`Self::observe_outbound`] only after it succeeds.
    pub fn slot_for_packet(&self, packet: &Icmp4, now_ms: u64) -> Option<usize> {
        if !packet.is_request {
            return None;
        }
        if let Some(index) = self.flows.iter().position(|flow| {
            flow.is_some_and(|flow| {
                flow.client_ip == packet.src_ip
                    && flow.server_ip == packet.dst_ip
                    && flow.client_identifier == packet.identifier
            })
        }) {
            return Some(index);
        }
        self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, flow)| {
                    flow.is_some_and(|flow| {
                        now_ms.saturating_sub(flow.last_used_ms) >= ICMP_IDLE_TIMEOUT_MS
                    })
                })
                .min_by_key(|(_, flow)| flow.map(|flow| flow.last_used_ms).unwrap_or(0))
                .map(|(index, _)| index)
        })
    }

    /// Commit a successfully enqueued outbound echo request.
    pub fn observe_outbound(&mut self, slot: usize, packet: &Icmp4, now_ms: u64) {
        if !packet.is_request || slot >= ICMP_SLOTS {
            return;
        }
        self.flows[slot] = Some(IcmpFlow {
            client_ip: packet.src_ip,
            server_ip: packet.dst_ip,
            client_identifier: packet.identifier,
            last_used_ms: now_ms,
        });
    }

    pub fn reverse(&mut self, packet: &Icmp4, uplink: [u8; 4], now_ms: u64) -> Option<IcmpFlow> {
        if !packet.is_reply || packet.dst_ip != uplink {
            return None;
        }
        let slot = packet.identifier.checked_sub(ICMP_ID_BASE)? as usize;
        let flow = self.flows.get(slot).copied().flatten()?;
        if packet.src_ip != flow.server_ip {
            return None;
        }
        self.flows[slot].as_mut()?.last_used_ms = now_ms;
        Some(flow)
    }
}

pub fn parse_icmp4(packet: &[u8]) -> Option<Icmp4> {
    let (header_len, total_len) = ipv4_bounds(packet, PROTO_ICMP)?;
    if total_len < header_len + 8 {
        return None;
    }
    if checksum(&packet[header_len..total_len]) != 0 {
        return None;
    }
    let kind = packet[header_len];
    if !matches!(kind, 0 | 8) || packet[header_len + 1] != 0 {
        return None;
    }
    Some(Icmp4 {
        src_ip: packet[12..16].try_into().ok()?,
        dst_ip: packet[16..20].try_into().ok()?,
        identifier: u16::from_be_bytes(packet[header_len + 4..header_len + 6].try_into().ok()?),
        is_request: kind == 8,
        is_reply: kind == 0,
    })
}

pub fn rewrite_icmp_outbound(packet: &mut [u8], uplink: [u8; 4], slot: usize) -> bool {
    let Some(info) = parse_icmp4(packet) else {
        return false;
    };
    if !info.is_request || slot >= ICMP_SLOTS {
        return false;
    }
    packet[12..16].copy_from_slice(&uplink);
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[header_len + 4..header_len + 6]
        .copy_from_slice(&(ICMP_ID_BASE + slot as u16).to_be_bytes());
    repair_ip_icmp_checksums(packet, header_len)
}

pub fn rewrite_icmp_inbound(packet: &mut [u8], flow: IcmpFlow) -> bool {
    let Some(info) = parse_icmp4(packet) else {
        return false;
    };
    if !info.is_reply {
        return false;
    }
    packet[16..20].copy_from_slice(&flow.client_ip);
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    packet[header_len + 4..header_len + 6].copy_from_slice(&flow.client_identifier.to_be_bytes());
    repair_ip_icmp_checksums(packet, header_len)
}

fn repair_ip_icmp_checksums(packet: &mut [u8], header_len: usize) -> bool {
    let total = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if total > packet.len() {
        return false;
    }
    packet[10..12].fill(0);
    let sum = crate::checksum(&packet[..header_len]);
    packet[10..12].copy_from_slice(&sum.to_be_bytes());
    packet[header_len + 2..header_len + 4].fill(0);
    let sum = crate::checksum(&packet[header_len..total]);
    packet[header_len + 2..header_len + 4].copy_from_slice(&sum.to_be_bytes());
    true
}

/// The largest inner payload we can forward: a full inner packet less its own
/// IP and UDP headers.
pub const MAX_PAYLOAD: usize = wirefeather::budget::INNER_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN;

/// One translated flow. The external port is implied by the slot index.
#[derive(Clone, Copy)]
pub struct Flow {
    pub client_ip: [u8; 4],
    pub client_port: u16,
    pub server_ip: [u8; 4],
    pub server_port: u16,
    pub last_used_ms: u64,
}

#[derive(Default)]
pub struct Table {
    flows: [Option<Flow>; SLOTS],
}

impl Table {
    pub const fn new() -> Self {
        Self {
            flows: [None; SLOTS],
        }
    }

    /// The slot for this flow, creating one if necessary.
    ///
    /// Returns the slot index, and whether the caller must rebind that slot's
    /// socket because the slot was reused for a different flow. Returns `None`
    /// only if every slot is occupied by a flow younger than the idle timeout.
    pub fn slot_for(
        &mut self,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) -> Option<usize> {
        let slot = self.slot_for_packet(client_ip, client_port, server_ip, server_port, now_ms)?;
        self.observe_outbound(slot, client_ip, client_port, server_ip, server_port, now_ms);
        Some(slot)
    }

    /// Select a translation slot without changing the table.
    pub fn slot_for_packet(
        &self,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) -> Option<usize> {
        let matches = |f: &Flow| {
            f.client_ip == client_ip
                && f.client_port == client_port
                && f.server_ip == server_ip
                && f.server_port == server_port
        };

        if let Some(index) = self
            .flows
            .iter()
            .position(|f| f.is_some_and(|f| matches(&f)))
        {
            return Some(index);
        }

        // Prefer a free slot, then the least recently used one that has gone
        // idle. A busy table never evicts a live flow, it just refuses.
        let victim = self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    f.is_some_and(|f| now_ms.saturating_sub(f.last_used_ms) >= IDLE_TIMEOUT_MS)
                })
                .min_by_key(|(_, f)| f.map(|f| f.last_used_ms).unwrap_or(0))
                .map(|(i, _)| i)
        })?;

        Some(victim)
    }

    /// Commit a successfully enqueued outbound UDP datagram.
    pub fn observe_outbound(
        &mut self,
        slot: usize,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) {
        if slot >= SLOTS {
            return;
        }
        self.flows[slot] = Some(Flow {
            client_ip,
            client_port,
            server_ip,
            server_port,
            last_used_ms: now_ms,
        });
    }

    pub fn get(&self, slot: usize) -> Option<Flow> {
        self.flows.get(slot).copied().flatten()
    }

    pub fn touch(&mut self, slot: usize, now_ms: u64) {
        if let Some(Some(flow)) = self.flows.get_mut(slot) {
            flow.last_used_ms = now_ms;
        }
    }

    /// Resolve a raw uplink reply only when its complete tuple belongs to one
    /// of our translated UDP flows. A translated port by itself is not an
    /// authority: raw sockets also see unrelated host traffic.
    pub fn reverse_udp(&mut self, packet: &Udp4<'_>, uplink: [u8; 4], now_ms: u64) -> Option<Flow> {
        let slot = packet.dst_port.checked_sub(EXT_PORT_BASE)? as usize;
        let flow = self.get(slot)?;
        if packet.dst_ip != uplink
            || packet.src_ip != flow.server_ip
            || packet.src_port != flow.server_port
        {
            return None;
        }
        self.touch(slot, now_ms);
        Some(flow)
    }
}

/// Concurrent TCP flows. These cost only a table entry — the packets are
/// forwarded through one shared raw socket rather than a socket each — so the
/// table can be considerably larger than the UDP one. A single page load opens
/// several connections at once.
pub const TCP_SLOTS: usize = 48;

/// External ports for translated TCP, one per slot, so a segment's destination
/// port identifies its flow.
pub const TCP_EXT_PORT_BASE: u16 = 41000;

/// Idle timeout for a TCP flow. Longer than UDP's because a connection may sit
/// silent between requests and still be very much alive.
pub const TCP_IDLE_TIMEOUT_MS: u64 = 120_000;

/// Keep a completely FIN-closed mapping through the remote TCP TIME_WAIT
/// interval so a new connection cannot reuse the same external tuple.
pub const TCP_CLOSED_GRACE_MS: u64 = 60_000;

/// The largest MSS we let either end negotiate.
///
/// A segment that arrives larger than the tunnel's MTU cannot be encapsulated
/// and is simply dropped, which presents as a connection that opens and then
/// hangs the moment it carries real data. Clamping the option in the SYN stops
/// that at the source instead.
pub const MAX_MSS: u16 = (wirefeather::budget::INNER_MTU
    - IPV4_HEADER_LEN
    - IPV4_MAX_OPTION_BYTES
    - TCP_HEADER_LEN
    - TCP_MAX_OPTION_BYTES) as u16;

const PROTO_TCP: u8 = 6;
const TCP_HEADER_LEN: usize = 20;
const IPV4_MAX_OPTION_BYTES: usize = 40;
const TCP_MAX_OPTION_BYTES: usize = 40;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_FIN: u8 = 0x01;
const OPTION_END: u8 = 0;
const OPTION_NOP: u8 = 1;
const OPTION_MSS: u8 = 2;
const OPTION_WINDOW_SCALE: u8 = 3;

#[derive(Clone, Copy)]
struct TcpFlow {
    tuple: Flow,
    external_port: u16,
    client_fin: bool,
    server_fin: bool,
    closed_at_ms: Option<u64>,
    client_next_seq: Option<u32>,
    server_next_seq: Option<u32>,
    /// The exponent each endpoint offered in its own SYN, or `None` when that
    /// SYN carried no Window Scale option. RFC 7323 enables scaling only when
    /// both SYNs offer it, so the pair must be kept, not just the values.
    client_window_scale: Option<u8>,
    server_window_scale: Option<u8>,
}

pub struct TcpTable {
    flows: [Option<TcpFlow>; TCP_SLOTS],
    port_generations: [u16; TCP_SLOTS],
    /// When generation 0 of each slot's port sequence was last released.
    ///
    /// Wrapping back to it reuses a port whose previous connection may still be
    /// in the remote's TIME_WAIT, so the wrap waits for that connection to age
    /// out rather than measuring from when it was originally opened.
    first_port_released_ms: [Option<u64>; TCP_SLOTS],
}

impl Default for TcpTable {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpTable {
    pub const fn new() -> Self {
        Self {
            flows: [None; TCP_SLOTS],
            port_generations: [u16::MAX; TCP_SLOTS],
            first_port_released_ms: [None; TCP_SLOTS],
        }
    }

    fn next_external_port(&self, slot: usize, now_ms: u64) -> Option<(u16, u16)> {
        let slot_port = u16::try_from(slot).ok()?;
        let stride = TCP_SLOTS as u16;
        let max_generation = (u16::MAX - TCP_EXT_PORT_BASE - slot_port) / stride;
        let generation = match self.port_generations.get(slot).copied()? {
            u16::MAX => 0,
            current if current >= max_generation => {
                // The sequence has run out and would restart at generation 0.
                // Its port is only safe once the connection that used it has
                // left the remote's TIME_WAIT; until then, refuse rather than
                // hand a stale four-tuple to a new flow.
                let released = self.first_port_released_ms.get(slot).copied()??;
                if now_ms.saturating_sub(released) < TCP_CLOSED_GRACE_MS {
                    return None;
                }
                0
            }
            current => current + 1,
        };
        let port = TCP_EXT_PORT_BASE + slot_port + generation * stride;
        Some((port, generation))
    }

    fn install_flow(
        &mut self,
        slot: usize,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) -> bool {
        let Some((external_port, generation)) = self.next_external_port(slot, now_ms) else {
            return false;
        };
        if self
            .flows
            .get(slot)
            .copied()
            .flatten()
            .is_some_and(|flow| flow.external_port == TCP_EXT_PORT_BASE + slot as u16)
        {
            self.first_port_released_ms[slot] = Some(now_ms);
        }
        self.port_generations[slot] = generation;
        if generation == 0 {
            self.first_port_released_ms[slot] = None;
        }
        self.flows[slot] = Some(TcpFlow {
            tuple: Flow {
                client_ip,
                client_port,
                server_ip,
                server_port,
                last_used_ms: now_ms,
            },
            external_port,
            client_fin: false,
            server_fin: false,
            closed_at_ms: None,
            client_next_seq: None,
            server_next_seq: None,
            client_window_scale: None,
            server_window_scale: None,
        });
        true
    }

    /// The slot for this connection, creating one if necessary.
    pub fn slot_for(
        &mut self,
        client_ip: [u8; 4],
        client_port: u16,
        server_ip: [u8; 4],
        server_port: u16,
        now_ms: u64,
    ) -> Option<usize> {
        let matches = |f: &TcpFlow| {
            f.tuple.client_ip == client_ip
                && f.tuple.client_port == client_port
                && f.tuple.server_ip == server_ip
                && f.tuple.server_port == server_port
        };

        if let Some(index) = self
            .flows
            .iter()
            .position(|f| f.is_some_and(|f| matches(&f)))
        {
            if let Some(flow) = &mut self.flows[index] {
                flow.tuple.last_used_ms = now_ms;
            }
            return Some(index);
        }

        let victim = self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, flow)| {
                    flow.is_some_and(|flow| {
                        flow.closed_at_ms.is_some()
                            || now_ms.saturating_sub(flow.tuple.last_used_ms) >= TCP_IDLE_TIMEOUT_MS
                    })
                })
                .min_by_key(|(_, flow)| flow.map(|flow| flow.tuple.last_used_ms).unwrap_or(0))
                .map(|(index, _)| index)
        })?;

        self.install_flow(
            victim,
            client_ip,
            client_port,
            server_ip,
            server_port,
            now_ms,
        )
        .then_some(())?;
        Some(victim)
    }

    /// Select the mapping for an outbound segment and reset a completed tuple
    /// when a new SYN starts its next lifetime.
    ///
    /// Raw-socket callers commit the selection with [`Self::observe_outbound`]
    /// only after a nonblocking enqueue succeeds.
    pub fn slot_for_packet(&mut self, packet: &TcpInfo<'_>, now_ms: u64) -> Option<usize> {
        let existing = self.flows.iter().position(|entry| {
            entry.is_some_and(|flow| {
                flow.tuple.client_ip == packet.src_ip
                    && flow.tuple.client_port == packet.src_port
                    && flow.tuple.server_ip == packet.dst_ip
                    && flow.tuple.server_port == packet.dst_port
            })
        });

        // Only an initial SYN can begin a connection. Requiring every other
        // segment to match an existing tuple prevents stray ACKs, FINs, RSTs,
        // and SYN-ACKs from consuming the fixed-capacity table.
        if let Some(slot) = existing {
            return Some(slot);
        }
        if !packet.opens_connection() {
            return None;
        }
        self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, flow)| {
                    flow.is_some_and(|flow| {
                        flow.closed_at_ms.is_some()
                            || now_ms.saturating_sub(flow.tuple.last_used_ms) >= TCP_IDLE_TIMEOUT_MS
                    })
                })
                .min_by_key(|(_, flow)| flow.map(|flow| flow.tuple.last_used_ms).unwrap_or(0))
                .map(|(index, _)| index)
        })
    }

    pub fn get(&self, slot: usize) -> Option<Flow> {
        self.flows
            .get(slot)
            .copied()
            .flatten()
            .map(|flow| flow.tuple)
    }

    pub fn touch(&mut self, slot: usize, now_ms: u64) {
        if let Some(Some(flow)) = self.flows.get_mut(slot) {
            flow.tuple.last_used_ms = now_ms;
        }
    }

    /// External port for a selected outbound packet.
    ///
    /// Reusing a closed slot rotates to another port in the same slot's
    /// generation sequence. The old TIME_WAIT tuple therefore remains
    /// distinguishable even though its table storage can be reclaimed.
    pub fn external_port_for_packet(
        &self,
        slot: usize,
        packet: &TcpInfo<'_>,
        now_ms: u64,
    ) -> Option<u16> {
        let existing = self.flows.get(slot).copied().flatten();
        let matches = existing.is_some_and(|flow| {
            flow.tuple.client_ip == packet.src_ip
                && flow.tuple.client_port == packet.src_port
                && flow.tuple.server_ip == packet.dst_ip
                && flow.tuple.server_port == packet.dst_port
        });
        if matches
            && !existing
                .is_some_and(|flow| packet.opens_connection() && flow.closed_at_ms.is_some())
        {
            return existing.map(|flow| flow.external_port);
        }
        self.next_external_port(slot, now_ms).map(|(port, _)| port)
    }

    /// Record client-to-server sequence and closure state after enqueue.
    pub fn observe_outbound(&mut self, slot: usize, packet: &TcpInfo, now_ms: u64) {
        if packet.opens_connection() {
            let Some(existing) = self.flows.get(slot).copied() else {
                return;
            };
            let matches = existing.is_some_and(|flow| {
                flow.tuple.client_ip == packet.src_ip
                    && flow.tuple.client_port == packet.src_port
                    && flow.tuple.server_ip == packet.dst_ip
                    && flow.tuple.server_port == packet.dst_port
            });
            let closed = existing.is_some_and(|flow| flow.closed_at_ms.is_some());
            if !matches || closed {
                if !self.install_flow(
                    slot,
                    packet.src_ip,
                    packet.src_port,
                    packet.dst_ip,
                    packet.dst_port,
                    now_ms,
                ) {
                    return;
                }
            } else if let Some(Some(flow)) = self.flows.get_mut(slot)
                // A SYN carrying the sequence this flow already recorded is a
                // retransmission of the handshake in progress, not a new
                // lifetime. Resetting on it would forget the server's window
                // scale from a SYN-ACK the client already has and will not see
                // repeated, leaving established server windows read as
                // unscaled.
                && flow.client_next_seq != Some(packet.next_sequence())
            {
                flow.client_fin = false;
                flow.server_fin = false;
                flow.closed_at_ms = None;
                flow.client_next_seq = None;
                flow.server_next_seq = None;
                flow.client_window_scale = None;
                flow.server_window_scale = None;
            }
        }
        self.observe(slot, packet, true, now_ms)
    }

    /// Record server-to-client sequence and closure state.
    pub fn observe_inbound(&mut self, slot: usize, packet: &TcpInfo<'_>, now_ms: u64) {
        self.observe(slot, packet, false, now_ms)
    }

    fn observe(&mut self, slot: usize, packet: &TcpInfo<'_>, outbound: bool, now_ms: u64) {
        let Some(Some(flow)) = self.flows.get_mut(slot) else {
            return;
        };
        flow.tuple.last_used_ms = now_ms;
        if packet.is_syn {
            let scale = packet.window_scale.map(|scale| scale.min(14));
            if outbound {
                flow.client_window_scale = scale;
            } else {
                flow.server_window_scale = scale;
            }
        }
        let (own_next, peer_next) = if outbound {
            (&mut flow.client_next_seq, flow.server_next_seq)
        } else {
            (&mut flow.server_next_seq, flow.client_next_seq)
        };

        if packet.is_rst {
            // Once this direction has sent a segment, RFC 5961's strict reset
            // check requires the RST sequence to equal the next expected one.
            // A refused initial SYN has no server sequence yet, so validate its
            // RST|ACK against the authenticated client's next sequence instead.
            let valid = own_next.map_or_else(
                || packet.is_ack && peer_next == Some(packet.acknowledgement),
                |expected| packet.sequence == expected,
            );
            if valid {
                if flow.external_port == TCP_EXT_PORT_BASE + slot as u16 {
                    self.first_port_released_ms[slot] = Some(now_ms);
                }
                self.flows[slot] = None;
            }
            return;
        }

        let next = packet.next_sequence();
        let sequence_valid = match *own_next {
            None if outbound || !packet.is_ack || peer_next == Some(packet.acknowledgement) => {
                *own_next = Some(next);
                true
            }
            Some(expected) if packet.sequence == expected => {
                *own_next = Some(next);
                true
            }
            _ => false,
        };

        if packet.is_fin && sequence_valid {
            if outbound {
                flow.client_fin = true;
            } else {
                flow.server_fin = true;
            }
            if flow.client_fin && flow.server_fin && flow.closed_at_ms.is_none() {
                flow.closed_at_ms = Some(now_ms);
            }
        }
    }

    pub fn closure(&self, slot: usize) -> Option<(bool, bool, Option<u64>)> {
        let flow = self.flows.get(slot).copied().flatten()?;
        Some((flow.client_fin, flow.server_fin, flow.closed_at_ms))
    }

    /// The receive-window scale in effect for this flow endpoint.
    ///
    /// The gateway rewrites the on-wire option to zero, so later window fields
    /// must be expanded by the endpoint's original scale before being capped.
    /// Scaling is only in effect once *both* SYNs offered the option: if the
    /// server's SYN-ACK omits it, RFC 7323 disables scaling in both directions
    /// and every window field stays a plain 16-bit count. Expanding one anyway
    /// would let the gateway advertise more space than the endpoint has.
    pub fn window_scale(&self, slot: usize, outbound: bool) -> u8 {
        self.flows
            .get(slot)
            .copied()
            .flatten()
            .and_then(|flow| {
                let (client, server) = (flow.client_window_scale?, flow.server_window_scale?);
                Some(if outbound { client } else { server })
            })
            .unwrap_or(0)
    }

    /// Explicitly release a slot when a caller has independently established
    /// that the connection is no longer live.
    pub fn release(&mut self, slot: usize, now_ms: u64) {
        if let Some(entry) = self.flows.get_mut(slot) {
            if entry.is_some_and(|flow| flow.external_port == TCP_EXT_PORT_BASE + slot as u16) {
                self.first_port_released_ms[slot] = Some(now_ms);
            }
            *entry = None;
        }
    }

    pub fn slot_for_external_port(&self, port: u16) -> Option<usize> {
        self.flows
            .iter()
            .position(|flow| flow.is_some_and(|flow| flow.external_port == port))
    }

    /// Resolve a raw uplink TCP segment against its complete translated tuple.
    pub fn reverse_tcp(&self, packet: &TcpInfo<'_>, uplink: [u8; 4]) -> Option<Flow> {
        let slot = self.slot_for_external_port(packet.dst_port)?;
        let flow = self.get(slot)?;
        if packet.dst_ip != uplink
            || packet.src_ip != flow.server_ip
            || packet.src_port != flow.server_port
        {
            return None;
        }
        Some(flow)
    }
}

/// Portable view of an unfragmented inner TCP segment.
pub struct TcpInfo<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub sequence: u32,
    pub acknowledgement: u32,
    /// The peer's currently advertised receive window in bytes.
    pub window: u16,
    pub is_syn: bool,
    pub is_fin: bool,
    pub is_rst: bool,
    pub is_ack: bool,
    pub mss: Option<u16>,
    /// Window Scale announced by this endpoint on a SYN, capped per RFC 7323.
    pub window_scale: Option<u8>,
    pub payload: &'a [u8],
}

impl TcpInfo<'_> {
    fn opens_connection(&self) -> bool {
        self.is_syn && !self.is_ack && !self.is_fin && !self.is_rst
    }

    fn next_sequence(&self) -> u32 {
        self.sequence
            .wrapping_add(self.payload.len() as u32)
            .wrapping_add(u32::from(self.is_syn))
            .wrapping_add(u32::from(self.is_fin))
    }
}

pub fn parse_tcp4(packet: &[u8]) -> Option<TcpInfo<'_>> {
    let (header_len, total_len) = ipv4_bounds(packet, PROTO_TCP)?;
    let tcp = packet.get(header_len..total_len)?;
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_header_len < TCP_HEADER_LEN || tcp_header_len > tcp.len() {
        return None;
    }
    let src_ip = packet[12..16].try_into().ok()?;
    let dst_ip = packet[16..20].try_into().ok()?;
    if checksum_with_carry(
        tcp,
        transport_pseudo_header_sum(src_ip, dst_ip, PROTO_TCP, tcp.len() as u16),
    ) != 0
    {
        return None;
    }
    let options = tcp_options(&tcp[..tcp_header_len]).ok()?;
    Some(TcpInfo {
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        src_ip,
        dst_ip,
        sequence: u32::from_be_bytes(tcp[4..8].try_into().ok()?),
        acknowledgement: u32::from_be_bytes(tcp[8..12].try_into().ok()?),
        window: u16::from_be_bytes(tcp[14..16].try_into().ok()?),
        is_syn: tcp[13] & TCP_FLAG_SYN != 0,
        is_fin: tcp[13] & TCP_FLAG_FIN != 0,
        is_rst: tcp[13] & TCP_FLAG_RST != 0,
        is_ack: tcp[13] & TCP_FLAG_ACK != 0,
        mss: options.mss,
        window_scale: options.window_scale,
        payload: &tcp[tcp_header_len..],
    })
}

#[derive(Default)]
struct TcpOptions {
    mss: Option<u16>,
    window_scale: Option<u8>,
}

fn tcp_mss(tcp_header: &[u8]) -> Result<Option<u16>, ()> {
    Ok(tcp_options(tcp_header)?.mss)
}

fn tcp_options(tcp_header: &[u8]) -> Result<TcpOptions, ()> {
    let mut index = TCP_HEADER_LEN;
    let mut options = TcpOptions::default();
    while index < tcp_header.len() {
        match tcp_header[index] {
            OPTION_END => break,
            OPTION_NOP => index += 1,
            kind => {
                let len = usize::from(*tcp_header.get(index + 1).ok_or(())?);
                if len < 2 || index + len > tcp_header.len() {
                    return Err(());
                }
                if kind == OPTION_MSS && len == 4 && options.mss.is_none() {
                    options.mss = Some(u16::from_be_bytes([
                        tcp_header[index + 2],
                        tcp_header[index + 3],
                    ]));
                } else if kind == OPTION_WINDOW_SCALE && len == 3 && options.window_scale.is_none()
                {
                    options.window_scale = Some(tcp_header[index + 2].min(14));
                }
                index += len;
            }
        }
    }
    Ok(options)
}

/// RFC 1624 incremental checksum update: `HC' = ~(~HC + ~m + m')`.
///
/// Recomputing a TCP checksum from scratch means a pass over the whole segment.
/// Only a few header words change during translation, and updating for just
/// those is both cheaper and exactly what the RFC prescribes.
fn adjust_checksum(old_sum: u16, old: &[u8], new: &[u8]) -> u16 {
    let mut acc = (!old_sum) as u32;
    for word in old.chunks_exact(2) {
        acc += (!u16::from_be_bytes([word[0], word[1]])) as u32;
    }
    for word in new.chunks_exact(2) {
        acc += u16::from_be_bytes([word[0], word[1]]) as u32;
    }
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

fn rewrite_ip_checksum(ip: &mut [u8]) {
    ip[10..12].fill(0);
    let sum = checksum(ip);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
}

fn forwardable_ipv4_header_len(packet: &[u8]) -> Option<usize> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(packet[0] & 0x0f) * 4;
    if header_len < IPV4_HEADER_LEN
        || header_len > packet.len()
        || packet[8] <= 1
        || checksum(&packet[..header_len]) != 0
    {
        return None;
    }
    Some(header_len)
}

/// Whether an IPv4 packet has a valid header and can cross another routed hop.
pub fn ipv4_ttl_is_forwardable(packet: &[u8]) -> bool {
    forwardable_ipv4_header_len(packet).is_some()
}

/// Decrement an IPv4 packet's hop limit and repair its header checksum.
///
/// Returns `false` for malformed packets and packets that expire at this hop.
pub fn decrement_ipv4_ttl(packet: &mut [u8]) -> bool {
    let Some(header_len) = forwardable_ipv4_header_len(packet) else {
        return false;
    };
    packet[8] -= 1;
    rewrite_ip_checksum(&mut packet[..header_len]);
    true
}

/// Translate a segment leaving the tunnel: it must appear to come from this
/// gateway's own address and its allocated external port.
pub fn rewrite_tcp_outbound(packet: &mut [u8], new_src_ip: [u8; 4], new_src_port: u16) -> bool {
    let Some(header_len) = tcp_offset(packet) else {
        return false;
    };
    let (ip, tcp) = packet.split_at_mut(header_len);

    let old_sum = u16::from_be_bytes([tcp[16], tcp[17]]);
    // The TCP checksum covers a pseudo-header containing the IP addresses, so
    // changing the address invalidates it just as changing the port does.
    let sum = adjust_checksum(old_sum, &ip[12..16], &new_src_ip);
    let sum = adjust_checksum(sum, &tcp[0..2], &new_src_port.to_be_bytes());
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    tcp[0..2].copy_from_slice(&new_src_port.to_be_bytes());
    ip[12..16].copy_from_slice(&new_src_ip);
    rewrite_ip_checksum(ip);
    true
}

/// Translate a segment arriving for a known flow back to its tunnel client.
pub fn rewrite_tcp_inbound(packet: &mut [u8], new_dst_ip: [u8; 4], new_dst_port: u16) -> bool {
    let Some(header_len) = tcp_offset(packet) else {
        return false;
    };
    let (ip, tcp) = packet.split_at_mut(header_len);

    let old_sum = u16::from_be_bytes([tcp[16], tcp[17]]);
    let sum = adjust_checksum(old_sum, &ip[16..20], &new_dst_ip);
    let sum = adjust_checksum(sum, &tcp[2..4], &new_dst_port.to_be_bytes());
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    tcp[2..4].copy_from_slice(&new_dst_port.to_be_bytes());
    ip[16..20].copy_from_slice(&new_dst_ip);
    rewrite_ip_checksum(ip);
    true
}

/// Reduce the MSS option of a SYN to at most [`MAX_MSS`].
///
/// Both directions need this: the client's SYN tells the server how large a
/// segment it may send, and the server's SYN-ACK does the same in reverse.
pub fn clamp_mss(packet: &mut [u8]) {
    let Some((header_len, total_len)) = ipv4_bounds(packet, PROTO_TCP) else {
        return;
    };
    let tcp = &mut packet[header_len..total_len];
    if tcp.len() < TCP_HEADER_LEN {
        return;
    }
    if tcp[13] & TCP_FLAG_SYN == 0 {
        return;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset <= TCP_HEADER_LEN || data_offset > tcp.len() {
        return;
    }
    // Validate the complete option list before mutating an early valid MSS.
    if tcp_mss(&tcp[..data_offset]).is_err() {
        return;
    }

    let mut i = TCP_HEADER_LEN;
    while i < data_offset {
        match tcp[i] {
            OPTION_END => break,
            OPTION_NOP => i += 1,
            kind => {
                if i + 1 >= data_offset {
                    break;
                }
                let len = tcp[i + 1] as usize;
                if len < 2 || i + len > data_offset {
                    break;
                }
                if kind == OPTION_MSS && len == 4 {
                    let mss = u16::from_be_bytes([tcp[i + 2], tcp[i + 3]]);
                    if mss > MAX_MSS {
                        let old = [tcp[i + 2], tcp[i + 3]];
                        let new = MAX_MSS.to_be_bytes();
                        let sum = u16::from_be_bytes([tcp[16], tcp[17]]);
                        let sum = adjust_checksum(sum, &old, &new);
                        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
                        tcp[i + 2..i + 4].copy_from_slice(&new);
                    }
                    return;
                }
                i += len;
            }
        }
    }
}

/// Cap the advertised TCP receive window and disable window scaling.
///
/// The gateway has fixed packet arenas rather than an elastic receive queue,
/// so forwarding a larger advertised window can let a peer send more data than
/// the corresponding arena can retain. Window Scale is negotiated only on SYN
/// and SYN-ACK packets; normalizing it to zero keeps every later 16-bit window
/// in literal bytes. A genuine zero window remains zero.
///
/// Malformed packets and malformed option lists are left untouched.
pub fn clamp_tcp_receive_window(packet: &mut [u8], max_window: u16) {
    clamp_tcp_receive_window_scaled(packet, max_window, 0);
}

/// Normalize a scaled receive window to literal bytes, then cap it.
///
/// `window_scale` is the value this endpoint originally announced before the
/// gateway normalized its SYN option to zero. SYN windows themselves are
/// never scaled. Genuine zero windows remain zero.
pub fn clamp_tcp_receive_window_scaled(packet: &mut [u8], max_window: u16, window_scale: u8) {
    let Some((header_len, total_len)) = ipv4_bounds(packet, PROTO_TCP) else {
        return;
    };
    let tcp = &mut packet[header_len..total_len];
    if tcp.len() < TCP_HEADER_LEN {
        return;
    }
    let data_offset = usize::from(tcp[12] >> 4) * 4;
    if data_offset < TCP_HEADER_LEN
        || data_offset > tcp.len()
        || tcp_mss(&tcp[..data_offset]).is_err()
    {
        return;
    }

    let old_window = u16::from_be_bytes([tcp[14], tcp[15]]);
    let is_syn = tcp[13] & TCP_FLAG_SYN != 0;
    let new_window = if old_window == 0 || is_syn {
        old_window.min(max_window)
    } else {
        let effective = u32::from(old_window) << window_scale.min(14);
        effective.min(u32::from(max_window)) as u16
    };
    if new_window != old_window {
        let new_window = new_window.to_be_bytes();
        let sum = u16::from_be_bytes([tcp[16], tcp[17]]);
        let sum = adjust_checksum(sum, &tcp[14..16], &new_window);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        tcp[14..16].copy_from_slice(&new_window);
    }

    if !is_syn {
        return;
    }
    let mut index = TCP_HEADER_LEN;
    while index < data_offset {
        match tcp[index] {
            OPTION_END => break,
            OPTION_NOP => index += 1,
            kind => {
                // tcp_mss validated the complete list above.
                let len = usize::from(tcp[index + 1]);
                if kind == OPTION_WINDOW_SCALE && len == 3 && tcp[index + 2] != 0 {
                    let scale_index = index + 2;
                    let word_index = scale_index & !1;
                    let old = [tcp[word_index], tcp[word_index + 1]];
                    let mut new = old;
                    new[scale_index - word_index] = 0;
                    let sum = u16::from_be_bytes([tcp[16], tcp[17]]);
                    let sum = adjust_checksum(sum, &old, &new);
                    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
                    tcp[scale_index] = 0;
                }
                index += len;
            }
        }
    }
}

fn tcp_offset(packet: &[u8]) -> Option<usize> {
    let (header_len, total_len) = ipv4_bounds(packet, PROTO_TCP)?;
    if total_len < header_len + TCP_HEADER_LEN {
        return None;
    }
    Some(header_len)
}

fn ipv4_bounds(packet: &[u8], protocol: u8) -> Option<(usize, usize)> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != protocol {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if header_len < IPV4_HEADER_LEN || header_len > packet.len() {
        return None;
    }
    if checksum(&packet[..header_len]) != 0 {
        return None;
    }
    // NAT cannot safely translate a transport header split across fragments.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }
    let total_len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total_len < header_len || total_len > packet.len() {
        return None;
    }
    Some((header_len, total_len))
}

/// A parsed inner IPv4/UDP datagram.
pub struct Udp4<'a> {
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Parse an inner packet, if it is IPv4 UDP without fragmentation.
///
/// Fragments are rejected rather than reassembled: the tunnel's 1280-byte MTU
/// is small enough that a well-behaved client will not produce them, and
/// reassembly needs buffers this device would rather spend on throughput.
pub fn parse_udp4(packet: &[u8]) -> Option<Udp4<'_>> {
    let (header_len, total_len) = ipv4_bounds(packet, PROTO_UDP)?;
    let udp = packet.get(header_len..total_len)?;
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if length != udp.len() || length < UDP_HEADER_LEN {
        return None;
    }
    let src_ip = packet[12..16].try_into().ok()?;
    let dst_ip = packet[16..20].try_into().ok()?;
    // IPv4 permits an omitted UDP checksum (encoded as zero), but every
    // nonzero checksum must cover the complete datagram and pseudo-header.
    let udp_checksum = u16::from_be_bytes([udp[6], udp[7]]);
    if udp_checksum != 0
        && checksum_with_carry(
            udp,
            transport_pseudo_header_sum(src_ip, dst_ip, PROTO_UDP, length as u16),
        ) != 0
    {
        return None;
    }

    Some(Udp4 {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
        payload: &udp[UDP_HEADER_LEN..length],
    })
}

/// Build an inner IPv4/UDP datagram into `out`, returning its length.
pub fn build_udp4(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    let out = out.get_mut(..total)?;

    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    // A zero identification field is fine precisely because we never fragment.
    out[4..6].fill(0);
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // don't fragment
    out[8] = 64;
    out[9] = PROTO_UDP;
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&src_ip);
    out[16..20].copy_from_slice(&dst_ip);
    let ip_checksum = checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    let udp = &mut out[IPV4_HEADER_LEN..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].fill(0);
    udp[UDP_HEADER_LEN..].copy_from_slice(payload);

    // UDP's checksum covers a pseudo-header of the IP addresses, protocol and
    // length as well as the datagram itself.
    let pseudo = transport_pseudo_header_sum(src_ip, dst_ip, PROTO_UDP, udp_len);
    let sum = checksum_with_carry(udp, pseudo);
    // All-zero means "no checksum" in IPv4, so a genuine zero is sent as ~0.
    let sum = if sum == 0 { 0xffff } else { sum };
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&sum.to_be_bytes());

    Some(total)
}

/// Prepend an IPv4/UDP header to a payload already at the start of `packet`.
///
/// This is the single-buffer counterpart to [`build_udp4`]: callers provide
/// the payload length, and the payload is shifted forward without allocating
/// a second full-MTU scratch buffer.
pub fn build_udp4_in_place(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    payload_len: usize,
    packet: &mut [u8],
) -> Option<usize> {
    let total = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload_len;
    let packet = packet.get_mut(..total)?;
    packet.copy_within(0..payload_len, IPV4_HEADER_LEN + UDP_HEADER_LEN);

    packet[0] = 0x45;
    packet[1] = 0;
    packet[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    packet[4..6].fill(0);
    packet[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = PROTO_UDP;
    packet[10..12].fill(0);
    packet[12..16].copy_from_slice(&src_ip);
    packet[16..20].copy_from_slice(&dst_ip);
    let ip_checksum = checksum(&packet[..IPV4_HEADER_LEN]);
    packet[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp_len = (UDP_HEADER_LEN + payload_len) as u16;
    let udp = &mut packet[IPV4_HEADER_LEN..];
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&udp_len.to_be_bytes());
    udp[6..8].fill(0);
    let pseudo = transport_pseudo_header_sum(src_ip, dst_ip, PROTO_UDP, udp_len);
    let sum = checksum_with_carry(udp, pseudo);
    let sum = if sum == 0 { 0xffff } else { sum };
    packet[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&sum.to_be_bytes());

    Some(total)
}

/// Build a minimal IPv4/TCP segment. The peer API uses this to terminate its
/// small HTTP connections without depending on an operating-system TCP stack.
#[allow(clippy::too_many_arguments)]
pub fn build_tcp4(
    src_ip: [u8; 4],
    src_port: u16,
    dst_ip: [u8; 4],
    dst_port: u16,
    sequence: u32,
    acknowledgement: u32,
    flags: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Option<usize> {
    let total = IPV4_HEADER_LEN + TCP_HEADER_LEN + payload.len();
    let out = out.get_mut(..total)?;

    out[0] = 0x45;
    out[1] = 0;
    out[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    out[4..6].fill(0);
    out[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
    out[8] = 64;
    out[9] = PROTO_TCP;
    out[10..12].fill(0);
    out[12..16].copy_from_slice(&src_ip);
    out[16..20].copy_from_slice(&dst_ip);
    let ip_sum = checksum(&out[..IPV4_HEADER_LEN]);
    out[10..12].copy_from_slice(&ip_sum.to_be_bytes());

    let tcp = &mut out[IPV4_HEADER_LEN..];
    tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
    tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    tcp[4..8].copy_from_slice(&sequence.to_be_bytes());
    tcp[8..12].copy_from_slice(&acknowledgement.to_be_bytes());
    tcp[12] = 5 << 4;
    tcp[13] = flags;
    tcp[14..16].copy_from_slice(&4096u16.to_be_bytes());
    tcp[16..18].fill(0);
    tcp[18..20].fill(0);
    tcp[TCP_HEADER_LEN..].copy_from_slice(payload);
    let tcp_len = (TCP_HEADER_LEN + payload.len()) as u16;
    let pseudo = transport_pseudo_header_sum(src_ip, dst_ip, PROTO_TCP, tcp_len);
    let sum = checksum_with_carry(tcp, pseudo);
    tcp[16..18].copy_from_slice(&sum.to_be_bytes());
    Some(total)
}

fn transport_pseudo_header_sum(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    protocol: u8,
    transport_len: u16,
) -> u32 {
    let mut sum = 0u32;
    for pair in src_ip.chunks_exact(2).chain(dst_ip.chunks_exact(2)) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    sum + protocol as u32 + transport_len as u32
}

/// The internet checksum of `bytes`, folded together with an existing partial
/// sum such as a pseudo-header.
fn checksum_with_carry(bytes: &[u8], mut sum: u32) -> u16 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    if let [last] = chunks.remainder() {
        sum += (*last as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tcp_option_tests {
    use super::*;

    #[test]
    fn reads_an_mss_option_from_a_syn_header() {
        let mut header = [0u8; TCP_HEADER_LEN + 4];
        header[TCP_HEADER_LEN..].copy_from_slice(&[OPTION_MSS, 4, 0x01, 0x00]);
        assert_eq!(tcp_mss(&header), Ok(Some(256)));
    }
}
