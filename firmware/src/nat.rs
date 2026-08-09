//! Source NAT for UDP flows leaving the tunnel for the WiFi uplink.
//!
//! This is milestone M3a, scoped to UDP. The plan anticipated that: smoltcp has
//! no forwarding path, so a general implementation needs either raw sockets
//! (where smoltcp is liable to answer forwarded TCP with its own RST) or a
//! `Driver` shim that diverts frames before smoltcp sees them. Neither is
//! needed for UDP.
//!
//! Instead each tunnelled flow gets an ordinary [`embassy_net::udp::UdpSocket`]
//! on the station interface. The stack then builds the outer IP and UDP headers
//! itself, using its own address, which *is* source NAT — and it means no
//! checksum fixup, no raw sockets, and no fighting smoltcp. Replies arrive on
//! the same socket and are rebuilt into inner packets addressed back to the
//! tunnel client.
//!
//! The cost is one socket per concurrent flow, so the table is small and
//! reclaims the least recently used slot under pressure.

use crate::inner::checksum;

/// Concurrent UDP flows. Each costs a socket plus its buffers, so this trades
/// directly against RAM; four is enough to forward DNS and a benchmark at once.
pub const SLOTS: usize = 4;

/// External ports are assigned one per slot, so a reply's destination port
/// identifies its flow before the table is consulted.
pub const EXT_PORT_BASE: u16 = 40000;

/// Drop a flow that has been idle this long, freeing its slot.
pub const IDLE_TIMEOUT_MS: u64 = 30_000;

const PROTO_UDP: u8 = 17;
const IPV4_HEADER_LEN: usize = 20;
const UDP_HEADER_LEN: usize = 8;

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
            if let Some(flow) = &mut self.flows[index] {
                flow.last_used_ms = now_ms;
            }
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

        self.flows[victim] = Some(Flow {
            client_ip,
            client_port,
            server_ip,
            server_port,
            last_used_ms: now_ms,
        });
        Some(victim)
    }

    pub fn get(&self, slot: usize) -> Option<Flow> {
        self.flows.get(slot).copied().flatten()
    }

    pub fn touch(&mut self, slot: usize, now_ms: u64) {
        if let Some(Some(flow)) = self.flows.get_mut(slot) {
            flow.last_used_ms = now_ms;
        }
    }
}

/// Concurrent TCP flows. These cost only a table entry — the packets are
/// forwarded through one shared raw socket rather than a socket each — so the
/// table can be considerably larger than the UDP one. A single page load opens
/// several connections at once.
pub const TCP_SLOTS: usize = 16;

/// External ports for translated TCP, one per slot, so a segment's destination
/// port identifies its flow.
pub const TCP_EXT_PORT_BASE: u16 = 41000;

/// Idle timeout for a TCP flow. Longer than UDP's because a connection may sit
/// silent between requests and still be very much alive.
pub const TCP_IDLE_TIMEOUT_MS: u64 = 120_000;

/// The largest MSS we let either end negotiate.
///
/// A segment that arrives larger than the tunnel's MTU cannot be encapsulated
/// and is simply dropped, which presents as a connection that opens and then
/// hangs the moment it carries real data. Clamping the option in the SYN stops
/// that at the source instead.
pub const MAX_MSS: u16 = (wirefeather::budget::INNER_MTU - IPV4_HEADER_LEN - TCP_HEADER_LEN) as u16;

const PROTO_TCP: u8 = 6;
const TCP_HEADER_LEN: usize = 20;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_RST: u8 = 0x04;
const OPTION_END: u8 = 0;
const OPTION_NOP: u8 = 1;
const OPTION_MSS: u8 = 2;

#[derive(Default)]
pub struct TcpTable {
    flows: [Option<Flow>; TCP_SLOTS],
}

impl TcpTable {
    pub const fn new() -> Self {
        Self {
            flows: [None; TCP_SLOTS],
        }
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
            if let Some(flow) = &mut self.flows[index] {
                flow.last_used_ms = now_ms;
            }
            return Some(index);
        }

        let victim = self.flows.iter().position(Option::is_none).or_else(|| {
            self.flows
                .iter()
                .enumerate()
                .filter(|(_, f)| {
                    f.is_some_and(|f| now_ms.saturating_sub(f.last_used_ms) >= TCP_IDLE_TIMEOUT_MS)
                })
                .min_by_key(|(_, f)| f.map(|f| f.last_used_ms).unwrap_or(0))
                .map(|(i, _)| i)
        })?;

        self.flows[victim] = Some(Flow {
            client_ip,
            client_port,
            server_ip,
            server_port,
            last_used_ms: now_ms,
        });
        Some(victim)
    }

    pub fn get(&self, slot: usize) -> Option<Flow> {
        self.flows.get(slot).copied().flatten()
    }

    pub fn touch(&mut self, slot: usize, now_ms: u64) {
        if let Some(Some(flow)) = self.flows.get_mut(slot) {
            flow.last_used_ms = now_ms;
        }
    }

    /// Release a slot whose connection has been reset, so it is available again
    /// without waiting out the idle timeout.
    pub fn release(&mut self, slot: usize) {
        if let Some(entry) = self.flows.get_mut(slot) {
            *entry = None;
        }
    }
}

/// Source and destination ports of an inner TCP segment, plus its flags.
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub src_ip: [u8; 4],
    pub dst_ip: [u8; 4],
    pub is_rst: bool,
}

pub fn parse_tcp4(packet: &[u8]) -> Option<TcpInfo> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != PROTO_TCP {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    let tcp = packet.get(header_len..)?;
    if tcp.len() < TCP_HEADER_LEN {
        return None;
    }
    Some(TcpInfo {
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        src_ip: packet[12..16].try_into().ok()?,
        dst_ip: packet[16..20].try_into().ok()?,
        is_rst: tcp[13] & TCP_FLAG_RST != 0,
    })
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
    let sum = checksum(&ip[..IPV4_HEADER_LEN]);
    ip[10..12].copy_from_slice(&sum.to_be_bytes());
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
    let Some(header_len) = tcp_offset(packet) else {
        return;
    };
    let tcp = &mut packet[header_len..];
    if tcp[13] & TCP_FLAG_SYN == 0 {
        return;
    }
    let data_offset = ((tcp[12] >> 4) as usize) * 4;
    if data_offset <= TCP_HEADER_LEN || data_offset > tcp.len() {
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

fn tcp_offset(packet: &[u8]) -> Option<usize> {
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != PROTO_TCP {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    if packet.len() < header_len + TCP_HEADER_LEN {
        return None;
    }
    Some(header_len)
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
    if packet.len() < IPV4_HEADER_LEN || packet[0] >> 4 != 4 || packet[9] != PROTO_UDP {
        return None;
    }
    let header_len = ((packet[0] & 0x0f) as usize) * 4;
    // The fragment-offset field and the "more fragments" bit must both be zero.
    if u16::from_be_bytes([packet[6], packet[7]]) & 0x3fff != 0 {
        return None;
    }

    let udp = packet.get(header_len..)?;
    if udp.len() < UDP_HEADER_LEN {
        return None;
    }
    let length = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if !(UDP_HEADER_LEN..=udp.len()).contains(&length) {
        return None;
    }

    Some(Udp4 {
        src_ip: packet[12..16].try_into().ok()?,
        dst_ip: packet[16..20].try_into().ok()?,
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
    let pseudo = pseudo_header_sum(src_ip, dst_ip, udp_len);
    let sum = checksum_with_carry(udp, pseudo);
    // All-zero means "no checksum" in IPv4, so a genuine zero is sent as ~0.
    let sum = if sum == 0 { 0xffff } else { sum };
    out[IPV4_HEADER_LEN + 6..IPV4_HEADER_LEN + 8].copy_from_slice(&sum.to_be_bytes());

    Some(total)
}

fn pseudo_header_sum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_len: u16) -> u32 {
    let mut sum = 0u32;
    for pair in src_ip.chunks_exact(2).chain(dst_ip.chunks_exact(2)) {
        sum += u16::from_be_bytes([pair[0], pair[1]]) as u32;
    }
    sum + PROTO_UDP as u32 + udp_len as u32
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
