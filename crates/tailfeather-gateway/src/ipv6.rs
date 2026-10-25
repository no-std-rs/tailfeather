//! Bounded IPv6 exit routing and endpoint-dependent source translation.
//!
//! UDP, TCP and ICMPv6 echo share a fixed mapping table. Extension headers,
//! fragments and jumbograms are rejected before creating state: this gateway
//! never reassembles packets or guesses where a transport header starts.
//! Error messages quote the original packet and are bounded to IPv6's minimum
//! MTU, following RFC 8200 and RFC 4443.

use core::net::Ipv6Addr;
use core::num::NonZeroU16;

pub const HEADER: usize = 40;
pub const MTU: usize = 1280;
pub const SLOTS: usize = 32;
const PORT_BASE: u16 = 45_000;
const IDLE_MS: u64 = 120_000;
const TCP_CLOSED_GRACE_MS: u64 = 2_000;
const TCP_PORT_REUSE_MS: u64 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    Malformed,
    Unsupported,
    SpoofedSource,
    IsolatedDestination,
    ExpiredHopLimit,
    PacketTooBig,
    Capacity,
    Unsolicited,
}

#[derive(Clone, Copy, Debug)]
pub struct Packet<'a> {
    pub source: Ipv6Addr,
    pub destination: Ipv6Addr,
    pub protocol: u8,
    pub hop_limit: u8,
    pub source_port: u16,
    pub destination_port: u16,
    pub bytes: &'a [u8],
}

impl<'a> Packet<'a> {
    pub fn parse(bytes: &'a [u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER || bytes[0] >> 4 != 6 {
            return Err(Error::Malformed);
        }
        let len = HEADER + usize::from(u16::from_be_bytes([bytes[4], bytes[5]]));
        if len != bytes.len() {
            return Err(Error::Malformed);
        }
        let source = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[8..24]).unwrap());
        let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&bytes[24..40]).unwrap());
        let protocol = bytes[6];
        let body = &bytes[HEADER..];
        let (source_port, destination_port) = match protocol {
            6 if body.len() >= 20 => {
                let header = usize::from(body[12] >> 4) * 4;
                if header < 20 || header > body.len() {
                    return Err(Error::Malformed);
                }
                (
                    u16::from_be_bytes([body[0], body[1]]),
                    u16::from_be_bytes([body[2], body[3]]),
                )
            }
            17 if body.len() >= 8 => {
                if usize::from(u16::from_be_bytes([body[4], body[5]])) != body.len()
                    || body[6..8] == [0, 0]
                {
                    return Err(Error::Malformed);
                }
                (
                    u16::from_be_bytes([body[0], body[1]]),
                    u16::from_be_bytes([body[2], body[3]]),
                )
            }
            58 if body.len() >= 8 => {
                if matches!(body[0], 128 | 129) && body[1] == 0 {
                    (u16::from_be_bytes([body[4], body[5]]), 0)
                } else if body[0] < 128 {
                    (0, 0)
                } else {
                    return Err(Error::Unsupported);
                }
            }
            6 | 17 | 58 => return Err(Error::Malformed),
            _ => return Err(Error::Unsupported),
        };
        if transport_checksum(source, destination, protocol, body) != 0 {
            return Err(Error::Malformed);
        }
        Ok(Self {
            source,
            destination,
            protocol,
            hop_limit: bytes[7],
            source_port,
            destination_port,
            bytes,
        })
    }
}

fn sum(bytes: &[u8], mut total: u32) -> u32 {
    let mut pairs = bytes.chunks_exact(2);
    for pair in &mut pairs {
        total += u32::from(u16::from_be_bytes([pair[0], pair[1]]));
    }
    if let Some(byte) = pairs.remainder().first() {
        total += u32::from(*byte) << 8;
    }
    total
}

pub fn transport_checksum(
    source: Ipv6Addr,
    destination: Ipv6Addr,
    protocol: u8,
    body: &[u8],
) -> u16 {
    let mut total = sum(&source.octets(), 0);
    total = sum(&destination.octets(), total);
    total = sum(&(body.len() as u32).to_be_bytes(), total);
    total += u32::from(protocol);
    total = sum(body, total);
    while total >> 16 != 0 {
        total = (total & 0xffff) + (total >> 16);
    }
    !(total as u16)
}

fn update_checksum(packet: &mut [u8]) {
    let source = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).unwrap());
    let destination = Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).unwrap());
    let offset = match packet[6] {
        6 => 16,
        17 => 6,
        58 => 2,
        _ => return,
    };
    packet[HEADER + offset..HEADER + offset + 2].fill(0);
    let mut checksum = transport_checksum(source, destination, packet[6], &packet[HEADER..]);
    if packet[6] == 17 && checksum == 0 {
        checksum = u16::MAX;
    }
    packet[HEADER + offset..HEADER + offset + 2].copy_from_slice(&checksum.to_be_bytes());
}

/// Unicast routable destinations only; neither IPv4-mapped addresses nor
/// link-local/loopback/multicast traffic crosses the tunnel boundary.
pub fn routable(address: Ipv6Addr) -> bool {
    let octets = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || (octets[0] == 0xfe && octets[1] & 0xc0 == 0x80)
        || address.to_ipv4_mapped().is_some())
}

#[derive(Clone, Copy)]
struct Flow {
    client: Ipv6Addr,
    server: Ipv6Addr,
    client_port: u16,
    server_port: u16,
    protocol: u8,
    // The fixed 45000..=65000 range supplies Option<Flow>'s empty niche, so
    // exact TCP sequence state costs no additional table space.
    external_port: NonZeroU16,
    touched: u64,
    client_next: u32,
    server_next: u32,
    tcp_state: u8,
}

const CLIENT_SEQUENCE: u8 = 1;
const SERVER_SEQUENCE: u8 = 2;
const CLIENT_FIN: u8 = 4;
const SERVER_FIN: u8 = 8;

#[derive(Clone, Copy)]
struct Tcp {
    sequence: u32,
    acknowledgement: u32,
    next: u32,
    flags: u8,
}

impl Tcp {
    fn parse(packet: &[u8]) -> Self {
        let sequence = u32::from_be_bytes(packet[44..48].try_into().unwrap());
        let acknowledgement = u32::from_be_bytes(packet[48..52].try_into().unwrap());
        let flags = packet[53];
        let payload = packet.len() - HEADER - usize::from(packet[52] >> 4) * 4;
        let next = sequence
            .wrapping_add(payload as u32)
            .wrapping_add(u32::from(flags & 2 != 0))
            .wrapping_add(u32::from(flags & 1 != 0));
        Self {
            sequence,
            acknowledgement,
            next,
            flags,
        }
    }
    fn opens(self) -> bool {
        self.flags & 0x17 == 2
    }
}

impl Flow {
    fn closed(self) -> bool {
        self.protocol == 6
            && self.tcp_state & (CLIENT_FIN | SERVER_FIN) == (CLIENT_FIN | SERVER_FIN)
    }
    fn live(self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.touched)
            < if self.closed() {
                TCP_CLOSED_GRACE_MS
            } else {
                IDLE_MS
            }
    }
    /// Mirror IPv4's strict reset and in-order FIN checks. Invalid sequence
    /// flags can still reach the endpoint, but never tear down NAT authority.
    fn observe_tcp(&mut self, packet: Tcp, outbound: bool) -> bool {
        if outbound
            && packet.opens()
            && self.tcp_state & CLIENT_SEQUENCE != 0
            && self.client_next != packet.next
        {
            self.tcp_state = 0;
        }
        let (own_bit, peer_bit, fin_bit, own, peer) = if outbound {
            (
                CLIENT_SEQUENCE,
                SERVER_SEQUENCE,
                CLIENT_FIN,
                &mut self.client_next,
                self.server_next,
            )
        } else {
            (
                SERVER_SEQUENCE,
                CLIENT_SEQUENCE,
                SERVER_FIN,
                &mut self.server_next,
                self.client_next,
            )
        };
        let own_known = self.tcp_state & own_bit != 0;
        let peer_known = self.tcp_state & peer_bit != 0;
        if packet.flags & 4 != 0 {
            return if own_known {
                packet.sequence == *own
            } else {
                packet.flags & 0x10 != 0 && peer_known && packet.acknowledgement == peer
            };
        }
        let sequence_valid = if own_known {
            packet.sequence == *own
        } else {
            outbound || packet.flags & 0x10 == 0 || (peer_known && packet.acknowledgement == peer)
        };
        if sequence_valid {
            *own = packet.next;
            self.tcp_state |= own_bit;
            if packet.flags & 1 != 0 {
                self.tcp_state |= fin_bit;
            }
        }
        false
    }
}

/// One translated outbound packet, not yet admitted to a network queue.
/// Dropping this token discards the candidate without allocating, touching or
/// closing any mapping or advancing the port-generation cursor.
#[must_use = "commit the prepared mapping only after successful packet enqueue"]
pub struct Prepared<'a> {
    gateway: &'a mut Gateway,
    flow: Flow,
    uplink: Ipv6Addr,
    slot: u8,
    next_port: u16,
    refresh: bool,
    retire: bool,
}

impl Prepared<'_> {
    pub fn destination(&self) -> Ipv6Addr {
        self.flow.server
    }
    /// Commit only after the caller has successfully enqueued the packet.
    pub fn commit(mut self, now_ms: u64) {
        // Publish the ordinary cursor before recording any release. A release
        // of an older-cycle port may replace it with wrap-pending quarantine.
        self.gateway.next_port = self.next_port;
        self.gateway.address(self.uplink, now_ms);
        let previous = self.gateway.flows[usize::from(self.slot)];
        if let Some(old) = previous
            && old.protocol == 6
            && old.external_port != self.flow.external_port
        {
            self.gateway.release_tcp(old.external_port, now_ms);
        }
        let first_close = self.flow.closed() && previous.is_some_and(|old| !old.closed());
        if first_close || (self.flow.protocol == 6 && self.retire) {
            self.gateway.release_tcp(self.flow.external_port, now_ms);
        }
        if self.refresh {
            self.flow.touched = now_ms;
        }
        self.gateway.flows[usize::from(self.slot)] =
            if self.retire { None } else { Some(self.flow) };
    }
}

pub struct Gateway {
    flows: [Option<Flow>; SLOTS],
    uplink: Option<Ipv6Addr>,
    next_port: u16,
    // One conservative quarantine protects all wrapped TCP tuples without
    // unbounded per-port state. The deadline starts at release, never open.
    last_tcp_release_ms: Option<u64>,
    last_error_ms: Option<u64>,
}

impl Default for Gateway {
    fn default() -> Self {
        Self::new()
    }
}

impl Gateway {
    pub const fn new() -> Self {
        Self {
            flows: [None; SLOTS],
            uplink: None,
            next_port: PORT_BASE,
            last_tcp_release_ms: None,
            last_error_ms: None,
        }
    }

    /// Forget mappings when the runtime observes a change in authenticated
    /// address ownership. Retain generation and release history so delayed
    /// replies cannot attach to the replacement owner's first mapping.
    pub fn clear(&mut self, now_ms: u64) {
        for index in 0..SLOTS {
            if let Some(flow) = self.flows[index]
                && flow.protocol == 6
            {
                self.release_tcp(flow.external_port, now_ms);
            }
        }
        self.flows.fill(None);
    }

    fn release_tcp(&mut self, port: NonZeroU16, now_ms: u64) {
        self.last_tcp_release_ms = Some(now_ms);
        // In this cycle every newly allocated port is below the cursor. A
        // released port ahead of it survived a previous wrap: do not revisit
        // it in the current cycle before its remote TIME_WAIT has elapsed.
        if self.next_port != 0 && port.get() >= self.next_port {
            self.next_port = 0;
        }
    }

    /// A shared ten-errors/second bound covers tunnel and uplink failures.
    pub fn error_response(
        &mut self,
        original: &[u8],
        gateway: Ipv6Addr,
        kind: Error,
        now_ms: u64,
        out: &mut [u8],
    ) -> Option<usize> {
        if self
            .last_error_ms
            .is_some_and(|last| now_ms.saturating_sub(last) < 100)
        {
            return None;
        }
        let len = error_reply(original, gateway, kind, out)?;
        self.last_error_ms = Some(now_ms);
        Some(len)
    }

    fn address(&mut self, uplink: Ipv6Addr, now_ms: u64) {
        if self.uplink != Some(uplink) {
            self.clear(now_ms);
            self.uplink = Some(uplink);
        }
    }

    pub fn prepare_outbound(
        &mut self,
        packet: &mut [u8],
        authenticated_source: Ipv6Addr,
        uplink: Ipv6Addr,
        now_ms: u64,
    ) -> Result<Prepared<'_>, Error> {
        let parsed = Packet::parse(packet)?;
        if parsed.source != authenticated_source {
            return Err(Error::SpoofedSource);
        }
        if !routable(parsed.source) || !routable(parsed.destination) || parsed.destination == uplink
        {
            return Err(Error::IsolatedDestination);
        }
        if packet.len() > MTU {
            return Err(Error::PacketTooBig);
        }
        if parsed.hop_limit <= 1 {
            return Err(Error::ExpiredHopLimit);
        }
        if parsed.protocol == 58 && packet[HEADER] != 128 {
            return Err(Error::Unsupported);
        }
        let tcp = (parsed.protocol == 6).then(|| Tcp::parse(packet));
        let same_uplink = self.uplink == Some(uplink);
        let existing = same_uplink
            .then(|| {
                self.flows.iter().position(|entry| {
                    entry.is_some_and(|flow| {
                        flow.client == parsed.source
                            && flow.server == parsed.destination
                            && flow.client_port == parsed.source_port
                            && flow.server_port == parsed.destination_port
                            && flow.protocol == parsed.protocol
                            && flow.live(now_ms)
                    })
                })
            })
            .flatten();
        let reuse = existing
            .filter(|&slot| !self.flows[slot].unwrap().closed() || !tcp.is_some_and(Tcp::opens));
        let (slot, mut flow, next_port) =
            if let Some(slot) = reuse {
                (slot, self.flows[slot].unwrap(), self.next_port)
            } else {
                if tcp.is_some_and(|tcp| !tcp.opens()) {
                    return Err(Error::Unsolicited);
                }
                let slot = existing
                    .or_else(|| (!same_uplink).then_some(0))
                    .or_else(|| self.flows.iter().position(Option::is_none))
                    .or_else(|| {
                        self.flows.iter().position(|entry| {
                            entry.is_some_and(|flow| !flow.live(now_ms) || flow.closed())
                        })
                    })
                    .ok_or(Error::Capacity)?;
                let mut candidate = self.next_port;
                let (external_port, next_port) =
                    loop {
                        if candidate == 0 {
                            if self.last_tcp_release_ms.is_some_and(|released| {
                                now_ms.saturating_sub(released) < TCP_PORT_REUSE_MS
                            }) {
                                return Err(Error::Capacity);
                            }
                            candidate = PORT_BASE;
                        }
                        let next = if candidate == 65_000 {
                            0
                        } else {
                            candidate + 1
                        };
                        if self.flows.iter().all(|entry| {
                            entry.is_none_or(|flow| flow.external_port.get() != candidate)
                        }) {
                            break (NonZeroU16::new(candidate).unwrap(), next);
                        }
                        candidate = next;
                    };
                (
                    slot,
                    Flow {
                        client: parsed.source,
                        server: parsed.destination,
                        client_port: parsed.source_port,
                        server_port: parsed.destination_port,
                        protocol: parsed.protocol,
                        external_port,
                        touched: now_ms,
                        client_next: 0,
                        server_next: 0,
                        tcp_state: 0,
                    },
                    next_port,
                )
            };
        let refresh = !flow.closed();
        let retire = tcp.is_some_and(|tcp| flow.observe_tcp(tcp, true));
        let port_offset = if flow.protocol == 58 {
            HEADER + 4
        } else {
            HEADER
        };
        packet[8..24].copy_from_slice(&uplink.octets());
        packet[port_offset..port_offset + 2]
            .copy_from_slice(&flow.external_port.get().to_be_bytes());
        packet[7] -= 1;
        if flow.protocol == 6 {
            clamp_mss(packet);
        }
        update_checksum(packet);
        Ok(Prepared {
            gateway: self,
            flow,
            uplink,
            slot: slot as u8,
            next_port,
            refresh,
            retire,
        })
    }

    /// Return the authenticated client's tailnet address after reversing the
    /// complete remote tuple. Unsolicited packets cannot create mappings.
    pub fn inbound(
        &mut self,
        packet: &mut [u8],
        uplink: Ipv6Addr,
        now_ms: u64,
    ) -> Result<Ipv6Addr, Error> {
        self.address(uplink, now_ms);
        let parsed = Packet::parse(packet)?;
        if parsed.destination != uplink {
            return Err(Error::Unsolicited);
        }
        if parsed.protocol == 58 && packet[HEADER] < 128 {
            if parsed.hop_limit <= 1 || packet.len() > MTU {
                return Err(Error::Unsolicited);
            }
            return self.inbound_error(packet, uplink, now_ms);
        }
        if parsed.protocol == 58 && packet[HEADER] != 129 {
            return Err(Error::Unsolicited);
        }
        let external = if parsed.protocol == 58 {
            parsed.source_port
        } else {
            parsed.destination_port
        };
        let slot = self
            .flows
            .iter()
            .position(|entry| {
                entry.is_some_and(|flow| {
                    flow.server == parsed.source
                        && flow.protocol == parsed.protocol
                        && flow.external_port.get() == external
                        && (flow.protocol == 58 || flow.server_port == parsed.source_port)
                        && flow.live(now_ms)
                })
            })
            .ok_or(Error::Unsolicited)?;
        if parsed.hop_limit <= 1 {
            return Err(Error::ExpiredHopLimit);
        }
        if packet.len() > MTU {
            return Err(Error::PacketTooBig);
        }
        let mut flow = self.flows[slot].unwrap();
        let refresh = !flow.closed();
        let retire = flow.protocol == 6 && flow.observe_tcp(Tcp::parse(packet), false);
        if retire || (refresh && flow.closed()) {
            self.release_tcp(flow.external_port, now_ms);
        }
        if refresh {
            flow.touched = now_ms;
        }
        let client = flow.client;
        packet[24..40].copy_from_slice(&client.octets());
        let port_offset = if flow.protocol == 58 {
            HEADER + 4
        } else {
            HEADER + 2
        };
        packet[port_offset..port_offset + 2].copy_from_slice(&flow.client_port.to_be_bytes());
        packet[7] -= 1;
        update_checksum(packet);
        self.flows[slot] = if retire { None } else { Some(flow) };
        Ok(client)
    }

    fn inbound_error(
        &mut self,
        packet: &mut [u8],
        uplink: Ipv6Addr,
        now_ms: u64,
    ) -> Result<Ipv6Addr, Error> {
        if !matches!(packet[HEADER], 1..=4) || packet.len() < HEADER + 8 + HEADER + 8 {
            return Err(Error::Malformed);
        }
        let quoted = &packet[HEADER + 8..];
        // ICMP errors may truncate their quotation; inspect only the fixed
        // header and first eight transport bytes, never parse it as complete.
        if quoted[0] >> 4 != 6 || quoted[8..24] != uplink.octets() {
            return Err(Error::Unsolicited);
        }
        let server = Ipv6Addr::from(<[u8; 16]>::try_from(&quoted[24..40]).unwrap());
        let protocol = quoted[6];
        let payload_len = usize::from(u16::from_be_bytes([quoted[4], quoted[5]]));
        let minimum = match protocol {
            6 => 20,
            17 | 58 => 8,
            _ => return Err(Error::Unsupported),
        };
        if payload_len < minimum || quoted.len() > HEADER + payload_len {
            return Err(Error::Malformed);
        }
        if protocol == 17
            && (usize::from(u16::from_be_bytes([quoted[44], quoted[45]])) != payload_len
                || quoted[46..48] == [0, 0])
        {
            return Err(Error::Malformed);
        }
        if protocol == 58 && (quoted[40] != 128 || quoted[41] != 0) {
            return Err(Error::Malformed);
        }
        let offset = if protocol == 58 { HEADER + 4 } else { HEADER };
        let external = u16::from_be_bytes([quoted[offset], quoted[offset + 1]]);
        let server_port = if protocol == 58 {
            0
        } else {
            u16::from_be_bytes([quoted[HEADER + 2], quoted[HEADER + 3]])
        };
        let flow = self
            .flows
            .iter()
            .flatten()
            .find(|flow| {
                flow.server == server
                    && flow.server_port == server_port
                    && flow.protocol == protocol
                    && flow.external_port.get() == external
                    && flow.live(now_ms)
            })
            .ok_or(Error::Unsolicited)?;
        let client = flow.client;
        packet[24..40].copy_from_slice(&client.octets());
        let quoted = &mut packet[HEADER + 8..];
        // Restore the embedded checksum incrementally even when only its
        // prefix was quoted (TCP's checksum may not be present).
        let checksum_offset = match protocol {
            6 => HEADER + 16,
            17 => HEADER + 6,
            58 => HEADER + 2,
            _ => return Err(Error::Unsupported),
        };
        if quoted.len() >= checksum_offset + 2 {
            let mut checksum =
                !u16::from_be_bytes([quoted[checksum_offset], quoted[checksum_offset + 1]]) as u32;
            for (old, new) in uplink
                .octets()
                .chunks_exact(2)
                .zip(client.octets().chunks_exact(2))
            {
                checksum += u32::from(!u16::from_be_bytes([old[0], old[1]]));
                checksum += u32::from(u16::from_be_bytes([new[0], new[1]]));
            }
            checksum += u32::from(!external) + u32::from(flow.client_port);
            while checksum >> 16 != 0 {
                checksum = (checksum & 0xffff) + (checksum >> 16);
            }
            let mut checksum = !(checksum as u16);
            if protocol == 17 && checksum == 0 {
                checksum = u16::MAX;
            }
            quoted[checksum_offset..checksum_offset + 2].copy_from_slice(&checksum.to_be_bytes());
        }
        quoted[8..24].copy_from_slice(&client.octets());
        quoted[offset..offset + 2].copy_from_slice(&flow.client_port.to_be_bytes());
        packet[7] -= 1;
        update_checksum(packet);
        Ok(client)
    }
}

fn clamp_mss(packet: &mut [u8]) {
    if packet[HEADER + 13] & 2 == 0 {
        return;
    }
    let end = HEADER + usize::from(packet[HEADER + 12] >> 4) * 4;
    let mut index = HEADER + 20;
    while index < end {
        match packet[index] {
            0 => break,
            1 => index += 1,
            _ => {
                if index + 2 > end {
                    return;
                }
                let len = usize::from(packet[index + 1]);
                if len < 2 || index + len > end {
                    return;
                }
                if packet[index] == 2 && len == 4 {
                    let mss = u16::from_be_bytes([packet[index + 2], packet[index + 3]]);
                    packet[index + 2..index + 4]
                        .copy_from_slice(&mss.min((MTU - HEADER - 20) as u16).to_be_bytes());
                }
                index += len;
            }
        }
    }
}

/// Emit an ICMPv6 error to the packet's source. Never answer another error,
/// an unspecified source or multicast traffic, and never quote past 1280 bytes.
pub fn error_reply(
    original: &[u8],
    gateway: Ipv6Addr,
    kind: Error,
    out: &mut [u8],
) -> Option<usize> {
    let parsed = Packet::parse(original).ok()?;
    if !routable(parsed.source)
        || parsed.destination.is_multicast()
        || (parsed.protocol == 58 && original[HEADER] < 128)
    {
        return None;
    }
    let (ty, code, value) = match kind {
        Error::ExpiredHopLimit => (3, 0, 0u32),
        Error::PacketTooBig => (2, 0, MTU as u32),
        _ => return None,
    };
    let len = (HEADER + 8 + original.len()).min(MTU).min(out.len());
    if len < HEADER + 8 + HEADER {
        return None;
    }
    out[..len].fill(0);
    out[0] = 0x60;
    out[4..6].copy_from_slice(&((len - HEADER) as u16).to_be_bytes());
    out[6] = 58;
    out[7] = 64;
    out[8..24].copy_from_slice(&gateway.octets());
    out[24..40].copy_from_slice(&parsed.source.octets());
    out[HEADER] = ty;
    out[HEADER + 1] = code;
    out[HEADER + 4..HEADER + 8].copy_from_slice(&value.to_be_bytes());
    out[HEADER + 8..len].copy_from_slice(&original[..len - HEADER - 8]);
    update_checksum(&mut out[..len]);
    Some(len)
}

/// Answer Echo Requests addressed to the gateway's own tailnet address.
/// Local delivery does not require an upstream route or exit-route approval.
pub fn echo_reply(original: &[u8], gateway: Ipv6Addr, out: &mut [u8]) -> Option<usize> {
    let parsed = Packet::parse(original).ok()?;
    if parsed.destination != gateway
        || parsed.protocol != 58
        || original[HEADER] != 128
        || !routable(parsed.source)
        || original.len() > MTU
    {
        return None;
    }
    let reply = out.get_mut(..original.len())?;
    reply.copy_from_slice(original);
    reply[8..24].copy_from_slice(&gateway.octets());
    reply[24..40].copy_from_slice(&parsed.source.octets());
    reply[7] = 64;
    reply[HEADER] = 129;
    update_checksum(reply);
    Some(reply.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn address(text: &str) -> Ipv6Addr {
        text.parse().unwrap()
    }
    pub(super) fn udp(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> [u8; 52] {
        let mut packet = [0; 52];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&12u16.to_be_bytes());
        packet[6] = 17;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[44..46].copy_from_slice(&12u16.to_be_bytes());
        packet[48..].copy_from_slice(b"test");
        update_checksum(&mut packet);
        packet
    }

    pub(super) fn tcp(
        source: Ipv6Addr,
        destination: Ipv6Addr,
        source_port: u16,
        destination_port: u16,
    ) -> [u8; 64] {
        let mut packet = [0; 64];
        packet[0] = 0x60;
        packet[4..6].copy_from_slice(&24u16.to_be_bytes());
        packet[6] = 6;
        packet[7] = 64;
        packet[8..24].copy_from_slice(&source.octets());
        packet[24..40].copy_from_slice(&destination.octets());
        packet[40..42].copy_from_slice(&source_port.to_be_bytes());
        packet[42..44].copy_from_slice(&destination_port.to_be_bytes());
        packet[52] = 0x60;
        packet[53] = 2;
        packet[60..64].copy_from_slice(&[2, 4, 0x05, 0xb4]);
        update_checksum(&mut packet);
        packet
    }

    fn outbound(
        gateway: &mut Gateway,
        packet: &mut [u8],
        client: Ipv6Addr,
        uplink: Ipv6Addr,
        now_ms: u64,
    ) -> Result<Ipv6Addr, Error> {
        let prepared = gateway.prepare_outbound(packet, client, uplink, now_ms)?;
        let destination = prepared.destination();
        prepared.commit(now_ms);
        Ok(destination)
    }

    #[test]
    fn tcp_requires_syn_and_preserves_checksum_while_clamping_mss() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = tcp(client, server, 12345, 443);
        packet[53] = 0x10;
        update_checksum(&mut packet);
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 0),
            Err(Error::Unsolicited)
        );
        packet[53] = 2;
        update_checksum(&mut packet);
        outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
        assert_eq!(u16::from_be_bytes([packet[62], packet[63]]), 1220);
        let translated = Packet::parse(&packet).unwrap();
        let mut reply = tcp(server, uplink, 443, translated.source_port);
        reply[53] = 0x12;
        update_checksum(&mut reply);
        assert_eq!(gateway.inbound(&mut reply, uplink, 1), Ok(client));
        assert_eq!(Packet::parse(&reply).unwrap().destination_port, 12345);
    }

    #[test]
    fn mtu_errors_are_bounded_rate_limited_and_do_not_answer_errors() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut packet = [0; 1400];
        packet[..52].copy_from_slice(&udp(client, server, 12345, 443));
        packet[4..6].copy_from_slice(&1360u16.to_be_bytes());
        packet[44..46].copy_from_slice(&1360u16.to_be_bytes());
        update_checksum(&mut packet);
        let mut gateway = Gateway::new();
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 0),
            Err(Error::PacketTooBig)
        );
        let mut reply = [0; MTU];
        let len = gateway
            .error_response(&packet, uplink, Error::PacketTooBig, 0, &mut reply)
            .unwrap();
        assert_eq!(len, MTU);
        assert_eq!(reply[40], 2);
        assert_eq!(&reply[44..48], &(MTU as u32).to_be_bytes());
        assert!(Packet::parse(&reply).is_ok());
        assert!(
            gateway
                .error_response(&packet, uplink, Error::PacketTooBig, 99, &mut reply)
                .is_none()
        );
        assert!(
            gateway
                .error_response(&packet, uplink, Error::PacketTooBig, 100, &mut reply)
                .is_some()
        );
        let mut nested = [0; MTU];
        assert!(error_reply(&reply, uplink, Error::ExpiredHopLimit, &mut nested).is_none());
    }

    #[test]
    fn capacity_is_bounded_and_reuse_rotates_the_external_port() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut old_port = 0;
        for index in 0..SLOTS {
            let mut packet = udp(client, server, index as u16 + 1000, 443);
            outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
            if index == 0 {
                old_port = Packet::parse(&packet).unwrap().source_port;
            }
        }
        let mut packet = udp(client, server, 2000, 443);
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 1),
            Err(Error::Capacity)
        );
        outbound(&mut gateway, &mut packet, client, uplink, IDLE_MS).unwrap();
        assert_ne!(Packet::parse(&packet).unwrap().source_port, old_port);
        assert_eq!(
            gateway.inbound(&mut udp(server, uplink, 443, old_port), uplink, IDLE_MS + 1),
            Err(Error::Unsolicited)
        );
    }

    #[test]
    fn udp_round_trip_checks_tuple_checksum_and_hop_limit() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 0),
            Ok(server)
        );
        let translated = Packet::parse(&packet).unwrap();
        assert_eq!(translated.source, uplink);
        assert_eq!(translated.hop_limit, 63);
        let mut reply = udp(server, uplink, 443, translated.source_port);
        assert_eq!(gateway.inbound(&mut reply, uplink, 1), Ok(client));
        let reply = Packet::parse(&reply).unwrap();
        assert_eq!(reply.destination, client);
        assert_eq!(reply.destination_port, 12345);
        assert_eq!(reply.hop_limit, 63);
        let mut spoof = udp(address("2001:db8::3"), uplink, 443, translated.source_port);
        assert_eq!(
            gateway.inbound(&mut spoof, uplink, 2),
            Err(Error::Unsolicited)
        );
    }

    #[test]
    fn malformed_spoofed_scoped_and_expired_packets_cannot_create_mappings() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        packet[46] ^= 1;
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 0),
            Err(Error::Malformed)
        );
        let mut packet = udp(client, server, 12345, 443);
        assert_eq!(
            outbound(&mut gateway, &mut packet, server, uplink, 0),
            Err(Error::SpoofedSource)
        );
        for bad in ["::1", "::", "fe80::1", "ff02::1", "::ffff:192.0.2.1"] {
            let mut packet = udp(client, address(bad), 12345, 443);
            assert_eq!(
                outbound(&mut gateway, &mut packet, client, uplink, 0),
                Err(Error::IsolatedDestination)
            );
        }
        let mut packet = udp(client, server, 12345, 443);
        packet[7] = 1;
        assert_eq!(
            outbound(&mut gateway, &mut packet, client, uplink, 0),
            Err(Error::ExpiredHopLimit)
        );
        let mut reply = [0; MTU];
        let len = error_reply(&packet, uplink, Error::ExpiredHopLimit, &mut reply).unwrap();
        assert_eq!(Packet::parse(&reply[..len]).unwrap().destination, client);
        assert_eq!(reply[40], 3);
        assert!(gateway.flows.iter().all(Option::is_none));
    }

    #[test]
    fn address_change_and_idle_expiry_invalidate_return_traffic() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
        let port = Packet::parse(&packet).unwrap().source_port;
        assert_eq!(
            gateway.inbound(&mut udp(server, uplink, 443, port), uplink, IDLE_MS),
            Err(Error::Unsolicited)
        );
        assert_eq!(
            gateway.inbound(
                &mut udp(server, address("2001:db8::4"), 443, port),
                address("2001:db8::4"),
                1
            ),
            Err(Error::Unsolicited)
        );
    }

    #[test]
    fn address_reassignment_discards_old_mapping_without_reusing_its_port() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
        let old_port = Packet::parse(&packet).unwrap().source_port;
        gateway.clear(1);
        let mut packet = udp(client, server, 12345, 443);
        outbound(&mut gateway, &mut packet, client, uplink, 1).unwrap();
        assert_ne!(Packet::parse(&packet).unwrap().source_port, old_port);
        assert_eq!(
            gateway.inbound(&mut udp(server, uplink, 443, old_port), uplink, 2),
            Err(Error::Unsolicited)
        );
    }

    #[test]
    fn upstream_packet_too_big_restores_quoted_client_tuple() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
        let mut reply = [0; MTU];
        let len = error_reply(&packet, server, Error::PacketTooBig, &mut reply).unwrap();
        assert_eq!(gateway.inbound(&mut reply[..len], uplink, 1), Ok(client));
        assert_eq!(Packet::parse(&reply[48..len]).unwrap().source, client);
        assert_eq!(Packet::parse(&reply[..len]).unwrap().destination, client);
    }

    #[test]
    fn malformed_foreign_and_expired_error_quotes_cannot_select_a_client() {
        let client = address("fd7a:115c:a1e0::1");
        let server = address("2001:db8::2");
        let uplink = address("2001:db8::1");
        let mut gateway = Gateway::new();
        let mut packet = udp(client, server, 12345, 443);
        outbound(&mut gateway, &mut packet, client, uplink, 0).unwrap();
        let mut reply = [0; MTU];
        let len = error_reply(&packet, server, Error::PacketTooBig, &mut reply).unwrap();
        // Keep the outer checksum valid to reach quotation validation.
        for (offset, value, expected) in [
            (48 + 8, 0x21, Error::Unsolicited),
            (48 + 40, 0, Error::Unsolicited),
            (48 + 5, 0, Error::Malformed),
            (48 + 6, 44, Error::Unsupported),
        ] {
            let mut bad = reply;
            bad[offset] = value;
            update_checksum(&mut bad[..len]);
            assert_eq!(gateway.inbound(&mut bad[..len], uplink, 1), Err(expected));
        }
        assert_eq!(
            gateway.inbound(&mut reply[..len], uplink, IDLE_MS),
            Err(Error::Unsolicited)
        );
    }
}

#[cfg(test)]
#[path = "ipv6_lifecycle_tests.rs"]
mod lifecycle_tests;
