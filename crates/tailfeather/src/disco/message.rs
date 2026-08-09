//! The three messages disco exchanges.
//!
//! Every one is `1B type ‖ 1B version ‖ body`, with the version zero. Addresses
//! inside a message are always sixteen bytes — an IPv4 address is written as
//! its IPv4-mapped IPv6 form — followed by a big-endian port. Writing four
//! bytes for a v4 address instead shortens every following field.

use core::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::keys::NodePublic;

use crate::disco::Error;

pub const TYPE_PING: u8 = 0x01;
pub const TYPE_PONG: u8 = 0x02;
pub const TYPE_CALL_ME_MAYBE: u8 = 0x03;

/// The only version defined.
pub const VERSION: u8 = 0;

/// `type ‖ version`.
pub const HEADER_LEN: usize = 2;

/// A transaction identifier, echoed by a pong so a reply can be matched to the
/// probe that caused it — and, more importantly, to the *path* it was sent on.
pub type TxId = [u8; 12];

/// 16-byte address plus a 2-byte port.
pub const ADDRESS_LEN: usize = 18;

/// How many endpoints one `CallMeMaybe` may carry.
///
/// A peer may list more; the extras are dropped. They are candidates, and any
/// one of them may be the one that works, so eight is a bound on effort rather
/// than on correctness.
pub const MAX_ENDPOINTS: usize = 8;

/// A probe. The sender is asking "can you hear me at this address?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping {
    pub tx_id: TxId,
    /// Which node is pinging. Present so a receiver can attribute the probe
    /// without having to already know the disco key, which is how a node
    /// learns a peer's disco key in the first place.
    pub node_key: Option<NodePublic>,
}

/// The answer, carrying the address the ping *appeared* to come from.
///
/// That address is the point of the whole exchange: it is the only way a node
/// behind NAT can learn what the rest of the internet sees it as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pong {
    pub tx_id: TxId,
    pub src: SocketAddr,
}

/// "Here are all the addresses I might be reachable at; try them."
///
/// Sent through the relay when a direct path is not yet established, which is
/// what makes it useful — it needs a working path to bootstrap a better one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallMeMaybe {
    pub endpoints: heapless::Vec<SocketAddr, MAX_ENDPOINTS>,
}

/// Clippy would have this boxed, which needs an allocator this crate does not
/// have. The size is bounded by [`MAX_ENDPOINTS`] and is a deliberate trade:
/// one stack buffer big enough for the largest message, rather than a heap.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Ping(Ping),
    Pong(Pong),
    CallMeMaybe(CallMeMaybe),
}

impl Message {
    /// Write the message, returning its length.
    pub fn encode(&self, out: &mut [u8]) -> Result<usize, Error> {
        match self {
            Self::Ping(ping) => {
                let len = HEADER_LEN + 12 + if ping.node_key.is_some() { 32 } else { 0 };
                let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
                out[0] = TYPE_PING;
                out[1] = VERSION;
                out[2..14].copy_from_slice(&ping.tx_id);
                if let Some(key) = &ping.node_key {
                    out[14..46].copy_from_slice(key.as_bytes());
                }
                Ok(len)
            }
            Self::Pong(pong) => {
                let len = HEADER_LEN + 12 + ADDRESS_LEN;
                let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
                out[0] = TYPE_PONG;
                out[1] = VERSION;
                out[2..14].copy_from_slice(&pong.tx_id);
                write_address(&pong.src, &mut out[14..14 + ADDRESS_LEN]);
                Ok(len)
            }
            Self::CallMeMaybe(call) => {
                let len = HEADER_LEN + call.endpoints.len() * ADDRESS_LEN;
                let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;
                out[0] = TYPE_CALL_ME_MAYBE;
                out[1] = VERSION;
                for (index, endpoint) in call.endpoints.iter().enumerate() {
                    let start = HEADER_LEN + index * ADDRESS_LEN;
                    write_address(endpoint, &mut out[start..start + ADDRESS_LEN]);
                }
                Ok(len)
            }
        }
    }

    /// Read a message from a decrypted disco payload.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() < HEADER_LEN {
            return Err(Error::Malformed);
        }
        let (kind, version, body) = (bytes[0], bytes[1], &bytes[HEADER_LEN..]);
        if version != VERSION {
            return Err(Error::Unsupported);
        }

        match kind {
            TYPE_PING => {
                if body.len() < 12 {
                    return Err(Error::Malformed);
                }
                let mut tx_id = [0u8; 12];
                tx_id.copy_from_slice(&body[..12]);
                // The node key is optional and newer senders pad after it, so
                // the length is a lower bound rather than an equality.
                let node_key = if body.len() >= 12 + 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&body[12..44]);
                    Some(NodePublic::from_bytes(key))
                } else {
                    None
                };
                Ok(Self::Ping(Ping { tx_id, node_key }))
            }
            TYPE_PONG => {
                if body.len() < 12 + ADDRESS_LEN {
                    return Err(Error::Malformed);
                }
                let mut tx_id = [0u8; 12];
                tx_id.copy_from_slice(&body[..12]);
                Ok(Self::Pong(Pong {
                    tx_id,
                    src: read_address(&body[12..12 + ADDRESS_LEN])?,
                }))
            }
            TYPE_CALL_ME_MAYBE => {
                let mut endpoints = heapless::Vec::new();
                for chunk in body.chunks_exact(ADDRESS_LEN) {
                    // More endpoints than we can hold is not an error: they are
                    // candidates, and any one of them may be the one that works.
                    if endpoints.push(read_address(chunk)?).is_err() {
                        break;
                    }
                }
                Ok(Self::CallMeMaybe(CallMeMaybe { endpoints }))
            }
            _ => Err(Error::Unsupported),
        }
    }
}

/// Write an address as 16 bytes plus a big-endian port.
///
/// An IPv4 address goes out in its IPv4-mapped form, which is what makes every
/// address the same width regardless of family.
fn write_address(address: &SocketAddr, out: &mut [u8]) {
    let octets = match address.ip() {
        IpAddr::V4(v4) => v4.to_ipv6_mapped().octets(),
        IpAddr::V6(v6) => v6.octets(),
    };
    out[..16].copy_from_slice(&octets);
    out[16..18].copy_from_slice(&address.port().to_be_bytes());
}

fn read_address(bytes: &[u8]) -> Result<SocketAddr, Error> {
    let octets: [u8; 16] = bytes.get(..16).ok_or(Error::Malformed)?.try_into().unwrap();
    let port = u16::from_be_bytes([bytes[16], bytes[17]]);
    let address = Ipv6Addr::from(octets);
    // An IPv4-mapped address is an IPv4 address; keeping it in v6 form would
    // make it fail to match the endpoint it came from.
    let address = match address.to_ipv4_mapped() {
        Some(v4) => IpAddr::V4(v4),
        None => IpAddr::V6(address),
    };
    Ok(SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::NodePrivate;

    fn round_trip(message: &Message) -> Message {
        let mut buffer = [0u8; 256];
        let len = message.encode(&mut buffer).unwrap();
        Message::decode(&buffer[..len]).unwrap()
    }

    #[test]
    fn a_ping_carries_its_transaction_id_and_the_sending_node() {
        let key = NodePrivate::from_bytes([0x11; 32]).public();
        let ping = Message::Ping(Ping {
            tx_id: *b"0123456789ab",
            node_key: Some(key),
        });

        let mut buffer = [0u8; 256];
        let len = ping.encode(&mut buffer).unwrap();
        assert_eq!(len, 2 + 12 + 32);
        assert_eq!(buffer[0], TYPE_PING);
        assert_eq!(buffer[1], VERSION);
        assert_eq!(round_trip(&ping), ping);
    }

    #[test]
    fn a_ping_without_a_node_key_is_shorter_and_still_valid() {
        let ping = Message::Ping(Ping {
            tx_id: *b"0123456789ab",
            node_key: None,
        });
        let mut buffer = [0u8; 256];
        assert_eq!(ping.encode(&mut buffer).unwrap(), 2 + 12);
        assert_eq!(round_trip(&ping), ping);
    }

    #[test]
    fn a_ping_with_trailing_padding_still_decodes() {
        // Newer senders pad a ping to probe path MTU. A decoder that required
        // an exact length would reject every one of them.
        let key = NodePrivate::from_bytes([0x11; 32]).public();
        let mut buffer = [0u8; 256];
        let base = Message::Ping(Ping {
            tx_id: *b"0123456789ab",
            node_key: Some(key),
        });
        let len = base.encode(&mut buffer).unwrap();
        let padded = len + 40;
        assert_eq!(Message::decode(&buffer[..padded]).unwrap(), base);
    }

    #[test]
    fn a_pong_reports_the_address_the_ping_came_from() {
        // The whole point of the exchange: this is how a node behind NAT learns
        // its own public address.
        let pong = Message::Pong(Pong {
            tx_id: *b"0123456789ab",
            src: "192.0.2.7:41641".parse().unwrap(),
        });
        let mut buffer = [0u8; 256];
        let len = pong.encode(&mut buffer).unwrap();
        assert_eq!(len, 2 + 12 + 18);
        assert_eq!(buffer[0], TYPE_PONG);
        assert_eq!(round_trip(&pong), pong);
    }

    #[test]
    fn an_ipv4_address_travels_in_its_mapped_form_and_comes_back_as_ipv4() {
        // Sixteen bytes regardless of family, or every field after it shifts.
        let pong = Message::Pong(Pong {
            tx_id: [0; 12],
            src: "10.1.2.3:1234".parse().unwrap(),
        });
        let mut buffer = [0u8; 64];
        pong.encode(&mut buffer).unwrap();
        // ::ffff:10.1.2.3
        assert_eq!(&buffer[14..24], &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(&buffer[24..26], &[0xff, 0xff]);
        assert_eq!(&buffer[26..30], &[10, 1, 2, 3]);
        assert_eq!(&buffer[30..32], &1234u16.to_be_bytes());
        assert_eq!(round_trip(&pong), pong);
    }

    #[test]
    fn an_ipv6_address_survives_unchanged() {
        let pong = Message::Pong(Pong {
            tx_id: [0; 12],
            src: "[2001:db8::1]:443".parse().unwrap(),
        });
        assert_eq!(round_trip(&pong), pong);
    }

    #[test]
    fn call_me_maybe_carries_a_list_of_candidates() {
        let mut endpoints = heapless::Vec::new();
        endpoints.push("192.0.2.1:1".parse().unwrap()).unwrap();
        endpoints.push("[2001:db8::2]:2".parse().unwrap()).unwrap();
        let call = Message::CallMeMaybe(CallMeMaybe { endpoints });

        let mut buffer = [0u8; 256];
        let len = call.encode(&mut buffer).unwrap();
        assert_eq!(len, 2 + 2 * 18);
        assert_eq!(buffer[0], TYPE_CALL_ME_MAYBE);
        assert_eq!(round_trip(&call), call);
    }

    #[test]
    fn messages_that_are_truncated_or_unknown_are_refused() {
        assert_eq!(Message::decode(&[]), Err(Error::Malformed));
        assert_eq!(Message::decode(&[TYPE_PING]), Err(Error::Malformed));
        // A ping with no room for a transaction id.
        assert_eq!(
            Message::decode(&[TYPE_PING, VERSION, 1, 2, 3]),
            Err(Error::Malformed)
        );
        // A pong missing its address.
        assert_eq!(
            Message::decode(&[TYPE_PONG, VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(Error::Malformed)
        );
        // A version or type from the future.
        assert_eq!(Message::decode(&[TYPE_PING, 9, 0]), Err(Error::Unsupported));
        assert_eq!(Message::decode(&[0x7f, VERSION]), Err(Error::Unsupported));
    }

    #[test]
    fn a_buffer_too_small_is_an_error_not_a_short_message() {
        let pong = Message::Pong(Pong {
            tx_id: [0; 12],
            src: "10.0.0.1:1".parse().unwrap(),
        });
        let mut buffer = [0u8; 8];
        assert_eq!(pong.encode(&mut buffer), Err(Error::BufferTooSmall));
    }
}
