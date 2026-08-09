//! The client half of a DERP connection.
//!
//! Sans-io, like everything else here: it is fed frames that arrived and writes
//! frames to send, so the same code runs over plain TCP, over TLS, and in a test
//! against recorded bytes.
//!
//! # Identity
//!
//! DERP addresses packets by *node* key — the same key WireGuard uses — not by
//! disco key and not by machine key. That is what lets the relay forward a
//! packet without being able to read it: it matches a destination key against
//! its table of connected clients and copies bytes.

use crate::keys::{NodePrivate, NodePublic};
use crypto_box::aead::AeadInPlace;
use crypto_box::{PublicKey, SalsaBox, SecretKey};

use crate::derp::frame::{self, Frame, FrameType};
use crate::derp::{Error, MAGIC};

/// The largest packet this client will relay.
pub const MAX_PACKET: usize = frame::MAX_FRAME - 32;

const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const KEY_LEN: usize = 32;

/// The hello a client sends. Only the version matters to a plain relay; the
/// other fields exist for meshed servers, which a device never is.
const CLIENT_INFO: &[u8] = br#"{"version":2}"#;

/// A source of random bytes for the handshake nonce.
pub trait Rng {
    fn fill_bytes(&mut self, dest: &mut [u8]);
}

fn shared(ours: &NodePrivate, theirs: &NodePublic) -> SalsaBox {
    SalsaBox::new(
        &PublicKey::from_bytes(*theirs.as_bytes()),
        &SecretKey::from_bytes(ours.to_bytes()),
    )
}

/// An established relay connection.
pub struct Client {
    server: NodePublic,
}

impl Client {
    /// Read the server's opening frame and learn its key.
    ///
    /// The key also appears in a `Derp-Public-Key` header on the upgrade
    /// response, but that is HTTP metadata; this is the protocol's own
    /// statement of it, and the one the handshake is bound to.
    pub fn read_server_key(frame: Frame, payload: &[u8]) -> Result<NodePublic, Error> {
        if frame.kind != FrameType::ServerKey {
            return Err(Error::Malformed);
        }
        if payload.len() < MAGIC.len() + KEY_LEN || payload[..MAGIC.len()] != MAGIC {
            return Err(Error::Malformed);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&payload[MAGIC.len()..MAGIC.len() + KEY_LEN]);
        Ok(NodePublic::from_bytes(key))
    }

    /// Write the client's answer: our key, a nonce, and a sealed hello.
    ///
    /// Sealing it is what proves we hold the private half of the node key we are
    /// claiming — the relay will forward packets addressed to it, so an
    /// unauthenticated claim would let anyone intercept another node's traffic.
    pub fn write_client_info(
        ours: &NodePrivate,
        our_public: &NodePublic,
        server: &NodePublic,
        rng: &mut impl Rng,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut payload = [0u8; KEY_LEN + NONCE_LEN + 128];
        let sealed_len = CLIENT_INFO.len() + TAG_LEN;
        let total = KEY_LEN + NONCE_LEN + sealed_len;
        if total > payload.len() {
            return Err(Error::BufferTooSmall);
        }

        payload[..KEY_LEN].copy_from_slice(our_public.as_bytes());
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        payload[KEY_LEN..KEY_LEN + NONCE_LEN].copy_from_slice(&nonce);

        // NaCl again, so the tag comes first — the same trap as disco.
        let body_start = KEY_LEN + NONCE_LEN + TAG_LEN;
        payload[body_start..body_start + CLIENT_INFO.len()].copy_from_slice(CLIENT_INFO);
        let tag = shared(ours, server)
            .encrypt_in_place_detached(
                &nonce.into(),
                &[],
                &mut payload[body_start..body_start + CLIENT_INFO.len()],
            )
            .map_err(|_| Error::Decryption)?;
        payload[KEY_LEN + NONCE_LEN..body_start].copy_from_slice(&tag);

        frame::write(FrameType::ClientInfo, &payload[..total], out)
    }

    /// Open the server's reply, completing the handshake.
    pub fn read_server_info(
        ours: &NodePrivate,
        server: &NodePublic,
        frame: Frame,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<Self, Error> {
        if frame.kind != FrameType::ServerInfo {
            return Err(Error::Malformed);
        }
        let sealed = payload.get(NONCE_LEN..).ok_or(Error::Malformed)?;
        let len = sealed.len().checked_sub(TAG_LEN).ok_or(Error::Malformed)?;
        let out = out.get_mut(..len).ok_or(Error::BufferTooSmall)?;

        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&payload[..NONCE_LEN]);
        let (tag, ciphertext) = sealed.split_at(TAG_LEN);
        out.copy_from_slice(ciphertext);
        shared(ours, server)
            .decrypt_in_place_detached(&nonce.into(), &[], out, tag.into())
            .map_err(|_| Error::Decryption)?;

        Ok(Self { server: *server })
    }

    pub fn server(&self) -> &NodePublic {
        &self.server
    }

    /// Frame a packet for another node.
    ///
    /// The relay reads only the destination key; everything after it is opaque,
    /// which is what makes relaying safe to do through a server nobody trusts.
    pub fn send_packet(
        &self,
        destination: &NodePublic,
        packet: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Error> {
        if packet.len() > MAX_PACKET {
            return Err(Error::TooLarge);
        }
        let mut payload = [0u8; frame::MAX_FRAME];
        payload[..KEY_LEN].copy_from_slice(destination.as_bytes());
        payload[KEY_LEN..KEY_LEN + packet.len()].copy_from_slice(packet);
        frame::write(
            FrameType::SendPacket,
            &payload[..KEY_LEN + packet.len()],
            out,
        )
    }

    /// Read a relayed packet, and who sent it.
    pub fn read_packet(frame: Frame, payload: &[u8]) -> Result<(NodePublic, &[u8]), Error> {
        if frame.kind != FrameType::RecvPacket {
            return Err(Error::Malformed);
        }
        if payload.len() < KEY_LEN {
            return Err(Error::Malformed);
        }
        let mut key = [0u8; KEY_LEN];
        key.copy_from_slice(&payload[..KEY_LEN]);
        Ok((NodePublic::from_bytes(key), &payload[KEY_LEN..]))
    }

    /// Tell the server whether this is the node's preferred relay, which is what
    /// it uses to decide where to deliver packets for a node connected to
    /// several.
    pub fn write_note_preferred(preferred: bool, out: &mut [u8]) -> Result<usize, Error> {
        frame::write(FrameType::NotePreferred, &[preferred as u8], out)
    }
}

/// Write the HTTP/1.1 upgrade that starts a DERP connection.
pub fn write_upgrade_request<'o>(host: &str, out: &'o mut [u8]) -> Result<&'o [u8], Error> {
    let parts: [&[u8]; 6] = [
        b"GET ",
        crate::derp::PATH.as_bytes(),
        b" HTTP/1.1\r\nHost: ",
        host.as_bytes(),
        b"\r\nConnection: Upgrade\r\nUpgrade: ",
        crate::derp::UPGRADE_TOKEN.as_bytes(),
    ];
    let mut len = 0;
    for part in parts {
        let end = len + part.len();
        out.get_mut(len..end)
            .ok_or(Error::BufferTooSmall)?
            .copy_from_slice(part);
        len = end;
    }
    let tail = b"\r\n\r\n";
    let end = len + tail.len();
    out.get_mut(len..end)
        .ok_or(Error::BufferTooSmall)?
        .copy_from_slice(tail);
    Ok(&out[..end])
}

/// Whether a response is the upgrade we asked for, and where its headers ended.
pub fn parse_upgrade(bytes: &[u8]) -> Result<usize, Error> {
    let end = bytes
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .ok_or(Error::Incomplete)?;
    let head = &bytes[..end];
    if !head.starts_with(b"HTTP/1.1 101") {
        return Err(Error::Malformed);
    }
    // The server states its version here as well as by behaviour. A relay that
    // spoke version 1 would omit the sender key from every received packet.
    if !contains(head, b"Derp-Version: 2") && !contains(head, b"derp-version: 2") {
        return Err(Error::Unsupported);
    }
    Ok(end)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Counter(u8);

    impl Rng for Counter {
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0;
                self.0 = self.0.wrapping_add(1);
            }
        }
    }

    /// The server key frame a real Headscale sent, reconstructed.
    fn server_key_frame(key: &NodePublic) -> heapless::Vec<u8, 64> {
        let mut payload = heapless::Vec::<u8, 64>::new();
        payload.extend_from_slice(&MAGIC).unwrap();
        payload.extend_from_slice(key.as_bytes()).unwrap();
        let mut out = heapless::Vec::<u8, 64>::new();
        out.resize_default(64).unwrap();
        let len = frame::write(FrameType::ServerKey, &payload, &mut out).unwrap();
        out.truncate(len);
        out
    }

    #[test]
    fn reads_the_server_key_out_of_its_opening_frame() {
        let server = NodePrivate::from_bytes([0x22; 32]).public();
        let bytes = server_key_frame(&server);
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(
            Client::read_server_key(frame, &bytes[frame::HEADER_LEN..]).unwrap(),
            server
        );
    }

    #[test]
    fn a_frame_without_the_magic_is_not_a_server_key() {
        // Otherwise 32 bytes of anything would be taken as the server's
        // identity, and the handshake would be sealed to a stranger.
        let mut payload = [0u8; 40];
        payload[..8].copy_from_slice(b"NOTDERP!");
        let mut bytes = [0u8; 64];
        let len = frame::write(FrameType::ServerKey, &payload, &mut bytes).unwrap();
        let frame = Frame::parse(&bytes).unwrap();
        assert_eq!(
            Client::read_server_key(frame, &bytes[frame::HEADER_LEN..len]),
            Err(Error::Malformed)
        );
    }

    /// The client's hello must open under the server's key — that is what proves
    /// we hold the node key we are claiming, and the relay forwards packets
    /// addressed to it.
    #[test]
    fn the_handshake_completes_against_a_server_that_holds_the_matching_key() {
        let ours = NodePrivate::from_bytes([0x11; 32]);
        let server_private = NodePrivate::from_bytes([0x22; 32]);
        let server = server_private.public();

        let mut out = [0u8; 256];
        let len =
            Client::write_client_info(&ours, &ours.public(), &server, &mut Counter(1), &mut out)
                .unwrap();

        let frame = Frame::parse(&out).unwrap();
        assert_eq!(frame.kind, FrameType::ClientInfo);
        let payload = &out[frame::HEADER_LEN..len];
        assert_eq!(&payload[..32], ours.public().as_bytes());

        // Open it the way the server would: our public key against its private.
        let sealed = &payload[32 + NONCE_LEN..];
        let mut nonce = [0u8; NONCE_LEN];
        nonce.copy_from_slice(&payload[32..32 + NONCE_LEN]);
        let (tag, ciphertext) = sealed.split_at(TAG_LEN);
        let mut plaintext = [0u8; 64];
        plaintext[..ciphertext.len()].copy_from_slice(ciphertext);
        shared(&server_private, &ours.public())
            .decrypt_in_place_detached(
                &nonce.into(),
                &[],
                &mut plaintext[..ciphertext.len()],
                tag.into(),
            )
            .expect("the server must be able to open our hello");
        assert_eq!(&plaintext[..ciphertext.len()], CLIENT_INFO);
    }

    #[test]
    fn a_packet_carries_its_destination_and_comes_back_with_its_source() {
        let ours = NodePrivate::from_bytes([0x11; 32]);
        let destination = NodePrivate::from_bytes([0x33; 32]).public();
        let client = Client {
            server: NodePrivate::from_bytes([0x22; 32]).public(),
        };

        let mut out = [0u8; 256];
        client
            .send_packet(&destination, b"wireguard bytes", &mut out)
            .unwrap();
        let frame = Frame::parse(&out).unwrap();
        assert_eq!(frame.kind, FrameType::SendPacket);
        assert_eq!(
            &out[frame::HEADER_LEN..frame::HEADER_LEN + 32],
            destination.as_bytes()
        );

        // What the far side sees: the same shape, with the sender's key instead.
        let mut relayed = [0u8; 256];
        relayed[..32].copy_from_slice(ours.public().as_bytes());
        relayed[32..32 + 15].copy_from_slice(b"wireguard bytes");
        let mut framed = [0u8; 256];
        let len = frame::write(FrameType::RecvPacket, &relayed[..47], &mut framed).unwrap();
        let frame = Frame::parse(&framed).unwrap();
        let (source, packet) = Client::read_packet(frame, &framed[frame::HEADER_LEN..len]).unwrap();
        assert_eq!(source, ours.public());
        assert_eq!(packet, b"wireguard bytes");
    }

    #[test]
    fn the_upgrade_request_and_response_match_what_a_real_server_expects() {
        let mut out = [0u8; 256];
        let request = write_upgrade_request("127.0.0.1:8080", &mut out).unwrap();
        let text = core::str::from_utf8(request).unwrap();
        assert!(text.starts_with("GET /derp HTTP/1.1\r\n"));
        assert!(text.contains("Upgrade: DERP\r\n"));
        assert!(text.contains("Connection: Upgrade\r\n"));

        // Headscale's actual response.
        let response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\nDerp-Version: 2\r\nDerp-Public-Key: nodekey:ee02\r\n\r\n\x01\x00";
        let end = parse_upgrade(response).unwrap();
        assert_eq!(&response[end..], b"\x01\x00", "the first frame follows");

        // A relay speaking version 1 would omit the sender key from every
        // packet it delivered, which is not something to discover later.
        let old = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nDerp-Version: 1\r\n\r\n";
        assert_eq!(parse_upgrade(old), Err(Error::Unsupported));
        assert_eq!(
            parse_upgrade(b"HTTP/1.1 400 Bad\r\n\r\n"),
            Err(Error::Malformed)
        );
        assert_eq!(parse_upgrade(b"HTTP/1.1 101"), Err(Error::Incomplete));
    }
}
