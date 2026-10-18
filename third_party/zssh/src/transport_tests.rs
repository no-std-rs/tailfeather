//! Post-decryption protocol regressions; OpenSSH covers the encrypted path.
extern crate std;

use super::*;
use core::{
    convert::Infallible,
    future::Future,
    task::{Context, Poll, Waker},
};
use embedded_io_async::ErrorType;
use std::vec::Vec;

#[derive(Default)]
struct Stream {
    input: Vec<u8>,
    offset: usize,
    output: Vec<u8>,
}
impl ErrorType for Stream {
    type Error = Infallible;
}
impl Read for Stream {
    async fn read(&mut self, bytes: &mut [u8]) -> Result<usize, Infallible> {
        let len = bytes.len().min(self.input.len() - self.offset);
        bytes[..len].copy_from_slice(&self.input[self.offset..][..len]);
        self.offset += len;
        Ok(len)
    }
}
impl Write for Stream {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, Infallible> {
        self.output.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    async fn flush(&mut self) -> Result<(), Infallible> {
        Ok(())
    }
}

struct Random;
impl rand::RngCore for Random {
    fn next_u32(&mut self) -> u32 {
        0
    }
    fn next_u64(&mut self) -> u64 {
        0
    }
    fn fill_bytes(&mut self, bytes: &mut [u8]) {
        bytes.fill(0);
    }
    fn try_fill_bytes(&mut self, bytes: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(bytes);
        Ok(())
    }
}
impl rand::CryptoRng for Random {}

struct TestBehavior {
    stream: Stream,
    random: Random,
    key: SecretKey,
}
impl Behavior for TestBehavior {
    type Stream = Stream;
    type Random = Random;
    type User = ();
    type Command = ();
    fn stream(&mut self) -> &mut Stream {
        &mut self.stream
    }
    fn random(&mut self) -> &mut Random {
        &mut self.random
    }
    fn host_secret_key(&self) -> &SecretKey {
        &self.key
    }
    fn allow_user(&mut self, _: &str, _: &AuthMethod) -> Option<()> {
        Some(())
    }
    fn parse_command(&mut self, _: &str) {}
}

fn blocking<F: Future>(future: F) -> F::Output {
    match core::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(Waker::noop()))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("in-memory I/O suspended"),
    }
}

fn packet(message: wire::Message<'_>) -> Vec<u8> {
    let mut buffer = [0; 256];
    let payload = message.encode(&mut buffer).unwrap();
    let mut padding = (8 - (5 + payload.len()) % 8) % 8;
    if padding < 4 {
        padding += 8;
    }
    let len = 1 + payload.len() + padding;
    let mut result = Vec::from((len as u32).to_be_bytes());
    result.push(padding as u8);
    result.extend_from_slice(payload);
    result.resize(4 + len, 0);
    result
}

fn authenticated<'a>(
    buffer: &'a mut [u8],
    messages: &[wire::Message<'_>],
) -> Transport<'a, TestBehavior> {
    let mut stream = Stream::default();
    for message in messages {
        stream.input.extend(packet(*message));
    }
    let mut transport = Transport::new(
        buffer,
        TestBehavior {
            stream,
            random: Random,
            key: SecretKey::Ed25519 {
                secret_key: ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            },
        },
    );
    // Isolate the state after successful handshake/authentication. Packets here
    // are plaintext so tests exercise parsing and window ownership directly.
    transport.client_ssh_id_length = 1;
    transport.authenticated = true;
    transport.current_user = Some(());
    transport
}

fn active(transport: &mut Transport<'_, TestBehavior>, credit: u32) {
    transport.request = Some(Request::Shell);
    transport.active_channel = Some(ChannelState {
        rx_channel_id: 0,
        tx_channel_id: 4,
        tx_max_packet: 64,
        rx_half: HalfState::Window(0),
        tx_half: HalfState::Window(credit),
        rx_committed: false,
    });
}

#[test]
fn zero_packet_limit_is_rejected_and_one_byte_limit_works() {
    for limit in [0, 1] {
        let mut buffer = [0; 1024];
        let mut transport = authenticated(
            &mut buffer,
            &[wire::Message::ChannelOpen {
                channel: wire::ChannelType::Session {
                    sender_channel: 4,
                    initial_window_size: 8,
                    maximum_packet_size: limit,
                },
            }],
        );
        let result = blocking(transport.poll_client());
        if limit == 0 {
            assert_eq!(result, Err(Error::Protocol(ProtocolError::MalformedPacket)));
            assert!(transport.active_channel.is_none());
        } else {
            assert!(result.is_ok());
            transport.behavior.stream.output.clear();
            blocking(Channel::new(&mut transport).write_all_stdout(b"a")).unwrap();
            assert_eq!(
                payloads(&transport.behavior.stream.output, Pipe::Stdout),
                b"a"
            );
        }
    }
}

fn payloads(mut bytes: &[u8], pipe: Pipe) -> Vec<u8> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let padding = usize::from(bytes[4]);
        let message = wire::Message::decode(&bytes[5..4 + len - padding]).unwrap();
        let data = match (pipe, message) {
            (
                Pipe::Stdout,
                wire::Message::ChannelData {
                    recipient_channel: 4,
                    data,
                },
            ) => data,
            (
                Pipe::Stderr,
                wire::Message::ChannelExtendedData {
                    recipient_channel: 4,
                    data: wire::ExtendedData::Stderr { data },
                },
            ) => data,
            other => panic!("unexpected output: {other:?}"),
        };
        match data {
            wire::Data::Borrowed { bytes } => result.extend_from_slice(bytes),
            _ => panic!("decoded data must borrow the packet"),
        }
        bytes = &bytes[4 + len..];
    }
    result
}

#[test]
fn zero_copy_output_survives_zero_and_partial_window_credit() {
    for pipe in [Pipe::Stdout, Pipe::Stderr] {
        for initial in [0, 2] {
            let mut buffer = [0; 1024];
            let adjust = wire::Message::ChannelWindowAdjust {
                recipient_channel: 0,
                bytes_to_add: 3,
            };
            let mut transport = authenticated(&mut buffer, &[adjust, adjust]);
            active(&mut transport, initial);
            let mut expected = Vec::new();
            {
                let mut channel = Channel::new(&mut transport);
                for text in [b"abc", b"xyz"] {
                    let mut writer = blocking(channel.writer(pipe)).unwrap();
                    let size = writer.buffer().len();
                    assert_eq!(
                        size,
                        if expected.is_empty() && initial != 0 {
                            2
                        } else {
                            3
                        }
                    );
                    writer.buffer().copy_from_slice(&text[..size]);
                    blocking(writer.write_all(size)).unwrap();
                    expected.extend_from_slice(&text[..size]);
                }
            }
            assert_eq!(payloads(&transport.behavior.stream.output, pipe), expected);
            assert_eq!(transport.channel_write_credit(), 0);
        }
    }
}

#[test]
fn zero_copy_writer_reports_close_before_exposing_a_buffer() {
    let mut buffer = [0; 1024];
    let mut transport = authenticated(
        &mut buffer,
        &[wire::Message::ChannelClose {
            recipient_channel: 0,
        }],
    );
    active(&mut transport, 0);
    let mut channel = Channel::new(&mut transport);
    assert!(matches!(
        blocking(channel.stdout()),
        Err(Error::UnexpectedEof)
    ));
}

fn close_messages(mut bytes: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        let len = u32::from_be_bytes(bytes[..4].try_into().unwrap()) as usize;
        let padding = usize::from(bytes[4]);
        let message = wire::Message::decode(&bytes[5..4 + len - padding]).unwrap();
        result.push(match message {
            wire::Message::ChannelEof {
                recipient_channel: 4,
            } => 0,
            wire::Message::ChannelRequest {
                recipient_channel: 4,
                request:
                    wire::Request::ExitStatus {
                        want_reply: false,
                        exit_status: 23,
                    },
            } => 1,
            wire::Message::ChannelClose {
                recipient_channel: 4,
            } => 2,
            other => panic!("unexpected close message: {other:?}"),
        });
        bytes = &bytes[4 + len..];
    }
    result
}

#[test]
fn exit_waits_for_the_peer_close_acknowledgment() {
    let mut buffer = [0; 1024];
    let mut transport = authenticated(
        &mut buffer,
        &[
            wire::Message::ChannelEof {
                recipient_channel: 0,
            },
            wire::Message::ChannelClose {
                recipient_channel: 0,
            },
        ],
    );
    active(&mut transport, 0);
    blocking(Channel::new(&mut transport).exit(23)).unwrap();
    assert_eq!(
        transport.behavior.stream.offset,
        transport.behavior.stream.input.len()
    );
    assert!(transport.active_channel.is_none());
    assert_eq!(close_messages(&transport.behavior.stream.output), [0, 1, 2]);
}

#[test]
fn a_peer_initiated_close_gets_only_a_close_acknowledgment() {
    let mut buffer = [0; 1024];
    let mut transport = authenticated(&mut buffer, &[]);
    active(&mut transport, 0);
    transport.channel_state().rx_half = HalfState::Close;
    transport.channel_state().tx_half = HalfState::Close;
    blocking(Channel::new(&mut transport).exit(23)).unwrap();
    assert_eq!(close_messages(&transport.behavior.stream.output), [2]);
    assert!(transport.active_channel.is_none());
}

#[test]
fn transport_eof_cannot_complete_the_channel_close_handshake() {
    let mut buffer = [0; 1024];
    let mut transport = authenticated(&mut buffer, &[]);
    active(&mut transport, 0);
    assert_eq!(
        blocking(Channel::new(&mut transport).exit(23)),
        Err(Error::UnexpectedEof)
    );
}

#[test]
fn oversized_packet_headers_are_rejected_before_reading_the_body() {
    for encrypted in [false, true] {
        for length in if encrypted {
            [496u32, u32::MAX - 7]
        } else {
            [516, u32::MAX - 3]
        } {
            let mut buffer = [0; 512];
            let mut transport = authenticated(&mut buffer, &[]);
            transport.authenticated = false;
            let mut header = length.to_be_bytes();
            if encrypted {
                let key = [1; 32];
                // recv starts at sequence zero, and uses the separate header
                // key before validating the packet length or reading its MAC.
                let mut cipher = ChaCha20Legacy::new((&key).into(), (&[0; 8]).into());
                cipher.apply_keystream(&mut header);
                transport.curr_keys = Some(KeyMaterial {
                    client_head_key: key,
                    client_main_key: [2; 32],
                    server_head_key: [3; 32],
                    server_main_key: [4; 32],
                    session_id: [5; 32],
                });
            }
            transport.behavior.stream.input.extend_from_slice(&header);
            assert_eq!(
                blocking(transport.recv()),
                Err(Error::Protocol(ProtocolError::BufferExhausted))
            );
            assert_eq!(transport.behavior.stream.offset, 4);
        }
    }
}
