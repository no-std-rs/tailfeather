//! Small allocation-free interoperability probes used by the namespace lab.

use core::net::{Ipv4Addr, SocketAddrV4};

use crate::exec::{Reactor, block_on};
use crate::net::{TcpListener, TcpStream, UdpSocket};
use crate::time::Clock;

const CHALLENGE: &[u8] = b"tailfeather-nostd-interop-v1";
pub const CHALLENGE_LEN: usize = CHALLENGE.len();
pub const RESPONSE_LEN: usize = 4 + CHALLENGE_LEN;

pub fn server(protocol: &str, bind: Ipv4Addr, port: u16) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    match protocol {
        "udp" => {
            let socket = UdpSocket::bind(&reactor, bind, port).expect("bind probe UDP server");
            evt!("{{\"event\":\"ready\",\"probe\":\"udp-server\"}}");
            block_on(&reactor, async {
                let mut request = [0u8; 64];
                let (len, from) = socket
                    .recv_from(&mut request)
                    .await
                    .expect("receive challenge");
                assert_eq!(&request[..len], CHALLENGE, "exact UDP challenge");
                let mut response = [0u8; 68];
                response[..4].copy_from_slice(&from.ip().octets());
                response[4..4 + len].copy_from_slice(&request[..len]);
                socket
                    .send_to(&response[..4 + len], &from)
                    .await
                    .expect("send UDP response");
                evt!(
                    "{{\"event\":\"observed\",\"protocol\":\"udp\",\"source\":\"{}\"}}",
                    from.ip()
                );
                crate::rt::exit(0)
            })
        }
        "tcp" => {
            let listener = TcpListener::bind(&reactor, bind, port).expect("bind probe TCP server");
            evt!("{{\"event\":\"ready\",\"probe\":\"tcp-server\"}}");
            block_on(&reactor, async {
                let stream = listener
                    .accept()
                    .await
                    .expect("accept probe TCP connection");
                let observed = stream.peer_address().expect("TCP peer address");
                let mut request = [0u8; CHALLENGE.len()];
                stream
                    .read_exact(&mut request)
                    .await
                    .expect("read exact challenge");
                assert_eq!(&request, CHALLENGE, "exact TCP challenge");
                stream
                    .write_all(&observed.ip().octets())
                    .await
                    .expect("write observed source");
                stream
                    .write_all(&request)
                    .await
                    .expect("write challenge response");
                evt!(
                    "{{\"event\":\"observed\",\"protocol\":\"tcp\",\"source\":\"{}\"}}",
                    observed.ip()
                );
                crate::rt::exit(0)
            })
        }
        _ => panic!("probe protocol must be udp or tcp"),
    }
}

pub fn client(protocol: &str, server: Ipv4Addr, port: u16, expected: Ipv4Addr) -> ! {
    let clock = Clock::start();
    let reactor = Reactor::new(clock);
    match protocol {
        "udp" => {
            let socket =
                UdpSocket::bind(&reactor, Ipv4Addr::UNSPECIFIED, 0).expect("bind probe UDP client");
            block_on(&reactor, async {
                let endpoint = SocketAddrV4::new(server, port);
                socket
                    .send_to(CHALLENGE, &endpoint)
                    .await
                    .expect("send challenge");
                let mut response = [0u8; 68];
                let (len, from) = socket
                    .recv_from(&mut response)
                    .await
                    .expect("receive response");
                assert_eq!(from, endpoint, "UDP response endpoint");
                verify(&response[..len], expected);
                evt!(
                    "{{\"event\":\"verified\",\"protocol\":\"udp\",\"source\":\"{}\"}}",
                    expected
                );
                crate::rt::exit(0)
            })
        }
        "tcp" => block_on(&reactor, async {
            let stream = TcpStream::connect(&reactor, server, port)
                .await
                .expect("connect probe TCP client");
            stream
                .write_all(CHALLENGE)
                .await
                .expect("send exact challenge");
            let mut response = [0u8; RESPONSE_LEN];
            stream
                .read_exact(&mut response)
                .await
                .expect("receive exact response");
            verify(&response, expected);
            evt!(
                "{{\"event\":\"verified\",\"protocol\":\"tcp\",\"source\":\"{}\"}}",
                expected
            );
            crate::rt::exit(0)
        }),
        _ => panic!("probe protocol must be udp or tcp"),
    }
}

fn verify(response: &[u8], expected: Ipv4Addr) {
    assert_eq!(response.len(), 4 + CHALLENGE.len(), "exact response length");
    assert_eq!(&response[..4], &expected.octets(), "gateway uplink source");
    assert_eq!(&response[4..], CHALLENGE, "exact challenge response");
}
