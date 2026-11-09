//! A Taildrop lab node: receive files from, and send one to, stock Tailscale.
//!
//! `taildrop_node <control-url> <state-directory> [--send=<ip>:<port>] [--timeout-seconds=N]`
//!
//! The single-use enrollment key is read from `TF_TEST_AUTH_KEY` and an
//! optional private control CA (DER) from the path in `TF_TEST_CA_DER`. The node
//! advertises a peer API on [`PEER_API_PORT`] and prints `READY <address>`
//! once mapped. Every received file is reported as
//! `RECEIVED name=<name> bytes=<n> fnv=<FNV-1a 64 hex>`.
//!
//! With `--send`, it then uploads [`SEND_BYTES`] bytes of [`pattern`] data as
//! `from-tailfeather.bin` to that peer API (a stock node's `PeerAPIURL`) and
//! prints `SENT ok` or `SENT err=<error>`.
use std::{io::Write as _, net::SocketAddr, path::PathBuf, time::Duration};
use tailfeather_gateway::peerapi::taildrop::{self, MemorySink, Peer, Upload};
use tailfeather_reactor::{
    native::{FileState, TokioNetwork},
    runtime::{self, Buffers, Config, Runtime},
    tcp::NetStack,
    tcp_async::Tcp,
};

const PEER_API_PORT: u16 = 5254;
const SEND_BYTES: u64 = 300_000;
const SEND_NAME: &str = "from-tailfeather.bin";

type Node<'a> = Runtime<'a, TokioNetwork, FileState, 4, 32>;
type Stream<'a> = Tcp<'a, 16, 128, std::collections::VecDeque<tailfeather_reactor::tcp::Packet>>;

/// Deterministic, non-repeating-at-small-periods test data the lab script
/// regenerates to verify what stock Tailscale stored.
fn pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(2_654_435_761) >> 13) as u8
}

struct Pattern {
    offset: u64,
}

impl embedded_io_async::ErrorType for Pattern {
    type Error = core::convert::Infallible;
}

impl embedded_io_async::Read for Pattern {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        for byte in buf.iter_mut() {
            *byte = pattern(self.offset);
            self.offset += 1;
        }
        Ok(buf.len())
    }
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn say(line: core::fmt::Arguments<'_>) {
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

async fn serve(
    runtime: &Node<'_>,
    tcp: &Stream<'_>,
    buffers: &mut Buffers<4>,
    send: Option<SocketAddr>,
    timeout: Duration,
) {
    let ready = async {
        let address = runtime.ready().await.unwrap();
        say(format_args!("READY {address}"));
        core::future::pending::<()>().await
    };
    let receive = async {
        let mut listener = tcp.listen(PEER_API_PORT).unwrap();
        let mut sink = MemorySink::new(64 << 20);
        let mut buffer = vec![0; 16 * 1024];
        loop {
            let Ok(stream) = listener.accept().await else {
                continue;
            };
            let Some(remote) = stream.remote_endpoint() else {
                continue;
            };
            // The runtime already enforced WireGuard source validation and
            // the packet filter. Stock Tailscale additionally requires the
            // sender to be the same user; this lab's tailnet has one user.
            let peer = Peer {
                addr: (*remote.ip()).into(),
                may_send_files: true,
            };
            let result = taildrop::serve_async(
                &mut &stream,
                &peer,
                &taildrop::Config::default(),
                &mut sink,
                &mut buffer,
            )
            .await;
            let _ = stream.shutdown();
            match result {
                Ok(taildrop::Served::Received { .. }) => {
                    for file in sink.take() {
                        say(format_args!(
                            "RECEIVED name={} bytes={} fnv={:016x} from={}",
                            file.name,
                            file.data.len(),
                            fnv1a(&file.data),
                            file.from,
                        ));
                    }
                }
                Ok(other) => say(format_args!("PEERAPI {other:?} from={remote}")),
                Err(error) => say(format_args!("PEERAPI error={error} from={remote}")),
            }
        }
    };
    let upload = async {
        let Some(target) = send else {
            return core::future::pending::<()>().await;
        };
        let SocketAddr::V4(target) = target else {
            panic!("--send needs an IPv4 peer API address");
        };
        runtime.ready().await.unwrap();
        let mut buffer = vec![0; 16 * 1024];
        // The first attempts may race WireGuard handshakes and map delivery.
        for attempt in 1..=20u16 {
            let stream = match runtime
                .connect(tcp, *target.ip(), target.port(), 40_000 + attempt)
                .await
            {
                Ok(stream) => stream,
                Err(error) => {
                    say(format_args!("CONNECT attempt={attempt} err={error}"));
                    tokio::time::sleep(Duration::from_millis(500)).await;
                    continue;
                }
            };
            let upload = Upload {
                peer_api: target.into(),
                name: SEND_NAME,
                size: SEND_BYTES,
                offset: 0,
            };
            let result = taildrop::send_async(
                &mut &stream,
                &upload,
                &mut Pattern { offset: 0 },
                &mut buffer,
            )
            .await;
            let _ = stream.shutdown();
            match result {
                Ok(()) => say(format_args!("SENT ok bytes={SEND_BYTES}")),
                Err(error) => say(format_args!("SENT err={error}")),
            }
            return core::future::pending::<()>().await;
        }
        say(format_args!("SENT err=no connection"));
        core::future::pending::<()>().await
    };
    tokio::select! {
        result = runtime.run(tcp, buffers) => panic!("runtime stopped: {result:?}"),
        _ = ready => {},
        _ = receive => {},
        _ = upload => {},
        _ = tokio::time::sleep(timeout) => say(format_args!("DEADLINE")),
    }
}

fn node(control_url: &str, state: PathBuf, send: Option<SocketAddr>, timeout: Duration) {
    let key = std::env::var("TF_TEST_AUTH_KEY").expect("TF_TEST_AUTH_KEY");
    let ca = std::env::var_os("TF_TEST_CA_DER")
        .map(|path| std::fs::read(path).expect("control CA"))
        .unwrap_or_default();
    std::fs::create_dir_all(&state).unwrap();
    let state = FileState::open(&state).unwrap();
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let network = executor
        .block_on(TokioNetwork::bind(std::net::Ipv4Addr::UNSPECIFIED, 0))
        .unwrap();
    let config = Config {
        control_url,
        hostname: "taildrop-node",
        auth_key: &key,
        control_ca_der: &ca,
        relay_only: false,
        ephemeral: true,
        os: std::env::consts::OS,
        peer_api_port: Some(PEER_API_PORT),
    };
    let mut node = Box::new(runtime::restore::<_, _, 4>(&config, &network, &state).unwrap());
    let runtime = Box::new(Node::new(config, &mut node, &network, &state).unwrap());
    let tcp = Box::new(Tcp::new(NetStack::new(1)));
    let mut buffers = Box::new(Buffers::new());
    executor.block_on(Box::pin(serve(&runtime, &tcp, &mut buffers, send, timeout)));
}

fn main() {
    let mut args = std::env::args().skip(1);
    let control_url = args.next().expect("control URL");
    let state = PathBuf::from(args.next().expect("state directory"));
    let mut timeout = Duration::from_secs(120);
    let mut send = None;
    for arg in args {
        if let Some(target) = arg.strip_prefix("--send=") {
            send = Some(target.parse().expect("--send=<ip>:<port>"));
        } else if let Some(seconds) = arg.strip_prefix("--timeout-seconds=") {
            timeout = Duration::from_secs(seconds.parse().unwrap());
        } else {
            panic!("unknown argument: {arg}");
        }
    }
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || node(&control_url, state, send, timeout))
        .unwrap()
        .join()
        .unwrap();
}
