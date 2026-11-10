//! A Taildrop lab node: receive files from, and send one to, stock Tailscale.
//!
//! `taildrop_node <control-url> <state-directory> [--send-to=<ipv4>] [--timeout-seconds=N]`
//!
//! The single-use enrollment key is read from `TF_TEST_AUTH_KEY` and an
//! optional private control CA (DER) from the path in `TF_TEST_CA_DER`. The
//! node advertises a peer API on [`PEER_API_PORT`] over IPv4 and IPv6, prints
//! `READY <ipv4> <ipv6>` once mapped, and authorizes every sender from the netmap exactly as stock
//! Tailscale does. Each received file is reported as
//! `RECEIVED name=<name> bytes=<n> fnv=<FNV-1a 64 hex> from=<address>`, and
//! each refused or failed request as `PEERAPI ...`.
//!
//! With `--send-to`, it finds that peer's peer API in the netmap and uploads
//! [`SEND_BYTES`] bytes of [`pattern`] data as `from-tailfeather.bin`, the way
//! an interrupted transfer would: the first upload breaks off after
//! [`BREAK_AT`] bytes, a resume probe asks the receiver what it kept, and the
//! rest follows. A receiver still finishing the broken attempt answers `409`;
//! the node then backs off and probes again. It prints `TARGET <peer-api>`,
//! `RESUMED offset=<n>` per attempt (`RETRY ...` between them), then
//! `SENT ok bytes=<n>` or `SENT err=<error>`. It then sends [`SEND6_BYTES`]
//! more as `from-tailfeather-v6.bin` to the peer's IPv6 peer API, printing
//! `TARGET6 <peer-api>` and `SENT6 ok bytes=<n>` or `SENT6 err=<error>`.
//!
//! Every line is echoed to stderr with the seconds since the first, so the
//! lab log shows how long each step took.
use std::{
    io::Write as _,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    time::Duration,
};
use tailfeather_gateway::peerapi::taildrop::{self, MemorySink, Peer, Upload};
use tailfeather_reactor::{
    native::{FileState, TokioNetwork},
    runtime::{self, Buffers, Config, Runtime},
    tcp::NetStack,
    tcp_async::Tcp,
};

const PEER_API_PORT: u16 = 5254;
const SEND_BYTES: u64 = 300_000;
const BREAK_AT: u64 = 150_000;
const SEND_NAME: &str = "from-tailfeather.bin";
const SEND6_BYTES: u64 = 100_000;
const SEND6_NAME: &str = "from-tailfeather-v6.bin";

type Queue = std::collections::VecDeque<tailfeather_reactor::tcp::Packet>;
type Node<'a> = Runtime<'a, TokioNetwork, FileState, 4, 32>;
type Stack<'a> = Tcp<'a, 16, 128, Queue>;
type Stream<'r, 's> = tailfeather_reactor::tcp_async::Stream<'r, 's, 16, 128, Queue>;

/// Deterministic test data the lab script regenerates to verify what stock
/// Tailscale stored.
fn pattern(offset: u64) -> u8 {
    (offset.wrapping_mul(2_654_435_761) >> 13) as u8
}

/// A seekable [`pattern`] source that fails at `break_at`, like a dropped
/// link.
struct Pattern {
    offset: u64,
    break_at: Option<u64>,
}

impl embedded_io_async::ErrorType for Pattern {
    type Error = embedded_io_async::ErrorKind;
}

impl embedded_io_async::Read for Pattern {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        let end = self.break_at.unwrap_or(u64::MAX);
        if self.offset >= end {
            return Err(embedded_io_async::ErrorKind::BrokenPipe);
        }
        let len = buf
            .len()
            .min(usize::try_from(end - self.offset).unwrap_or(usize::MAX));
        for byte in &mut buf[..len] {
            *byte = pattern(self.offset);
            self.offset += 1;
        }
        Ok(len)
    }
}

impl embedded_io_async::Seek for Pattern {
    async fn seek(&mut self, pos: embedded_io_async::SeekFrom) -> Result<u64, Self::Error> {
        let embedded_io_async::SeekFrom::Start(offset) = pos else {
            return Err(embedded_io_async::ErrorKind::Unsupported);
        };
        self.offset = offset;
        Ok(offset)
    }
}

fn fnv1a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |hash, &byte| {
        (hash ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn say(line: core::fmt::Arguments<'_>) {
    static START: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let start = *START.get_or_init(std::time::Instant::now);
    eprintln!("[{:>8.3}] {line}", start.elapsed().as_secs_f64());
    println!("{line}");
    std::io::stdout().flush().unwrap();
}

/// Wait until the netmap names `peer` a Taildrop target, and return its
/// peer API: the one `taildrop_target` picks, or with `ipv6` its IPv6 one.
async fn target(runtime: &Node<'_>, peer: Ipv4Addr, ipv6: bool) -> SocketAddr {
    loop {
        let found = runtime.with_netmap(|netmap| {
            let record = netmap.peer_by_address(IpAddr::V4(peer))?;
            let target = netmap.taildrop_target(record)?;
            if ipv6 {
                record.peer_api6().map(SocketAddr::V6)
            } else {
                Some(target)
            }
        });
        if let Some(found) = found {
            return found;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

async fn connect<'r, 's>(
    runtime: &Node<'_>,
    tcp: &'r Stack<'s>,
    target: SocketAddr,
) -> Result<Stream<'r, 's>, String> {
    // The first attempts may race WireGuard handshakes.
    for attempt in 1..=20 {
        match runtime
            // Port 0: the stack picks, never reusing a just-closed tuple.
            .connect(tcp, target.ip(), target.port(), 0)
            .await
        {
            Ok(stream) => return Ok(stream),
            Err(error) => {
                say(format_args!("CONNECT attempt={attempt} err={error}"));
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }
    Err(format!("no connection to {target}"))
}

async fn upload(runtime: &Node<'_>, tcp: &Stack<'_>, peer: Ipv4Addr) -> Result<(), String> {
    let target = target(runtime, peer, false).await;
    say(format_args!("TARGET {target}"));
    let mut buffer = vec![0; 16 * 1024];
    let upload = Upload {
        peer_api: target,
        name: SEND_NAME,
        size: SEND_BYTES,
        offset: 0,
    };

    // A transfer that breaks off part way, as a dropped link would.
    let stream = connect(runtime, tcp, target).await?;
    let mut broken = Pattern {
        offset: 0,
        break_at: Some(BREAK_AT),
    };
    let first = taildrop::send_async(&mut &stream, &upload, &mut broken, &mut buffer).await;
    say(format_args!("BROKEN {first:?}"));
    let _ = stream.shutdown();
    drop(stream);
    if first.is_ok() {
        return Err("the broken upload unexpectedly completed".into());
    }
    // Let the receiver see the short body and keep what arrived.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mut source = Pattern {
        offset: 0,
        break_at: None,
    };
    // Until the receiver has seen the broken connection end, stock Tailscale
    // reports that transfer as still in progress (`409`). Its stored prefix
    // can still grow meanwhile, so each retry probes afresh.
    for attempt in 1..=20 {
        let stream = connect(runtime, tcp, target).await?;
        let offset = taildrop::resume_offset_async(
            &mut &stream,
            target,
            SEND_NAME,
            &mut source,
            &mut buffer,
        )
        .await
        .map_err(|error| format!("resume probe: {error}"))?;
        let _ = stream.shutdown();
        drop(stream);
        say(format_args!("RESUMED offset={offset}"));

        let stream = connect(runtime, tcp, target).await?;
        let resumed = Upload { offset, ..upload };
        let result = taildrop::send_async(&mut &stream, &resumed, &mut source, &mut buffer).await;
        let _ = stream.shutdown();
        match result {
            Ok(()) => return Ok(()),
            Err(taildrop::SendError::Rejected(409)) => {
                say(format_args!(
                    "RETRY attempt={attempt}: the broken transfer is still in progress"
                ));
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Err("the receiver kept the broken transfer in progress".into())
}

/// One whole upload to the peer's IPv6 peer API.
async fn upload6(runtime: &Node<'_>, tcp: &Stack<'_>, peer: Ipv4Addr) -> Result<(), String> {
    let target = target(runtime, peer, true).await;
    say(format_args!("TARGET6 {target}"));
    let mut buffer = vec![0; 16 * 1024];
    let upload = Upload {
        peer_api: target,
        name: SEND6_NAME,
        size: SEND6_BYTES,
        offset: 0,
    };
    let stream = connect(runtime, tcp, target).await?;
    let mut source = Pattern {
        offset: 0,
        break_at: None,
    };
    let result = taildrop::send_async(&mut &stream, &upload, &mut source, &mut buffer).await;
    let _ = stream.shutdown();
    result.map_err(|error| error.to_string())
}

async fn serve(
    runtime: &Node<'_>,
    tcp: &Stack<'_>,
    buffers: &mut Buffers<4>,
    send_to: Option<Ipv4Addr>,
    timeout: Duration,
) {
    let ready = async {
        let address = runtime.ready().await.unwrap();
        let address6 = runtime
            .ipv6_address()
            .map_or_else(|| "none".into(), |address| address.to_string());
        say(format_args!("READY {address} {address6}"));
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
            let addr = remote.ip();
            let peer = Peer {
                addr,
                may_send_files: runtime.with_netmap(|netmap| netmap.taildrop_allows_from(addr)),
            };
            say(format_args!("ACCEPTED from={remote}"));
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
    let send = async {
        let Some(peer) = send_to else {
            return core::future::pending::<()>().await;
        };
        runtime.ready().await.unwrap();
        match upload(runtime, tcp, peer).await {
            Ok(()) => say(format_args!("SENT ok bytes={SEND_BYTES}")),
            Err(error) => say(format_args!("SENT err={error}")),
        }
        match upload6(runtime, tcp, peer).await {
            Ok(()) => say(format_args!("SENT6 ok bytes={SEND6_BYTES}")),
            Err(error) => say(format_args!("SENT6 err={error}")),
        }
        core::future::pending::<()>().await
    };
    // Every few seconds, the state of each open connection: a stall then
    // shows up in the log as a connection whose queues stop moving.
    let trace = async {
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            tcp.trace();
        }
    };
    tokio::select! {
        result = runtime.run(tcp, buffers) => panic!("runtime stopped: {result:?}"),
        _ = trace => {},
        _ = ready => {},
        _ = receive => {},
        _ = send => {},
        _ = tokio::time::sleep(timeout) => say(format_args!("DEADLINE")),
    }
}

fn node(control_url: &str, state: PathBuf, send_to: Option<Ipv4Addr>, timeout: Duration) {
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
        peer_api_ipv6: true,
    };
    let mut node = Box::new(runtime::restore::<_, _, 4>(&config, &network, &state).unwrap());
    let runtime = Box::new(Node::new(config, &mut node, &network, &state).unwrap());
    let tcp = Box::new(Tcp::new(NetStack::new(1)));
    let mut buffers = Box::new(Buffers::new());
    executor.block_on(Box::pin(serve(
        &runtime,
        &tcp,
        &mut buffers,
        send_to,
        timeout,
    )));
}

fn main() {
    let mut args = std::env::args().skip(1);
    let control_url = args.next().expect("control URL");
    let state = PathBuf::from(args.next().expect("state directory"));
    let mut timeout = Duration::from_secs(120);
    let mut send_to = None;
    for arg in args {
        if let Some(peer) = arg.strip_prefix("--send-to=") {
            send_to = Some(peer.parse().expect("--send-to=<ipv4>"));
        } else if let Some(seconds) = arg.strip_prefix("--timeout-seconds=") {
            timeout = Duration::from_secs(seconds.parse().unwrap());
        } else {
            panic!("unknown argument: {arg}");
        }
    }
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || node(&control_url, state, send_to, timeout))
        .unwrap()
        .join()
        .unwrap();
}
