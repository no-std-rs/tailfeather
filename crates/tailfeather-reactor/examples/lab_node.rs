//! One shared-runtime node for the privileged NAT lab.
//!
//! `lab_node <control-url> <state-directory> [--timeout-seconds=N]`
//!
//! The single-use enrollment key is read from `TF_TEST_AUTH_KEY` and an
//! optional private control CA (DER) from the path in `TF_TEST_CA_DER`. The
//! node prints `UDP_BOUND port=<port>`, then `READY <address>` once mapped,
//! and serves the tailnet (disco, WireGuard, DERP) until the deadline.
//!
//! For throughput measurements it also serves two bulk TCP ports on its
//! tailnet address: 5001 discards everything it receives and answers `done`
//! after the sender's FIN; 5002 sends `TF_BULK_BYTES` (default 256 MiB) of
//! zeros and closes.
use embedded_io_async::{Read as _, Write as _};
use std::{io::Write as _, path::PathBuf, time::Duration};
use tailfeather_reactor::{
    native::{FileState, TokioNetwork},
    runtime::{self, Buffers, Config, Network as _, Runtime},
    tcp::{NetStack, OWNED_BUFFER},
    tcp_async::Tcp,
};

type Node<'a> = Runtime<'a, TokioNetwork, FileState, 4, 32>;
/// The hosted adapters' heap-backed TCP stack.
type Stream<'a> = Tcp<'a, 16, 128, std::collections::VecDeque<tailfeather_reactor::tcp::Packet>>;

/// Only small futures live here. The runtime, TCP stack and buffers are
/// built before, on the worker thread: a large value constructed inside an
/// async fn becomes part of its poll function's stack frame, which every
/// poll then reserves and probes page by page.
async fn serve(runtime: &Node<'_>, tcp: &Stream<'_>, buffers: &mut Buffers<4>, timeout: Duration) {
    let ready = async {
        let address = runtime.ready().await.unwrap();
        println!("READY {address}");
        std::io::stdout().flush().unwrap();
        core::future::pending::<()>().await
    };
    let bulk_bytes: usize = std::env::var("TF_BULK_BYTES")
        .map_or(256 << 20, |value| value.parse().expect("TF_BULK_BYTES"));
    let sink = async {
        let mut listener = tcp.listen(5001).unwrap();
        let mut buffer = vec![0; 65536];
        loop {
            let Ok(stream) = listener.accept().await else {
                continue;
            };
            let mut total = 0usize;
            while let Ok(len @ 1..) = (&stream).read(&mut buffer).await {
                total += len;
            }
            let _ = (&stream).write_all(b"done\n").await;
            let _ = stream.shutdown();
            println!("BULK sink bytes={total}");
        }
    };
    let source = async {
        let mut listener = tcp.listen(5002).unwrap();
        let buffer = vec![0; 65536];
        loop {
            let Ok(stream) = listener.accept().await else {
                continue;
            };
            let mut remaining = bulk_bytes;
            while remaining != 0 {
                let len = remaining.min(buffer.len());
                if (&stream).write_all(&buffer[..len]).await.is_err() {
                    break;
                }
                remaining -= len;
            }
            let _ = stream.shutdown();
            println!("BULK source bytes={}", bulk_bytes - remaining);
        }
    };
    tokio::select! {
        result = runtime.run(tcp, buffers) => panic!("runtime stopped: {result:?}"),
        _ = ready => {},
        _ = sink => {},
        _ = source => {},
        _ = tokio::time::sleep(timeout) => println!("DEADLINE"),
    }
}

fn node(control_url: &str, state: PathBuf, timeout: Duration) {
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
    println!(
        "UDP_BOUND port={}",
        network.local_endpoint().unwrap().port()
    );
    let config = Config {
        control_url,
        hostname: "reactor-node",
        auth_key: &key,
        control_ca_der: &ca,
        relay_only: false,
        ephemeral: true,
        os: std::env::consts::OS,
        peer_api_port: None,
    };
    let mut node = Box::new(runtime::restore::<_, _, 4>(&config, &network, &state).unwrap());
    let runtime = Box::new(Node::new(config, &mut node, &network, &state).unwrap());
    // TF_TCP_BUFFER overrides the per-connection buffer (and window) bytes.
    let bytes = std::env::var("TF_TCP_BUFFER")
        .map_or(OWNED_BUFFER, |value| value.parse().expect("TF_TCP_BUFFER"));
    let tcp = Box::new(Tcp::new(NetStack::with_buffer_size(1, bytes)));
    let mut buffers = Box::new(Buffers::new());
    executor.block_on(Box::pin(serve(&runtime, &tcp, &mut buffers, timeout)));
}

fn main() {
    let mut args = std::env::args().skip(1);
    let control_url = args.next().expect("control URL");
    let state = PathBuf::from(args.next().expect("state directory"));
    let mut timeout = Duration::from_secs(300);
    for arg in args {
        let seconds = arg
            .strip_prefix("--timeout-seconds=")
            .unwrap_or_else(|| panic!("unknown argument: {arg}"));
        timeout = Duration::from_secs(seconds.parse().unwrap());
    }
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || node(&control_url, state, timeout))
        .unwrap()
        .join()
        .unwrap();
}
