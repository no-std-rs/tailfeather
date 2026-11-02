//! One shared-runtime node for the privileged NAT lab.
//!
//! `lab_node <control-url> <state-directory> [--timeout-seconds=N]`
//!
//! The single-use enrollment key is read from `TF_TEST_AUTH_KEY` and an
//! optional private control CA (DER) from the path in `TF_TEST_CA_DER`. The
//! node prints `UDP_BOUND port=<port>`, then `READY <address>` once mapped,
//! and serves the tailnet (disco, WireGuard, DERP) until the deadline.
use std::{io::Write as _, path::PathBuf, time::Duration};
use tailfeather_reactor::{
    native::{FileState, TokioNetwork},
    runtime::{self, Buffers, Config, Network as _, Runtime},
    tcp::{NetStack, Storage},
    tcp_async::Tcp,
};

async fn serve(control_url: &str, state: PathBuf, timeout: Duration) {
    let key = std::env::var("TF_TEST_AUTH_KEY").expect("TF_TEST_AUTH_KEY");
    let ca = std::env::var_os("TF_TEST_CA_DER")
        .map(|path| std::fs::read(path).expect("control CA"))
        .unwrap_or_default();
    std::fs::create_dir_all(&state).unwrap();
    let state = FileState::open(&state).unwrap();
    let network = TokioNetwork::bind(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .await
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
    };
    let mut node = runtime::restore::<_, _, 4>(&config, &network, &state).unwrap();
    let runtime = Runtime::<_, _, 4, 32>::new(config, &mut node, &network, &state).unwrap();
    let mut storage = Box::new(Storage::<8, 65536>::new());
    let tcp = Tcp::new(NetStack::<8, 32>::with_storage(1, &mut storage));
    let mut buffers = Box::new(Buffers::new());
    let ready = async {
        let address = runtime.ready().await.unwrap();
        println!("READY {address}");
        std::io::stdout().flush().unwrap();
        core::future::pending::<()>().await
    };
    tokio::select! {
        result = runtime.run(&tcp, &mut buffers) => panic!("runtime stopped: {result:?}"),
        _ = ready => {},
        _ = tokio::time::sleep(timeout) => println!("DEADLINE"),
    }
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
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(Box::pin(serve(&control_url, state, timeout)));
        })
        .unwrap()
        .join()
        .unwrap();
}
