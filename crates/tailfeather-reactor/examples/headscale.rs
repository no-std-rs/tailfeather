//! Real Headscale exercise of the shared runtime with fixed or owned TCP arenas.
//! The argument is a private fixture directory; credentials are read from files.
use embedded_io_async::{Read, Write};
use std::{path::Path, time::Duration};
use tailfeather_reactor::{
    exec::Reactor,
    native::{FileState, TokioNetwork},
    runtime::{self, Buffers, Config, Runtime},
    tcp::{NetStack, Packet, PacketQueue, Storage},
    tcp_async::Tcp,
};

fn config<'a>(name: &'a str, key: &'a str, ca: &'a [u8], control_url: &'a str) -> Config<'a> {
    Config {
        control_url,
        hostname: name,
        auth_key: key,
        control_ca_der: ca,
        relay_only: !std::env::args().any(|arg| arg == "--direct"),
        ephemeral: true,
        os: std::env::consts::OS,
    }
}

async fn pair<'a, B: PacketQueue<32>>(
    root: &Path,
    keys: &[String],
    server_tcp: NetStack<'a, 8, 32, B>,
    client_tcp: NetStack<'a, 8, 32, B>,
) {
    let ca = std::fs::read(root.join("ca.der")).unwrap();
    let control_url = std::env::var("TAILFEATHER_FIXTURE_CONTROL_URL")
        .unwrap_or_else(|_| "https://localhost:18443".into());
    let server_network = TokioNetwork::bind(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .await
        .unwrap();
    let client_network = TokioNetwork::bind(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .await
        .unwrap();
    let server_state = FileState::open(&root.join("reactor-server")).unwrap();
    let client_state = FileState::open(&root.join("reactor-client")).unwrap();
    let server_config = config("reactor-server", &keys[0], &ca, &control_url);
    let client_config = config("reactor-client", &keys[1], &ca, &control_url);
    let mut server_node =
        runtime::restore::<_, _, 4>(&server_config, &server_network, &server_state).unwrap();
    let mut client_node =
        runtime::restore::<_, _, 4>(&client_config, &client_network, &client_state).unwrap();
    let server = Runtime::<_, _, 4, 32>::new(
        server_config,
        &mut server_node,
        &server_network,
        &server_state,
    )
    .unwrap();
    let client = Runtime::<_, _, 4, 32>::new(
        client_config,
        &mut client_node,
        &client_network,
        &client_state,
    )
    .unwrap();
    let server_tcp = Tcp::new(server_tcp);
    let client_tcp = Tcp::new(client_tcp);
    let mut server_buffers = Buffers::new();
    let mut client_buffers = Buffers::new();
    let traffic = async {
        let (server_ip, client_ip) = tokio::join!(server.ready(), client.ready());
        client_ip.unwrap();
        let server_ip = server_ip.unwrap();
        println!("PASS: shared runtime registration and map updates");
        if std::env::args().any(|arg| arg == "--offline-direct") {
            println!("READY: stop the fixture, then create continue in its directory");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            while !root.join("continue").exists() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let mut listener = server.listen(&server_tcp, 2222).await.unwrap();
        let (from, to) = tokio::join!(
            client.connect(&client_tcp, server_ip, 2222, 49152),
            listener.accept()
        );
        let mut from = from.unwrap();
        let mut to = to.unwrap();
        let payload = [0x5a; 16384];
        let send = async {
            for _ in 0..64 {
                from.write_all(&payload).await.unwrap();
            }
            from.shutdown().unwrap();
        };
        let receive = async {
            let mut received = [0; 8192];
            let mut total = 0;
            loop {
                let len = to.read(&mut received).await.unwrap();
                if len == 0 {
                    break;
                }
                assert!(received[..len].iter().all(|byte| *byte == 0x5a));
                total += len;
            }
            assert_eq!(total, 1024 * 1024);
            to.write_all(b"response-after-half-close").await.unwrap();
            to.shutdown().unwrap();
        };
        tokio::join!(send, receive);
        let mut response = [0; 25];
        from.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"response-after-half-close");
        assert_eq!(from.read(&mut response).await.unwrap(), 0);
        drop(from);
        drop(to);
        drop(listener);
        let client_clock = Reactor::with_clock(&client_network);
        let server_clock = Reactor::with_clock(&server_network);
        let (a, b) = tokio::join!(
            client_tcp.drain(&client_clock),
            server_tcp.drain(&server_clock)
        );
        a.unwrap();
        b.unwrap();
        println!(
            "PASS: shared runtime encrypted 1 MiB transfer, half-close response and acknowledged drain"
        );
    };
    tokio::select! {
        result = server.run(&server_tcp, &mut server_buffers) => panic!("server stopped: {result:?}"),
        result = client.run(&client_tcp, &mut client_buffers) => panic!("client stopped: {result:?}"),
        _ = traffic => {},
        _ = tokio::time::sleep(Duration::from_secs(100)) => panic!("shared runtime fixture deadline"),
    }
}

fn main() {
    let root = std::path::PathBuf::from(std::env::args_os().nth(1).expect("fixture directory"));
    let keys: Vec<String> =
        serde_json::from_slice(&std::fs::read(root.join("keys.json")).unwrap()).unwrap();
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            if std::env::args().any(|arg| arg == "--owned") {
                type Stack = NetStack<'static, 8, 32, std::collections::VecDeque<Packet>>;
                runtime.block_on(Box::pin(pair(&root, &keys, Stack::new(1), Stack::new(2))));
            } else {
                let mut a = Box::new(Storage::<8, 65536>::new());
                let mut b = Box::new(Storage::<8, 65536>::new());
                runtime.block_on(Box::pin(pair(
                    &root,
                    &keys,
                    NetStack::<8, 32>::with_storage(1, &mut a),
                    NetStack::<8, 32>::with_storage(2, &mut b),
                )));
            }
            if !std::env::args().any(|arg| arg == "--offline-direct") {
                runtime.block_on(Box::pin(reconnect(&root, false)));
                runtime.block_on(Box::pin(reconnect(&root, true)));
            }
        })
        .unwrap()
        .join()
        .unwrap();
}

async fn reconnect(root: &Path, rejected: bool) {
    let ca = std::fs::read(root.join("ca.der")).unwrap();
    let url = std::env::var("TAILFEATHER_FIXTURE_CONTROL_URL").unwrap();
    let name = if rejected {
        "reactor-rejected"
    } else {
        "reactor-client"
    };
    let state = FileState::open(&root.join(name)).unwrap();
    let network = TokioNetwork::bind(std::net::Ipv4Addr::UNSPECIFIED, 0)
        .await
        .unwrap();
    let config = config(
        name,
        if rejected { "fixture-invalid-key" } else { "" },
        &ca,
        &url,
    );
    let mut node = runtime::restore::<_, _, 4>(&config, &network, &state).unwrap();
    let runtime = Runtime::<_, _, 4, 8>::new(config, &mut node, &network, &state).unwrap();
    let mut storage = Storage::<4, 1024>::new();
    let tcp = Tcp::new(NetStack::<4, 4>::with_storage(3, &mut storage));
    let mut buffers = Buffers::new();
    tokio::select! {
        result = async {
            let result = runtime.run(&tcp, &mut buffers).await;
            assert_eq!(result, Err("registration rejected"));
            assert!(rejected);
        } => result,
        result = runtime.ready() => {
            if rejected { assert_eq!(result, Err("registration rejected")); }
            else { result.unwrap(); }
        },
        _ = tokio::time::sleep(Duration::from_secs(60)) => panic!("reconnect readiness deadline"),
    }
    println!(
        "PASS: shared runtime {}",
        if rejected {
            "rejects invalid enrollment"
        } else {
            "reconnects using durable identity without an auth key"
        }
    );
}
