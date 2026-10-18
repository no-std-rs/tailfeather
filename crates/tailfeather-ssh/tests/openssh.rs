//! Independent OpenSSH wire interoperability, including real policy binding.
use std::future::Future;
use std::io::{Read as _, Write as _};
use std::net::{TcpListener, TcpStream};
use std::process::{Command, Stdio};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use embedded_io_async::{ErrorType, Read, Write};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};
use tailfeather::keys::NodePrivate;
use tailfeather::netmap::{Netmap, Parser};
use tailfeather_ssh::{Authorizer, Console, HostKey, Reply, TailnetAccess};

struct Stream(TcpStream);
impl ErrorType for Stream {
    type Error = std::io::Error;
}
impl Read for Stream {
    async fn read(&mut self, bytes: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(bytes)
    }
}
impl Write for Stream {
    async fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        // Deliberately short writes exercise the engine's write_all handling.
        self.0.write(&bytes[..bytes.len().min(7)])
    }
    async fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}

struct Echo {
    used: Arc<AtomicBool>,
    revoke: bool,
    access: Arc<AtomicBool>,
    bulk: bool,
}
impl Console for Echo {
    fn open(&mut self, output: &mut [u8]) -> Reply {
        if !self.bulk {
            return Reply::output(0);
        }
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = (index % 251) as u8;
        }
        Reply::exit(output.len(), 0)
    }
    fn input(&mut self, byte: u8, output: &mut [u8]) -> Reply {
        self.used.store(true, Ordering::SeqCst);
        if self.revoke {
            self.access.store(false, Ordering::SeqCst);
        }
        output[0] = byte;
        if byte == b'\n' {
            Reply::exit(1, 0)
        } else {
            Reply::output(1)
        }
    }
}

struct NoWake;
impl Wake for NoWake {
    fn wake(self: Arc<Self>) {}
}

fn blocking<F: Future>(future: F) -> F::Output {
    // The test adapter blocks inside read/write, so its future never suspends.
    let waker = Waker::from(Arc::new(NoWake));
    match std::pin::pin!(future)
        .as_mut()
        .poll(&mut Context::from_waker(&waker))
    {
        Poll::Ready(result) => result,
        Poll::Pending => panic!("blocking stream unexpectedly suspended"),
    }
}

fn run(
    username: &str,
    exec: bool,
    revoke: bool,
    bulk: bool,
) -> (std::process::Output, bool, String) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let used = Arc::new(AtomicBool::new(false));
    let server_used = used.clone();
    let worker = std::thread::spawn(move || {
        let (socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket
            .set_write_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        socket.set_nodelay(true).unwrap();
        let peer = NodePrivate::from_bytes([42; 32]).public();
        let mut key_text = [0; 128];
        let key_text = peer.encode(&mut key_text).unwrap();
        let json = format!(
            r#"{{"Node":{{"Addresses":["100.64.0.1/32"]}},"Peers":[{{"ID":1,"Key":"{key_text}","Addresses":["100.64.0.2/32"]}}],"PacketFilter":[{{"SrcIPs":["100.64.0.2/32"],"DstPorts":[{{"IP":"100.64.0.1/32","Ports":{{"First":22,"Last":22}}}}],"IPProto":[6]}}],"SSHPolicy":{{"rules":[{{"principals":[{{"nodeIP":"100.64.0.2"}}],"sshUsers":{{"console":"console"}},"action":{{"accept":true}}}}]}}}}"#
        );
        let mut map = Netmap::<1>::new();
        let mut parser = Parser::new();
        parser.push(&mut map, json.as_bytes()).unwrap();
        parser.finish(&mut map).unwrap();
        let gate = TailnetAccess {
            netmap: &map,
            peer_key: peer,
            source: "100.64.0.2".parse().unwrap(),
            destination: "100.64.0.1".parse().unwrap(),
            local_user: "console",
        };
        let live = Arc::new(AtomicBool::new(true));
        let access = |name: &str| live.load(Ordering::SeqCst) && gate.allows(name);
        let mut console = Echo {
            used: server_used,
            revoke,
            access: live.clone(),
            bulk,
        };
        let mut random = ChaCha20Rng::from_seed([7; 32]);
        let key = HostKey::from_seed(&[9; 32]);
        let mut packet = [0; tailfeather_ssh::PACKET_BUFFER];
        let mut output = vec![
            0;
            if bulk {
                2 * 1024 * 1024 + 65536
            } else {
                tailfeather_ssh::CONSOLE_BUFFER
            }
        ];
        let mut stream = Stream(socket);
        let result = blocking(tailfeather_ssh::serve(
            &mut stream,
            &mut random,
            &key,
            &access,
            &mut console,
            &mut packet,
            &mut output,
        ));
        assert!(packet.iter().all(|byte| *byte == 0));
        assert!(output.iter().all(|byte| *byte == 0));
        // Model graceful TCP close: flush our FIN and consume the client's
        // remaining control messages, avoiding an RST for unread input.
        let _ = stream.0.shutdown(std::net::Shutdown::Write);
        let _ = std::io::copy(&mut stream.0, &mut std::io::sink());
        format!("{result:?}")
    });
    let mut command = Command::new("ssh");
    command.args([
        "-F",
        "/dev/null",
        "-T",
        "-p",
        &port.to_string(),
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "BatchMode=yes",
        "-o",
        "PreferredAuthentications=none",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ConnectionAttempts=1",
        "-l",
        username,
        "127.0.0.1",
    ]);
    if exec {
        command.arg("must-not-execute");
    }
    let mut client = command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("OpenSSH is required");
    if !exec {
        let _ = client.stdin.take().unwrap().write_all(b"hello\n");
    }
    let result = client.wait_with_output().unwrap();
    let server_result = worker.join().unwrap();
    (result, used.load(Ordering::SeqCst), server_result)
}

#[test]
fn openssh_none_auth_console_round_trip_with_real_policy() {
    let (result, used, server) = run("console", false, false, false);
    assert!(
        result.status.success(),
        "{}; server={server}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"hello\n");
    assert!(used);
    assert_eq!(server, "Ok(())");
}

#[test]
fn denied_user_and_exec_cannot_reach_the_console() {
    for (username, exec) in [("root", false), ("console", true)] {
        let (result, used, _) = run(username, exec, false, false);
        assert!(!result.status.success());
        assert!(!used);
        assert!(result.stdout.is_empty());
    }
}

#[test]
fn revoked_access_prevents_further_output() {
    let (result, used, server) = run("console", false, true, false);
    assert!(used);
    assert!(!result.status.success());
    assert!(result.stdout.is_empty());
    assert!(server.contains("AccessRevoked"), "{server}");
}

#[test]
fn response_larger_than_openssh_window_survives_window_adjustments() {
    let (result, _, server) = run("console", false, false, true);
    assert!(
        result.status.success(),
        "{}; server={server}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout.len(), 2 * 1024 * 1024 + 65536);
    assert!(
        result
            .stdout
            .iter()
            .enumerate()
            .all(|(i, b)| *b == (i % 251) as u8),
        "response corrupted at a window adjustment"
    );
}

#[test]
fn standalone_no_std_server_round_trips_with_openssh() {
    // Cargo's release checks do not build the separate Bazel-only ELF fixture.
    // Keep its presence mandatory when this test runs under Bazel.
    let Some(binary) = std::env::var_os("TF_SSH_NO_STD_PROBE") else {
        assert!(
            std::env::var_os("TEST_SRCDIR").is_none(),
            "Bazel must supply TF_SSH_NO_STD_PROBE"
        );
        eprintln!("standalone fixture is exercised by the Bazel openssh_test target");
        return;
    };
    let binary = std::fs::canonicalize(binary).unwrap();
    let quoted = binary.to_str().unwrap().replace('\'', "'\"'\"'");
    let mut client = Command::new("ssh")
        .args([
            "-F",
            "/dev/null",
            "-T",
            "-o",
            &format!("ProxyCommand='{quoted}'"),
            "-o",
            "BatchMode=yes",
            "-o",
            "PreferredAuthentications=none",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "ConnectTimeout=5",
            "-l",
            "console",
            "fixture",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    client.stdin.take().unwrap().write_all(b"no-std\n").unwrap();
    let result = client.wait_with_output().unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(result.stdout, b"no-std\n");
}
