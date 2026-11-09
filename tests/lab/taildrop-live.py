#!/usr/bin/env python3
"""Live, isolated Headscale + stock Tailscale <-> Tailfeather Taildrop test.

Proves both directions against the unmodified client:

* `tailscale file cp` lists the Tailfeather node as a target and uploads to
  its peer API, which stores the exact bytes under the exact name.
* The Tailfeather node uploads to the stock node's peer API, and
  `tailscale file get` hands back the exact bytes.

Uses a separate userspace daemon with no host network changes and no access
to the user's existing tailnet or credentials. Taildrop only works between
untagged nodes of one user, so unlike the SSH lab both nodes enroll untagged.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request

SEND_NAME = "from-tailfeather.bin"
SEND_BYTES = 300_000


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def tls_proxy(listener, context, upstream_port):
    """Terminate TLS on loopback and forward to Headscale's plain listener.

    Serves both the reactor's HTTPS control connection and DERP for both
    nodes, like the privileged labs' socat terminator, without host tools.
    """
    def pipe(source, sink):
        try:
            while data := source.recv(65536):
                sink.sendall(data)
        except OSError:
            pass
        finally:
            for sock in (source, sink):
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def handle(raw):
        try:
            client = context.wrap_socket(raw, server_side=True)
            upstream = socket.create_connection(("127.0.0.1", upstream_port))
        except OSError:
            raw.close()
            return
        threading.Thread(target=pipe, args=(client, upstream), daemon=True).start()
        pipe(upstream, client)

    while True:
        try:
            raw, _ = listener.accept()
        except OSError:
            return
        threading.Thread(target=handle, args=(raw,), daemon=True).start()


def fnv1a(data):
    value = 0xCBF29CE484222325
    for byte in data:
        value = ((value ^ byte) * 0x100000001B3) & 0xFFFFFFFFFFFFFFFF
    return value


def pattern(length):
    """The node's `pattern` upload data, regenerated for comparison."""
    mask = (1 << 64) - 1
    return bytes((((offset * 2_654_435_761) & mask) >> 13) & 0xFF for offset in range(length))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headscale", required=True)
    parser.add_argument("--node", default="crates/tailfeather-reactor/target/debug/examples/taildrop_node")
    parser.add_argument("--config", default=None, help="base Headscale YAML")
    parser.add_argument("--tls-ca", default=None, help="loopback TLS fixture's ca.pem; its siblings are used too")
    parser.add_argument("--tailscale", default="tailscale")
    parser.add_argument("--tailscaled", default="tailscaled")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    node_binary = Path(args.node).resolve()
    with tempfile.TemporaryDirectory(prefix="tailfeather-taildrop-live-") as directory:
        state = Path(directory)
        (state / "logs").mkdir()
        (state / "config").mkdir()
        tls_dir = Path(args.tls_ca).parent if args.tls_ca else root / "tests/lab/loopback-tls"
        client_env = dict(os.environ, XDG_CONFIG_HOME=str(state / "config"),
                          SSL_CERT_FILE=str(tls_dir / "ca.pem"))
        headscale = state / "headscale"
        shutil.copyfile(args.headscale, headscale)
        headscale.chmod(0o700)
        control_port = port()
        stun_port = port(socket.SOCK_DGRAM)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(tls_dir / "server.pem", tls_dir / "server.key")
        listener = socket.create_server(("127.0.0.1", 0))
        tls_port = listener.getsockname()[1]
        threading.Thread(target=tls_proxy, args=(listener, context, control_port), daemon=True).start()
        # Verified TLS for DERP too: the embedded relay is reached through the
        # terminator, and both nodes trust only the fixture CA.
        (state / "derp.yaml").write_text(
            "regions:\n  999:\n    regionid: 999\n    regioncode: lab\n    regionname: Taildrop lab\n"
            "    nodes:\n      - name: lab\n        regionid: 999\n        hostname: 127.0.0.1\n"
            f"        ipv4: 127.0.0.1\n        derpport: {tls_port}\n        stunport: {stun_port}\n"
        )
        config = Path(args.config or root / "tests/lab/headscale.yaml").read_text()
        config = config.replace("/tmp/tailfeather-lab/headscale", str(state / "headscale-state"))
        config = config.replace("http://127.0.0.1:8080", f"http://127.0.0.1:{control_port}")
        config = config.replace("0.0.0.0:8080", f"127.0.0.1:{control_port}")
        config = config.replace("0.0.0.0:9090", "127.0.0.1:0")
        config = config.replace("0.0.0.0:50443", "127.0.0.1:0")
        config = config.replace("0.0.0.0:3478", f"127.0.0.1:{stun_port}")
        config = config.replace("automatically_add_embedded_derp_region: true", "automatically_add_embedded_derp_region: false")
        config = config.replace("paths: []", f"paths: ['{state / 'derp.yaml'}']")
        config = config.replace("mode: database", f"mode: file\n  path: {state / 'policy.json'}")
        config = config.replace("level: debug", "level: info")
        config += f"\nunix_socket: {state / 'headscale.sock'}\nunix_socket_permission: '0700'\n"
        config += "\ntaildrop:\n  enabled: true\n"
        (state / "headscale-state").mkdir()
        (state / "headscale.yaml").write_text(config)
        (state / "policy.json").write_text(json.dumps({
            "acls": [{"action": "accept", "src": ["live@"], "dst": ["live@:*"]}],
        }))
        hs = [str(headscale), "--config", str(state / "headscale.yaml")]
        processes = []
        logs = []

        def spawn(command, name, env=None):
            log = state / f"{name}.log"
            logs.append(log)
            with log.open("wb") as output:
                process = subprocess.Popen(command, stdout=output, stderr=subprocess.STDOUT, env=env)
            processes.append(process)
            return process

        def wait_for(predicate, process, description, seconds=45):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                result = predicate()
                if result:
                    return result
                if process.poll() is not None:
                    raise RuntimeError(f"{description}: process exited {process.returncode}")
                time.sleep(0.2)
            raise TimeoutError(description)

        def hs_json(*command):
            result = subprocess.run(hs + list(command) + ["--output", "json"], capture_output=True, check=True, timeout=15)
            return json.loads(result.stdout)

        try:
            coordinator = spawn(hs + ["serve"], "headscale")

            def healthy():
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{control_port}/health", timeout=1) as response:
                        return response.status == 200
                except OSError:
                    return False

            wait_for(healthy, coordinator, "Headscale startup")
            user = hs_json("users", "create", "live")
            keys = [
                hs_json("preauthkeys", "create", "--user", str(user["id"]), "--expiration", "10m")["key"]
                for _ in range(2)
            ]
            sock = state / "tailscaled.sock"
            daemon = spawn([
                args.tailscaled, "--tun=userspace-networking", f"--socket={sock}",
                f"--statedir={state / 'tailscale'}", "--port=0",
            ], "tailscaled", env=dict(client_env, TS_NO_LOGS_NO_SUPPORT="1", TS_LOGS_DIR=str(state / "logs")))
            wait_for(sock.exists, daemon, "Tailscale startup")
            client = [args.tailscale, f"--socket={sock}"]
            # Pass the disposable credential through an inherited pipe, never
            # through argv, a generated source file, or terminal output.
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, keys.pop().encode())
                os.close(write_fd)
                subprocess.run(client + [
                    "up", f"--login-server=http://127.0.0.1:{control_port}",
                    f"--auth-key=file:/proc/self/fd/{read_fd}", "--hostname=real-tailscale",
                    "--accept-dns=false", "--accept-routes=false",
                ], pass_fds=(read_fd,), capture_output=True, check=True, timeout=45)
            finally:
                os.close(read_fd)

            def status():
                return json.loads(subprocess.check_output(client + ["status", "--json"], env=client_env, timeout=5))

            def stock_peer_api():
                for url in status()["Self"].get("PeerAPIURL") or []:
                    parsed = urllib.parse.urlsplit(url if "://" in url else f"http://{url}")
                    if parsed.hostname and "." in parsed.hostname:
                        return f"{parsed.hostname}:{parsed.port}"
                return None

            stock_api = wait_for(stock_peer_api, daemon, "stock peer API listener")
            version = subprocess.check_output(client + ["version"], env=client_env, timeout=5).decode().splitlines()[0]
            print(f"TAILSCALE {version} peerapi={stock_api}", flush=True)

            env = dict(os.environ, TF_TEST_AUTH_KEY=keys.pop(), TF_TEST_CA_DER=str(tls_dir / "ca.der"))
            node = spawn([
                str(node_binary), f"https://127.0.0.1:{tls_port}", str(state / "node"),
                f"--send={stock_api}", "--timeout-seconds=150",
            ], "node", env=env)
            del env
            node_log = state / "node.log"

            def node_line(prefix):
                return next((line for line in node_log.read_text().splitlines() if line.startswith(prefix)), None)

            address = wait_for(lambda: node_line("READY "), node, "Tailfeather registration and netmap").split()[1]
            print(f"READY {address}", flush=True)

            # Stock -> Tailfeather. The CLI only offers peers that advertise a
            # peer API, are online and belong to the same user.
            def peer_status():
                return next((peer for peer in (status().get("Peer") or {}).values()
                             if address in peer.get("TailscaleIPs", [])), None)

            def is_target():
                peer = peer_status()
                if not peer or not peer.get("Online"):
                    return False
                output = subprocess.run(client + ["file", "cp", "--targets"], env=client_env,
                                        capture_output=True, timeout=10).stdout.decode()
                return address in output
            try:
                wait_for(is_target, daemon, "online Tailfeather node listed by `tailscale file cp --targets`")
            except TimeoutError:
                print(json.dumps(peer_status(), indent=1), flush=True)
                raise

            payload = os.urandom(200_000)
            name = "hello wörld #1.bin"
            upload = state / "outbox" / name
            upload.parent.mkdir()
            upload.write_bytes(payload)
            result = subprocess.run(client + ["file", "cp", str(upload), f"{address}:"], env=client_env,
                                    capture_output=True, timeout=60)
            assert result.returncode == 0, f"tailscale file cp exited {result.returncode}: {result.stderr.decode(errors='replace')}"
            received = wait_for(lambda: node_line("RECEIVED "), node, "Tailfeather receipt")
            print(received, flush=True)
            expected = f"RECEIVED name={name} bytes={len(payload)} fnv={fnv1a(payload):016x} "
            assert received.startswith(expected), f"{received!r} != {expected!r}..."

            # Tailfeather -> stock.
            sent = wait_for(lambda: node_line("SENT "), node, "Tailfeather upload", seconds=60)
            print(sent, flush=True)
            assert sent == f"SENT ok bytes={SEND_BYTES}", sent
            inbox = state / "inbox"
            inbox.mkdir()

            def fetched():
                subprocess.run(client + ["file", "get", str(inbox)], env=client_env, capture_output=True, timeout=15)
                return (inbox / SEND_NAME).exists()
            wait_for(fetched, daemon, "`tailscale file get` of the Tailfeather upload")
            data = (inbox / SEND_NAME).read_bytes()
            assert data == pattern(SEND_BYTES), f"stored {len(data)} bytes, fnv={fnv1a(data):016x}"
            print("PASS: stock tailscale and Tailfeather exchanged Taildrop files in both directions")
        except Exception:
            for log in logs:
                print(f"--- {log.name} ---", flush=True)
                print(log.read_text(errors="replace")[-16000:], flush=True)
            raise
        finally:
            for process in reversed(processes):
                if process.poll() is None:
                    process.terminate()
            for process in reversed(processes):
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


if __name__ == "__main__":
    main()
