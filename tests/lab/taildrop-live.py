#!/usr/bin/env python3
"""Live, isolated Headscale + stock Tailscale <-> Tailfeather Taildrop test.

Proves both directions against the unmodified client:

* `tailscale file cp` lists the Tailfeather node as a target and uploads to
  its peer API, which stores the exact bytes under the exact name.
* The Tailfeather node finds the stock node's peer API in its netmap and
  uploads to it, breaking the first attempt off half way; a resume probe
  recovers the stored prefix, the rest follows, and `tailscale file get`
  hands back the exact bytes.
* Both again over IPv6: the Tailfeather node advertises `peerapi6`, accepts
  an upload that `tailscale nc` carries to its IPv6 address, and uploads to
  the stock node's IPv6 peer API.
* Each Tailfeather upload finishes within a bound (generous under chaos), so
  slow loss recovery fails the test instead of only slowing it down.

The Tailfeather node authorizes senders, and picks its target, from the
netmap exactly as stock Tailscale does.

Uses a separate userspace daemon with no host network changes and no access
to the user's existing tailnet or credentials. Taildrop only works between
untagged nodes of one user, so unlike the SSH lab both nodes enroll untagged.

Chaos: with TF_LAB_CHAOS set to netem options or a profile name (`jitter`,
`lossy`, `reorder`, `storm`, the same presets as the ESP exit stage), the test
re-runs itself in a private user and network namespace and impairs its
loopback, which every hop of the test crosses: control, DERP, WireGuard and
the peer API streams. TF_LAB_CHAOS_SEED (default random, always printed)
seeds netem, so the same loss, duplication and reordering replay.
"""
import argparse
import json
import os
from pathlib import Path
import random
import select
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request

CHAOS_PROFILES = {
    "jitter": "delay 15ms 15ms",
    "lossy": "delay 10ms 5ms loss 2% duplicate 0.5%",
    "reorder": "delay 25ms 20ms reorder 10% 50% duplicate 1%",
    "storm": "delay 30ms 25ms loss 3% 25% duplicate 2% reorder 10% corrupt 0.1%",
}
CHAOS_RERUN = ""


def enter_chaos_namespace():
    """Re-execute in a private network namespace with an impaired loopback."""
    global CHAOS_RERUN
    profile = os.environ.get("TF_LAB_CHAOS")
    if not profile:
        return
    seed = os.environ.get("TF_LAB_CHAOS_SEED") or str(random.randrange(1, 1 << 31))
    CHAOS_RERUN = f"TF_LAB_CHAOS={profile!r} TF_LAB_CHAOS_SEED={seed}"
    if os.environ.get("TF_LAB_CHAOS_INSIDE"):
        return
    options = CHAOS_PROFILES.get(profile, profile)
    print(f"CHAOS {options} seed={seed} (reproduce with {CHAOS_RERUN})", flush=True)
    # tailscaled pauses control while it sees no default route, so give the
    # namespace a dummy uplink. Every hop of the test stays on loopback.
    setup = ("ip link set lo up && ip link add uplink type dummy && "
             "ip addr add 192.0.2.10/24 dev uplink && ip link set uplink up && "
             "ip route add default via 192.0.2.1 dev uplink && "
             f"tc qdisc add dev lo root netem limit 10000 {options} seed {seed}")
    env = dict(os.environ, TF_LAB_CHAOS_INSIDE="1", TF_LAB_CHAOS_SEED=seed)
    unshare = shutil.which("unshare")
    if not unshare:
        raise SystemExit("TF_LAB_CHAOS needs util-linux unshare")
    os.execve(unshare, [unshare, "--user", "--map-root-user", "--net", "sh", "-c",
                        f'{setup} && exec "$@"', "sh", sys.executable, *sys.argv], env)


SEND_NAME = "from-tailfeather.bin"
SEND_BYTES = 300_000
BREAK_AT = 150_000
SEND6_NAME = "from-tailfeather-v6.bin"
SEND6_BYTES = 100_000
NC_NAME = "over ipv6.bin"
NC_BYTES = 50_000
# Seconds from the broken first attempt to the finished resumed upload. Clean
# runs take well under a second, the storm profile about one to five.
UPLOAD_BOUND = 30


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
    enter_chaos_namespace()
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
            # Impaired links legitimately need longer; a hang still fails.
            deadline = time.monotonic() + seconds * (4 if CHAOS_RERUN else 1)
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
            stock_ip = stock_api.rsplit(":", 1)[0]
            version = subprocess.check_output(client + ["version"], env=client_env, timeout=5).decode().splitlines()[0]
            print(f"TAILSCALE {version} peerapi={stock_api}", flush=True)

            env = dict(os.environ, TF_TEST_AUTH_KEY=keys.pop(), TF_TEST_CA_DER=str(tls_dir / "ca.der"))
            node = spawn([
                str(node_binary), f"https://127.0.0.1:{tls_port}", str(state / "node"),
                f"--send-to={stock_ip}", f"--timeout-seconds={600 if CHAOS_RERUN else 150}",
            ], "node", env=env)
            del env
            node_log = state / "node.log"

            def node_line(prefix):
                return next((line for line in node_log.read_text().splitlines() if line.startswith(prefix)), None)

            _, address, address6 = wait_for(lambda: node_line("READY "), node,
                                            "Tailfeather registration and netmap").split()
            print(f"READY {address} {address6}", flush=True)
            assert address6 != "none", "control assigned no IPv6 address"

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

            # The peer API is advertised for both families.
            urls = peer_status().get("PeerAPIURL") or []
            assert f"http://[{address6}]:5254" in urls, urls

            # Stock -> Tailfeather over IPv6. The CLI always picks the IPv4
            # peer API, so carry a raw upload to the IPv6 one with
            # `tailscale nc`, which dials through the daemon's tailnet stack.
            stock_ip6 = next(ip for ip in status()["Self"]["TailscaleIPs"] if ":" in ip)
            body = os.urandom(NC_BYTES)
            request = (f"PUT /v0/put/{urllib.parse.quote(NC_NAME)} HTTP/1.1\r\n"
                       f"Host: [{address6}]:5254\r\nContent-Length: {len(body)}\r\n"
                       "Connection: close\r\n\r\n").encode() + body
            before = node_log.read_text().count("RECEIVED ")
            # `tailscale nc` ends the whole connection at end of input, so keep
            # its input open until the response head has arrived.
            nc = subprocess.Popen(client + ["nc", address6, "5254"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=client_env)
            try:
                nc.stdin.write(request)
                nc.stdin.flush()
                reply = b""
                deadline = time.monotonic() + 60 * (4 if CHAOS_RERUN else 1)
                while b"\r\n\r\n" not in reply and time.monotonic() < deadline:
                    if select.select([nc.stdout], [], [], 0.5)[0]:
                        chunk = os.read(nc.stdout.fileno(), 4096)
                        if not chunk:
                            break
                        reply += chunk
            finally:
                nc.kill()
                stderr = nc.communicate()[1]
            reply = reply.decode(errors="replace")
            assert reply.startswith("HTTP/1.1 200"), f"`tailscale nc` upload: {reply!r} {stderr!r}"
            received6 = wait_for(lambda: node_log.read_text().count("RECEIVED ") > before and
                                 [line for line in node_log.read_text().splitlines()
                                  if line.startswith("RECEIVED ")][-1], node, "Tailfeather receipt over IPv6")
            print(received6, flush=True)
            expected = f"RECEIVED name={NC_NAME} bytes={len(body)} fnv={fnv1a(body):016x} from={stock_ip6}"
            assert received6 == expected, f"{received6!r} != {expected!r}"

            # Tailfeather -> stock, found through the netmap and resumed.
            sent = wait_for(lambda: node_line("SENT "), node, "Tailfeather upload", seconds=60)
            progress = [line for line in node_log.read_text().splitlines()
                        if line.startswith(("TARGET ", "RESUMED ", "RETRY "))]
            print("\n".join(progress), flush=True)
            print(sent, flush=True)
            assert node_line("TARGET ") == f"TARGET {stock_api}", node_line("TARGET ")
            # On a clean link the receiver keeps exactly the bytes sent before
            # the break; under chaos some may still have been in flight. Either
            # way the probe must find a stored prefix, and the content check
            # below proves the resumed file is exact.
            offsets = [int(line.split("=")[1]) for line in progress if line.startswith("RESUMED ")]
            assert offsets and all(0 <= offset <= BREAK_AT for offset in offsets), progress
            if not CHAOS_RERUN:
                assert offsets == [BREAK_AT], progress
            # Under chaos the receiver may end the broken transfer with an
            # error first, and then discards its partial file as stock
            # Tailscale does: a later probe then rightly finds nothing.
            assert sent == f"SENT ok bytes={SEND_BYTES}", sent
            # How long loss recovery took, from the node's timestamped log.
            stamps = {}
            for line in node_log.read_text().splitlines():
                if line.startswith("[") and "] " in line:
                    stamp, event = line[1:].split("] ", 1)
                    stamps.setdefault(event.split()[0], float(stamp))
            took = stamps["SENT"] - stamps["BROKEN"]
            print(f"TIMING broken-to-sent={took:.2f}s", flush=True)
            assert took < UPLOAD_BOUND, f"the resumed upload took {took:.1f}s (bound {UPLOAD_BOUND}s)"

            # Tailfeather -> stock's IPv6 peer API.
            sent6 = wait_for(lambda: node_line("SENT6 "), node, "Tailfeather upload over IPv6", seconds=60)
            print(node_line("TARGET6 "), flush=True)
            print(sent6, flush=True)
            stock_api6 = next(urllib.parse.urlsplit(url).netloc for url in status()["Self"]["PeerAPIURL"]
                              if urllib.parse.urlsplit(url).hostname == stock_ip6)
            assert node_line("TARGET6 ") == f"TARGET6 {stock_api6}", (node_line("TARGET6 "), stock_api6)
            assert sent6 == f"SENT6 ok bytes={SEND6_BYTES}", sent6
            inbox = state / "inbox"
            inbox.mkdir()

            def fetched():
                subprocess.run(client + ["file", "get", str(inbox)], env=client_env, capture_output=True, timeout=15)
                return (inbox / SEND_NAME).exists() and (inbox / SEND6_NAME).exists()
            wait_for(fetched, daemon, "`tailscale file get` of the Tailfeather uploads")
            for name, size in [(SEND_NAME, SEND_BYTES), (SEND6_NAME, SEND6_BYTES)]:
                data = (inbox / name).read_bytes()
                assert data == pattern(size), f"{name}: stored {len(data)} bytes, fnv={fnv1a(data):016x}"
            print("PASS: stock tailscale and Tailfeather exchanged Taildrop files in both directions "
                  "over IPv4 and IPv6, with netmap authorization and discovery and a resumed upload")
        except Exception:
            if CHAOS_RERUN:
                print(f"--- reproduce with: {CHAOS_RERUN} ---", flush=True)
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
            # Keep the logs, timestamped node log included, as test outputs.
            outputs = os.environ.get("TEST_UNDECLARED_OUTPUTS_DIR")
            if outputs:
                for log in logs:
                    shutil.copyfile(log, Path(outputs) / log.name)


if __name__ == "__main__":
    main()
