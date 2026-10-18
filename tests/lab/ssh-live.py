#!/usr/bin/env python3
"""Live, isolated Headscale + real tailscale ssh -> Tailfeather test.

Requires the repository-pinned Headscale binary, tailscale/tailscaled, and the
live_server Cargo example. Uses a separate userspace daemon, with no host
network changes and no access to the user's existing tailnet or credentials.
"""
import argparse
import json
import os
import pty
from pathlib import Path
import shutil
import select
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request


def port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def terminal_ssh(command, message, env):
    """Give the default client a real controlling terminal, without -T."""
    pid, master = pty.fork()
    if pid == 0:
        try:
            os.execvpe(command[0], command, env)
        except OSError:
            os._exit(127)
    output = bytearray()
    status = None
    sent = False
    deadline = time.monotonic() + 40
    try:
        while time.monotonic() < deadline:
            ready, _, _ = select.select([master], [], [], 0.1)
            if ready:
                try:
                    chunk = os.read(master, 65536)
                except OSError as error:
                    if error.errno != 5:  # Linux PTYs report EIO after exit.
                        raise
                    chunk = b""
                output.extend(chunk)
            if not sent and b"Tailfeather live console" in output:
                os.write(master, message)
                sent = True
            if status is None:
                exited, result = os.waitpid(pid, os.WNOHANG)
                if exited:
                    status = result
            if status is not None and (not ready or not chunk):
                return subprocess.CompletedProcess(command, os.waitstatus_to_exitcode(status), bytes(output), b"")
        raise TimeoutError("interactive tailscale ssh:\n" + output.decode(errors="replace"))
    finally:
        os.close(master)
        if status is None:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--headscale", required=True)
    parser.add_argument("--server", default="target/debug/examples/live_server")
    parser.add_argument("--config", default=None, help="base Headscale YAML")
    parser.add_argument("--tailscale", default="tailscale")
    parser.add_argument("--tailscaled", default="tailscaled")
    parser.add_argument("--interactive", action="store_true", help="use a real terminal and default PTY negotiation")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    server = Path(args.server).resolve()
    with tempfile.TemporaryDirectory(prefix="tailfeather-ssh-live-") as directory:
        state = Path(directory)
        (state / "logs").mkdir()
        (state / "config").mkdir()
        client_env = dict(os.environ, XDG_CONFIG_HOME=str(state / "config"))
        if os.environ.get("TF_TEST_SSH_DEBUG"):
            client_env["TS_DEBUG_SSH_EXEC"] = "1"
        headscale = state / "headscale"
        shutil.copyfile(args.headscale, headscale)
        headscale.chmod(0o700)
        control_port = port()
        config = Path(args.config or root / "tests/lab/headscale.yaml").read_text()
        config = config.replace("/tmp/tailfeather-lab/headscale", str(state / "headscale-state"))
        config = config.replace("http://127.0.0.1:8080", f"http://127.0.0.1:{control_port}")
        config = config.replace("0.0.0.0:8080", f"127.0.0.1:{control_port}")
        config = config.replace("0.0.0.0:9090", "127.0.0.1:0")
        config = config.replace("0.0.0.0:50443", "127.0.0.1:0")
        config = config.replace("0.0.0.0:3478", f"127.0.0.1:{port(socket.SOCK_DGRAM)}")
        config = config.replace("mode: database", f"mode: file\n  path: {state / 'policy.json'}")
        config = config.replace("level: debug", "level: info")
        config += f"\nunix_socket: {state / 'headscale.sock'}\nunix_socket_permission: '0700'\n"
        (state / "headscale-state").mkdir()
        (state / "headscale.yaml").write_text(config)
        (state / "policy.json").write_text(json.dumps({
            "tagOwners": {"tag:client": [], "tag:server": []},
            "acls": [{"action": "accept", "src": ["tag:client"], "dst": ["tag:server:22"]}],
            "ssh": [{"action": "accept", "src": ["tag:client"], "dst": ["tag:server"], "users": ["console"]}],
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

        def wait_for(predicate, process, description, seconds=30):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                if predicate():
                    return
                if process.poll() is not None:
                    raise RuntimeError(f"{description}: process exited {process.returncode}")
                time.sleep(0.1)
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
            keys = {}
            for tag in ["client", "server"]:
                keys[tag] = hs_json("preauthkeys", "create", "--user", str(user["id"]), "--tags", f"tag:{tag}", "--expiration", "10m")["key"]
            sock = state / "tailscaled.sock"
            daemon = spawn([
                args.tailscaled, "--tun=userspace-networking", f"--socket={sock}",
                f"--statedir={state / 'tailscale'}", "--port=0",
            ], "tailscaled", env=dict(os.environ, TS_NO_LOGS_NO_SUPPORT="1", TS_LOGS_DIR=str(state / "logs")))
            wait_for(sock.exists, daemon, "Tailscale startup")
            client = [args.tailscale, f"--socket={sock}"]
            # Pass the disposable credential through an inherited pipe, never
            # through argv, a generated source file, or terminal output.
            read_fd, write_fd = os.pipe()
            try:
                os.write(write_fd, keys["client"].encode())
                os.close(write_fd)
                subprocess.run(client + [
                    "up", f"--login-server=http://127.0.0.1:{control_port}",
                    f"--auth-key=file:/proc/self/fd/{read_fd}", "--hostname=real-tailscale-client",
                    "--accept-dns=false", "--accept-routes=false",
                ], pass_fds=(read_fd,), capture_output=True, check=True, timeout=45)
            finally:
                os.close(read_fd)
            # The real client and server share this host underlay, while their
            # tailnet addresses, identities and protocol stacks remain separate.
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                probe.connect(("192.0.2.1", 9))
                underlay = probe.getsockname()[0]
            env = dict(os.environ, TF_TEST_AUTH_KEY=keys.pop("server"))
            live = spawn([str(server), f"127.0.0.1:{control_port}", underlay], "server", env=env)
            del env
            server_log = state / "server.log"
            wait_for(lambda: "READY " in server_log.read_text(), live, "Tailfeather registration and netmap")
            ready = next(line for line in server_log.read_text().splitlines() if line.startswith("READY "))
            address = ready.split()[1]
            print(ready, flush=True)
            # Wait for control to distribute the advertised SSH host key. This
            # is exactly what the unmodified tailscale ssh wrapper verifies.
            def discovered():
                status = json.loads(subprocess.check_output(client + ["status", "--json"], env=client_env, timeout=5))
                return any(address in peer.get("TailscaleIPs", []) and peer.get("sshHostKeys") for peer in (status.get("Peer") or {}).values())
            wait_for(discovered, daemon, "SSH host-key distribution")
            version = subprocess.check_output(client + ["version"], env=client_env, timeout=5).decode().splitlines()[0]
            print(f"TAILSCALE {version}", flush=True)
            message = b"hello through real tailscale ssh\n"
            command = client + ["ssh", f"console@{address}"]
            if args.interactive:
                result = terminal_ssh(command, message, client_env)
            else:
                result = subprocess.run(command, env=client_env, input=message, capture_output=True, timeout=40)
            print(result.stdout.decode(errors="replace"), end="", flush=True)
            if result.stderr:
                print(result.stderr.decode(errors="replace"), end="", flush=True)
            assert result.returncode == 0, f"tailscale ssh exited {result.returncode}"
            if args.interactive:
                assert b"Tailfeather live console\n" + message in result.stdout.replace(b"\r\n", b"\n"), repr(result.stdout)
            else:
                assert result.stdout == b"Tailfeather live console\n" + message, repr(result.stdout)
            wait_for(lambda: "SESSION " in server_log.read_text(), live, "SSH session completion")
            session = next(line for line in server_log.read_text().splitlines() if line.startswith("SESSION "))
            # The stock tailscale nc ProxyCommand returns when either io.Copy
            # ends. After OpenSSH exits successfully it can close the proxy
            # before the SSH close acknowledgment reaches our TCP stack. Keep
            # that transport EOF visible; never weaken the engine's separate
            # close-handshake contract. Client status/output above must prove
            # that this exact console exchange completed before accepting EOF.
            assert session in {"SESSION Ok(())", "SESSION Err(Transport(UnexpectedEof))"}, session
            wait_for(lambda: "DRAINED" in server_log.read_text(), live, "TCP drain")
            print(server_log.read_text(), end="")
            print("PASS: default tailscale ssh verified the advertised key and completed the console exchange (exit 0)")
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
