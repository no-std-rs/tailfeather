#!/usr/bin/env python3
"""Disposable real Headscale tests of the hosted runtime's production IO actors."""
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

IMAGE = 'docker.io/headscale/headscale@sha256:895742a51a0661d60855359f01b2e3218afb4cca86987890dbd4fe11a4b7feeb'
ENGINE = os.environ.get('CONTAINER_ENGINE', 'docker')
RUNTIME = os.environ.get('TAILFEATHER_FIXTURE_RUNTIME', 'hosted')
REPO = Path(__file__).resolve().parents[2]


def run(*args, **kwargs):
    # All generated keys remain captured or in mode-0600 fixture files. No
    # authentication material is passed in arguments or printed on failures.
    return subprocess.run(args, check=True, capture_output=True, **kwargs)


def private(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), 'w') as output:
        json.dump(value, output)


def wait_for(predicate, process=None):
    deadline = time.monotonic() + 90
    while not predicate():
        if process and process.poll() is not None:
            raise RuntimeError('hosted fixture exited before readiness')
        if time.monotonic() >= deadline:
            raise TimeoutError('Headscale fixture readiness deadline')
        time.sleep(0.1)


def main():
    # Independent worktrees may run fixtures concurrently. Never reuse or stop
    # an unrelated service listening on a historical fixed fixture port.
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        control_port = listener.getsockname()[1]
    with socket.socket(type=socket.SOCK_DGRAM) as listener:
        listener.bind(('127.0.0.1', 0))
        stun_port = listener.getsockname()[1]
    control_url = f'https://localhost:{control_port}'
    name = 'tailfeather-hosted-' + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory(prefix='tailfeather-headscale-') as directory:
        root = Path(directory)
        (root / 'data').mkdir()
        run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-subj', '/CN=Hosted fixture CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-keyout', str(root / 'ca.key'), '-out', str(root / 'ca.pem'))
        run('openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes',
            '-subj', '/CN=localhost', '-keyout', str(root / 'key.pem'), '-out', str(root / 'leaf.csr'))
        (root / 'leaf.ext').write_text('basicConstraints=critical,CA:FALSE\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n')
        run('openssl', 'x509', '-req', '-days', '1', '-in', str(root / 'leaf.csr'),
            '-CA', str(root / 'ca.pem'), '-CAkey', str(root / 'ca.key'), '-CAcreateserial',
            '-extfile', str(root / 'leaf.ext'), '-out', str(root / 'cert.pem'))
        run('openssl', 'x509', '-in', str(root / 'ca.pem'), '-outform', 'DER', '-out', str(root / 'ca.der'))
        config = {
            'server_url': control_url, 'listen_addr': f'127.0.0.1:{control_port}',
            'metrics_listen_addr': '127.0.0.1:0', 'grpc_listen_addr': '127.0.0.1:0',
            'noise': {'private_key_path': '/fixture/data/noise.key'},
            'prefixes': {'v4': '100.64.0.0/10', 'v6': 'fd7a:115c:a1e0::/48'},
            'derp': {'server': {'enabled': True, 'region_id': 999, 'region_code': 'fixture',
                'verify_clients': False, 'stun_listen_addr': f'127.0.0.1:{stun_port}',
                'private_key_path': '/fixture/data/derp.key', 'automatically_add_embedded_derp_region': True},
                'urls': [], 'auto_update_enabled': False},
            'database': {'type': 'sqlite', 'sqlite': {'path': '/fixture/data/db.sqlite'}},
            'tls_cert_path': '/fixture/cert.pem', 'tls_key_path': '/fixture/key.pem',
            'policy': {'mode': 'database'}, 'disable_check_updates': True,
            'dns': {'magic_dns': False, 'base_domain': 'tailnet.invalid', 'override_local_dns': False},
            'unix_socket': '/fixture/data/headscale.sock', 'log': {'level': 'warn'},
        }
        (root / 'config.yaml').write_text(json.dumps(config))
        started = False
        try:
            run(ENGINE, 'run', '-d', '--name', name, '--network', 'host', '--user', '0',
                '-v', str(root) + ':/fixture:Z', IMAGE, 'serve', '--config', '/fixture/config.yaml')
            started = True

            def cli(*args):
                return run(ENGINE, 'exec', name, 'headscale', '--config', '/fixture/config.yaml', *args)

            def ready():
                result = subprocess.run([ENGINE, 'exec', name, 'headscale', '--config',
                    '/fixture/config.yaml', 'users', 'list', '--output', 'json'], capture_output=True)
                return result.returncode == 0

            wait_for(ready)
            user = json.loads(cli('users', 'create', 'fixture', '--output', 'json').stdout)['id']
            modes = ('relay', 'relay-persistent', 'direct') if RUNTIME == 'hosted' else ('relay', 'direct')
            for mode in modes:
                case = root / mode
                case.mkdir(mode=0o700)
                shutil.copyfile(root / 'ca.der', case / 'ca.der')
                key_args = ['preauthkeys', 'create', '--user', str(user), '--expiration', '10m', '--output', 'json']
                if mode != 'relay-persistent':
                    key_args += ['--ephemeral']
                keys = [json.loads(cli(*key_args).stdout)['key'] for _ in range(2)]
                private(case / 'keys.json', keys)
                log = case / 'run.log'
                if RUNTIME == 'hosted':
                    args = ['cargo', 'run', '--manifest-path', 'hosted/Cargo.toml', '--locked',
                        '--example', 'headscale', '--', str(case)]
                    if mode != 'relay-persistent':
                        args += ['--ephemeral']
                elif RUNTIME in ('reactor-fixed', 'reactor-owned'):
                    features = 'std,accelerated-crypto' if RUNTIME == 'reactor-owned' else 'std'
                    args = ['cargo', 'run', '--manifest-path', 'crates/tailfeather-reactor/Cargo.toml',
                        '--locked', '--features', features, '--example', 'headscale', '--', str(case)]
                    if RUNTIME == 'reactor-owned':
                        args += ['--owned']
                else:
                    raise ValueError('unknown fixture runtime')
                if mode == 'direct':
                    args += ['--direct', '--offline-direct']
                with log.open('w') as output:
                    process = subprocess.Popen(args, cwd=REPO, stdout=output, stderr=subprocess.STDOUT,
                        env={**os.environ, 'TAILFEATHER_FIXTURE_CONTROL_URL': control_url})
                    try:
                        if mode == 'direct':
                            wait_for(lambda: 'READY: stop the fixture' in log.read_text(), process)
                            # Give the earlier node its peer-add map update before
                            # removing both coordinator and DERP from the path.
                            time.sleep(1)
                            run(ENGINE, 'stop', '--time', '1', name)
                            (case / 'continue').write_text('coordinator and DERP are offline\n')
                        code = process.wait(timeout=120)
                        text = log.read_text()
                        for line in text.splitlines():
                            if line.startswith('PASS:'):
                                print(line, flush=True)
                        if code:
                            # Hosted diagnostics contain stage names and fixture
                            # addresses only, never the captured preauth keys.
                            print(text[-4000:], flush=True)
                            raise RuntimeError('real Headscale ' + mode + ' fixture failed')
                        if RUNTIME == 'hosted' and mode == 'relay':
                            wait_for(lambda: not json.loads(cli('nodes', 'list', '--output', 'json').stdout))
                            print('PASS: Headscale removed ephemeral nodes immediately on logout', flush=True)
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=10)
        finally:
            if started:
                subprocess.run([ENGINE, 'rm', '-f', name], capture_output=True, check=False)


if __name__ == '__main__':
    main()
