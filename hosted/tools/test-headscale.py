#!/usr/bin/env python3
"""Disposable real Headscale tests of the hosted runtime's production IO actors."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import uuid

IMAGE = 'docker.io/headscale/headscale@sha256:895742a51a0661d60855359f01b2e3218afb4cca86987890dbd4fe11a4b7feeb'
ENGINE = os.environ.get('CONTAINER_ENGINE', 'docker')
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
            'server_url': 'https://localhost:18443', 'listen_addr': '127.0.0.1:18443',
            'metrics_listen_addr': '127.0.0.1:0', 'grpc_listen_addr': '127.0.0.1:0',
            'noise': {'private_key_path': '/fixture/data/noise.key'},
            'prefixes': {'v4': '100.64.0.0/10', 'v6': 'fd7a:115c:a1e0::/48'},
            'derp': {'server': {'enabled': True, 'region_id': 999, 'region_code': 'fixture',
                'verify_clients': False, 'stun_listen_addr': '127.0.0.1:13478',
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
            for mode in ('relay', 'direct'):
                case = root / mode
                case.mkdir(mode=0o700)
                shutil.copyfile(root / 'ca.der', case / 'ca.der')
                keys = [json.loads(cli('preauthkeys', 'create', '--user', str(user), '--ephemeral',
                    '--expiration', '10m', '--output', 'json').stdout)['key'] for _ in range(2)]
                private(case / 'keys.json', keys)
                log = case / 'run.log'
                args = ['cargo', 'run', '--manifest-path', 'hosted/Cargo.toml', '--locked',
                    '--example', 'headscale', '--', str(case), '--ephemeral']
                if mode == 'direct':
                    args += ['--direct', '--offline-direct']
                with log.open('w') as output:
                    process = subprocess.Popen(args, cwd=REPO, stdout=output, stderr=subprocess.STDOUT)
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
                    finally:
                        if process.poll() is None:
                            process.terminate()
                            process.wait(timeout=10)
        finally:
            if started:
                subprocess.run([ENGINE, 'rm', '-f', name], capture_output=True, check=False)


if __name__ == '__main__':
    main()
