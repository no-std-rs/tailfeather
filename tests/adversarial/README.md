# Adversarial LAN service

This repo-only service emits deterministic synthetic faults for the bare
allocation-free harness. None of these bytes are claimed to have been emitted by hosted
Tailscale, stock Headscale, or tailscaled.

```sh
python3 tests/adversarial/service.py --mode map33 --port 8444
python3 tests/adversarial/service.py --mode malformed-h2 --port 8444
python3 tests/adversarial/service.py --mode disconnect --cut 7 --port 8444
python3 tests/adversarial/service.py --mode tls-wrong-name --port 8444
```

Modes cover a deterministic 33-peer uncompressed map, malformed Noise,
HTTP/2, control, and DERP boundaries, and disconnects at a chosen byte. TLS
mode creates a short-lived, locally generated certificate for `wrong.invalid`;
the bare harness checks untrusted issuer, wrong name, and validity-time
cases by varying its anchor, expected host, and trusted clock. Generated keys
live only in a temporary directory and are never committed.

Run `scripts/adversarial-nostd.sh` after building the harness. Physical-device
scripts are retained only as optional diagnostics.
