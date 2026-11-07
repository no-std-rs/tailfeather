# Compatibility tests

The committed offline matrix runs on ordinary BuildBuddy RBE:

```sh
bazel test //:offline_conformance --test_output=all
```

The live matrix runs only on the bare `linux-amd64-kvm` pool:

```sh
bazel test //:privileged_lab --test_output=all
```

The live target boots a disposable smolVM guest and admits no skipped
capabilities. It preflights KVM, TUN, namespaces, veth, and kernel WireGuard;
starts pinned Headscale, a TLS front, and pinned `tailscaled` on a real TUN;
compares every conformance status with `expectations/lab.json`; and exercises
example-responder, harness-responder, and harness-initiator WireGuard modes.
`lab/reactor-rebind.sh` puts the shared reactor runtime and a stock
`tailscaled` behind separate filtering NATs, changes the reactor node's public
UDP mapping mid-session, and requires the stock client to reach the new port
directly within 40 seconds, below Headscale's map keepalive interval.
Diagnostics are printed on every failure and the guest plus host state is
removed on exit.

Every lab stage runs even after another one fails, and the guest ends with a
per-stage PASS/FAIL summary and timings. Stages that share the host-level lab
(conformance, WireGuard interop, no-std interop) run in sequence; the
namespace-isolated network stages (three SSH modes, reactor rebinding, the NAT
matrix) run concurrently.

## NAT matrix

```sh
bazel test --config=local --config=optimized //:nat_matrix --test_output=all
```

`lab/nat-matrix.sh` holds Tailfeather to the official client, not to a fixed
table. Every scenario is run twice behind identical namespaces: side A is
always a stock `tailscaled` (the observer); side B is a second stock
`tailscaled` (the baseline) and then the Tailfeather reactor node. The
observer's own disco pings report the path, so both runs are measured by the
same unmodified implementation over the standard protocols only. Tailfeather
fails a scenario if the official client went direct and it did not, or if it
is slower than the baseline (time to direct path, failover to DERP during a
UDP outage, recovery afterwards, recovery from a NAT rebinding) by more than
3 s and 50%, or if its direct round trip is more than 3 ms worse. Where the
official client must go direct, the baseline is also required to, so a broken
topology cannot pass by failing both sides.

NAT profiles: `public` (no NAT), `easy` (endpoint-independent mapping, port
preserving), `cone` (full cone), `hard` (endpoint-dependent mapping, a random
port per destination), `cgnat` (easy NAT behind a carrier NAT), `blocked` (no
UDP), and a shared `lan`. `+outage` and `+rebind` add mid-session events.
Each scenario owns its namespaces and Headscale, so these run in parallel
(`TF_NAT_JOBS`).

Measured scenarios run one at a time afterwards, so CPU contention cannot
decide them:

- `+bulk` transfers `TF_NAT_BULK_MB` (128) MiB of TCP each way,
  `TF_NAT_BULK_ROUNDS` (3) times, and keeps the median. The observer uses a
  real TUN and the kernel's TCP; B serves the bytes from its userspace stack
  (the official client's netstack, or the Tailfeather node). `+bulk-wan`
  first adds 10 ms of `netem` delay each way on every public port, and
  `easy-blocked+bulk` measures DERP. A rate passes if it is within 15%
  (`TF_NAT_SLACK_RATE_PERCENT`) of the official client in raw throughput or
  per CPU core: the node runs one packet thread, while the official client
  spreads WireGuard over every core it can take. The table prints both.
- `+ssh` connects with the stock `tailscale ssh` client to Tailscale SSH on B
  (the official server running `cat`, or the Tailfeather console from
  `TF_NAT_SSH_SERVER`). Session setup time is compared; pasted-input echo
  throughput (`TF_NAT_SSH_BYTES`) is reported but not gated, because the
  console's fixed, microcontroller-sized buffers bound it by design.

Outside the VM it runs on any Linux host with passwordless sudo, iproute2,
iptables, socat and openssl (rebind scenarios also need `conntrack`, bulk
scenarios `tc` with `netem`, SSH scenarios an OpenSSH client):

```sh
tests/lab/nat-matrix.sh matrix HEADSCALE TAILSCALE TAILSCALED LAB_NODE tests/lab/headscale.yaml
tests/lab/nat-matrix.sh one ... easy-cgnat+rebind tailfeather   # one run
```

`TF_NAT_SCENARIOS` selects scenarios, `TF_NAT_KEEP=1` keeps every log,
`TF_NAT_PCAP=1` records the public segment (`TF_NAT_PCAP_FILTER` overrides
the capture filter; bulk runs also record the observer's plaintext TUN) and
`TF_NAT_TS_VERBOSE=2` makes the official clients log their disco decisions.
`TF_TCP_BUFFER` overrides the node's per-connection TCP buffer for
experiments. Build the node with
`--config=optimized`: a debug build adds about 10 ms to each disco round trip.

`vectors/` is immutable captured ground truth. Bazel supplies vector,
expectation, harness, and lab-state paths through `TS_CONFORMANCE_*` runfile
environment variables. Updating a baseline or vector is a deliberate reviewed
source change, not a runtime download.
