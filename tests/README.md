# Compatibility test framework

The goal is a node that real Tailscale and real Headscale both accept. This
directory is the instrument for measuring how far away that is.

```sh
tests/lab/lab.sh up              # real Headscale in a container
tests/lab/lab.sh reference       # real tailscaled joins it, as ground truth
sudo tests/lab/capture.sh        # capture vectors from both into tests/vectors/
cargo run -p ts-conformance --bin conformance
```

The last command prints the compatibility matrix. Release gating additionally
compares every status with an exact environment-specific baseline.

## Why it is built this way

**100% compatibility cannot be proven by a test suite.** What a suite can do is
make the gap explicit, measurable, and impossible to forget. So this is not a
set of tests that pass or fail; it is an enumeration of every behaviour a
Tailscale-compatible node must exhibit, each carrying a status. Unimplemented
behaviour is *declared*, not omitted, so the score starts low and honestly and
rises as real work lands. No count is copied into documentation: the command's
schema-versioned report and exact baseline are the authority.

**Nothing here is a mock.** The one protocol bug on this project that cost real
time — WireGuard's Noise construction string — would have passed any test
written against our own understanding, because our understanding was the thing
that was wrong. It was caught by handing a packet to the Linux kernel and
watching it disagree. Every check is therefore run against a live reference
implementation or against bytes captured from one.

That principle is enforced by the statuses. `PASS` means this run verified the
behaviour. `PASS*` means a named artifact outside the process did — the
root-requiring interop scripts. Only those two count. `TODO` is unbuilt work,
`FAIL` is a real defect, and `SKIP` means the check could not run and is
excluded from the score rather than counted as success.

## Layout

```
lab/lab.sh            start Headscale, mint preauth keys, join a reference client
lab/capture.sh        record ground truth into vectors/
lab/extract_map.py    recover decrypted MapResponses from the reference client's log
lab/probe_capver.py   binary-search the server's minimum capability version
lab/headscale.yaml    lab server configuration
vectors/              committed ground truth, pinned to the versions that produced it
```

The suite itself is `crates/ts-conformance`. `checks.rs` is the specification:
adding a behaviour there before implementing it is the intended workflow.

## Ground truth

The control protocol runs inside Noise, so a packet capture alone shows only
opaque frames. The decrypted view comes from the reference client: `TS_DEBUG_MAP=1`
makes tailscaled log each MapResponse in cleartext. Between the capture and the
log we get both what went over the wire and what it meant.

Vectors are committed along with `versions.json`, which pins the Headscale and
Tailscale versions they came from. Re-capture after upgrading either.

## Facts this framework has already established

These were discovered by probing the real server, not read from documentation,
and each is a constraint the implementation has to satisfy:

- The server publishes its Noise public key at `GET /key?v=<capver>`, encoded as
  `mkey:` followed by 64 hex characters.
- `GET /key` without a capability version is rejected outright.
- **Headscale v0.29.3 rejects any capability version below 113.** This floor
  rises as servers are upgraded, which is why it is probed rather than hardcoded
  — a stale constant fails before any protocol work even begins.
- A two-node tailnet already produces 27 KB of MapResponse JSON across 11
  responses, 5 of which are deltas. Deltas omit fields rather than repeating
  them, so a parser that treats every response as a full map silently loses
  state. Neither buffering the whole map nor ignoring deltas is viable.

## Testing against hosted Tailscale

Hosted testing is opt-in and needs OAuth credentials with `auth_keys`,
`devices:core`, and `devices:routes`. The release runner must create one
non-ephemeral DUT key and one ephemeral reference key, approve exit routes,
exercise TCP and UDP, force direct→DERP→direct, verify reboot identity reuse,
and delete all run-scoped resources in a `finally` path. A hosted result is not
accepted from committed captures or a local Headscale run; integrated checks
must be live `pass` for the candidate commit.

The harness has a TLS client, but the firmware trusted-time bootstrap and the
complete hosted orchestration remain release blockers. Hosted map responses
must be uncompressed until a bounded allocation-free decoder exists.
