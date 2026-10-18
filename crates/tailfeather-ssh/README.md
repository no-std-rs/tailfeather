# tailfeather-ssh

A small, `no_std`, allocation-free SSH console for a Tailfeather node. The
application supplies a TCP byte stream, secure RNG, persistent Ed25519 host key,
current authorization, and console callbacks. No shell process or operating
system is required.

Connect with `ssh -T console@device`. This is a line-oriented application console:
one connection, one shell channel, no PTY, resize handling, terminal emulator,
command execution, file transfer, forwarding, or client-side SSH implementation.
The application chooses the console's username and command vocabulary. Exec
requests exit with status 1 without reaching the console. Environment requests
are discarded by the engine and never reach the application.

## Size choices

- One caller-owned 4,096-byte packet buffer is shared by input and output.
- One caller-owned response buffer; 256 bytes is a suggested size, not a minimum.
- `TcpStorage` uses two socket slots with 1 KiB per direction per slot (4 KiB
  total byte queues), rather than the existing stack's 8 KiB default queues.
- Four SSH policy rules, eight IPv4 principals and four username mappings per
  rule; usernames have at most 31 bytes. No per-peer SSH identity strings.
- A single cryptographic suite: Curve25519, Ed25519, and OpenSSH ChaCha20-Poly1305.
  The server-only `zssh` 0.4.2 shares the project's crypto dependencies, with a
  [small local backport](../../../third_party/zssh/README.tailfeather.md) for correct
  output under receive-window backpressure.
- Tailfeather defaults are disabled to omit Curve25519's precomputed tables.
  Key operations trade some speed for flash size. Other node consumers retain
  their previous default via `fast-curve25519`; Cargo feature unification may
  re-enable the tables if the application requests that feature elsewhere.
- A one-byte receive window permits alternating input/output with a single
  packet buffer. This sacrifices throughput, especially for pasted text over
  a high-latency path. Console line editing and echo belong to the application.
- The 4 KiB packet limit deliberately omits SSH's general 32 KiB packet guarantee.
  Oversized client packets disconnect. OpenSSH's default handshake is covered
  by the interoperability test.

`bazel run //crates/tailfeather-ssh:footprint --config=local --config=optimized`
prints concrete type/future sizes. The future includes suspended crypto/I/O
state; packet and response buffers are separate. TCP buffers, the Tailfeather
node, the RNG, console state, and transient execution stack are additional.
The probe binary includes the host standard library, so its ELF size is not a
firmware flash measurement.

With Rust 1.95.0 on x86-64 Linux, the optimized host memory probe reports:

| Storage | Bytes |
| --- | ---: |
| SSH session future (probe I/O adapter) | 3,376 |
| Shared SSH packet | 4,096 |
| Suggested console response | 256 |
| Retained SSH policy | 1,552 |
| Persistent host signing key | 224 |
| Small TCP storage, including socket metadata | 4,928 |

The separate `probe:no_std_probe` fixture links without `std`, libc, or an
allocator. Its optimized x86-64 code and read-only data are 130,120 bytes, with
173 bytes of initialized data. This measures the SSH console fixture, excluding
the Tailscale node, TCP stack, and application-specific policy/console code; it
is not an ESP32 flash measurement. Its 128 KiB code/data budget and allocator
absence are checked with:

```sh
bazel test //crates/tailfeather-ssh/probe:artifact_contract --config=optimized
```

## Authorization

Enable `tailfeather`'s `ssh-policy` feature (enabled by this crate). It adds a
bounded consumer to the existing streaming map parser and retains
`MapResponse.SSHPolicy`. Other consumers pay no policy storage cost when that
feature is disabled.

`TailnetAccess` requires all of:

1. The authenticated WireGuard public key still belongs to a current peer that
   control has not marked expired.
2. The source is one of that peer's exact node IPv4 `/32` addresses. Routed
   `AllowedIPs` are insufficient. The destination is this node's assigned `/32`.
3. The network packet filter permits TCP to destination port 22.
4. The separate SSH policy allows the requested username to map to the local
   console username.

Only compiled IPv4 `nodeIP` and `any` principals and unconditional accept/reject
actions are supported. An explicit username mapping takes priority over `*`;
an empty mapping does not match. `=` implements non-root identity mapping;
`root` and numeric zero are excluded. There are no Unix accounts or UID aliases.
Use an explicit non-root console name such as `console`.

Check/delegation, rule expiry, nonzero session durations, recording requirements,
node-ID/user-login principals, unknown requirements, duplicate fields, malformed
values, and capacity overflow invalidate the **entire** policy. An unsupported
earlier rule cannot be skipped in favour of a later accept. Configure an
explicit `accept` policy whose compiled principals are IPv4 node addresses for
this first version. The default check-mode policy will deny access. This is a
deliberate subset, not full Tailscale SSH policy compatibility.

Absent/null policy deltas preserve the previous policy. An empty policy revokes
access. A replacement policy authorizes nobody until its entire object arrives.
Keep normal map framing/validation transactional, as with the other fields.

SSH peers must have key expiry disabled. This clock-free subset accepts absent
or canonical Go zero `KeyExpiry` values, and denies finite or unsupported expiry
values even when the deadline is in the future. Full records and peer patches
retain this restriction independently of `Expired`; null patches preserve it.
Key-rotation patches immediately replace the identity used for authorization.

## Wiring

Generate and persist a separate random 32-byte host-key seed. Use
`HostKey::public_key` to render its public OpenSSH key and include that line in
`Hostinfo.ssh_host_keys` when registering and publishing host info. This advertises
Tailscale SSH and distributes the public host key through control.

Route decrypted **local-destination** TCP/22 packets to the existing
`tailfeather::local_tcp` stack. Use `TcpStorage::new()` for one session and one
listener with small byte queues (`Storage::<2, 1024>`). Wrap a claimed stream
in this crate's reexported `embedded_io_async` 0.6 `Read`/`Write` traits; use the
reactor's wakeups for
`WouldBlock` and preserve short writes. The underlying Tailfeather TCP stack
itself owns no executor or operating-system socket.

Construct `TailnetAccess` using authenticated tunnel metadata and the TCP
endpoints. Never treat a source IP from a LAN connection as an authenticated
Tailscale identity. Then call `serve(stream, rng, host_key, access, console,
packet_buffer, response_buffer)`. It returns when the single console exits or
the connection fails. Gracefully close/drain TCP and release its slot afterwards.
The crate does not enable a listener in the firmware or harness automatically.

For a changing map, pass an authorizer closure which briefly borrows the current
map and calls `TailnetAccess::allows`. The server rechecks before each console
callback and response. The surrounding reactor must cancel/drop `serve` on a
policy or peer change, and enforce handshake/idle deadlines: a blocked read or
write cannot observe policy updates by itself. Packet and response storage are
wiped on completion/error or cancellation after the first poll.

## Verification

```sh
bazel test //crates/tailfeather-ssh:unit_test //crates/tailfeather-ssh:openssh_test
```

The OpenSSH test uses a loopback TCP stream as a wire-protocol oracle, a synthetic
authenticated peer and compiled control policy, and deliberately short writes.
It covers console round trips, denied usernames, blocked exec, revocation,
responses larger than the client's receive window, and the standalone no_std
fixture reached through OpenSSH's ProxyCommand.
The standalone fixture is built and tested by Bazel; Cargo's release checks run
the TCP interoperability cases without it.
It does not establish a live connection through Tailscale's hosted control plane.
