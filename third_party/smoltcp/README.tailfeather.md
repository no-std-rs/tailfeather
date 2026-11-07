# Local smoltcp patch

Source: the published `smoltcp` 0.13.1 crate from
<https://static.crates.io/crates/smoltcp/smoltcp-0.13.1.crate>, licensed under
0BSD. Upstream: <https://github.com/smoltcp-rs/smoltcp>. Example and bench
targets are omitted, and Cargo publication is disabled for this local copy.
Upstream's warnings for feature sets its CI does not build are allowed in
`Cargo.toml`.

The reactor and hosted workspaces use this copy through `[patch.crates-io]`.
The other workspaces (firmware, web, the root library crates) still use the
published crate. Nothing changes on the wire: these are sender-side TCP
behaviours that any peer, including the official client's gVisor stack, sees
as ordinary TCP.

Local changes, all in `src/socket/tcp.rs` and
`src/socket/tcp/congestion/reno.rs`:

- The congestion window bounds the data in flight. Upstream subtracted only
  what the current dispatch would send, so a sender kept transmitting until
  the receiver's whole window was in flight. Behind a relay with a bounded
  queue (DERP), that overflowed the queue on every round trip.
- Fast retransmission resends one segment, not the whole window. Recovery
  follows NewReno (RFC 6582): each partial ACK immediately retransmits the
  next hole, and recovery ends at the first ACK covering everything sent
  when the loss was detected. Fast retransmission no longer doubles the
  retransmission timeout, since no timer expired.
- The minimum retransmission timeout is 200 ms, as in Linux and gVisor,
  instead of RFC 6298's 1 s. Doubled on each timeout, the 1 s floor left a
  lossy relayed transfer idle for up to 60 s.
- Reno follows RFC 5681. Upstream grew the window by one segment per ACK even
  above `ssthresh`, so it never left slow start, and only halved the window
  on loss. Now congestion avoidance adds one segment per window of
  acknowledged data, and each loss event sets `ssthresh` to half the window.
  Slow start credits every acknowledged byte, as Linux does: receivers that
  coalesce segments send stretch ACKs, and RFC 3465's two-segment cap made
  the ramp additive. The initial window is RFC 6928's.

`test_fast_retransmit_after_triple_duplicate_ack` now expects one
retransmitted segment. `test_fast_retransmit_partial_ack_retransmits_next_hole`
covers NewReno recovery. The `netsim` snapshot covers the build without a
congestion controller, where in-flight limiting and single-segment recovery
raise goodput at 1-20% random loss (for example 13.7 to 25.5 Mbit/s with
4 KiB buffers at 5% loss). Run the upstream suite here:

```sh
cargo test --release --features _netsim
cargo test --release --features socket-tcp-reno --lib
```
