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
Diagnostics are printed on every failure and the guest plus host state is
removed on exit.

`vectors/` is immutable captured ground truth. Bazel supplies vector,
expectation, harness, and lab-state paths through `TS_CONFORMANCE_*` runfile
environment variables. Updating a baseline or vector is a deliberate reviewed
source change, not a runtime download.
