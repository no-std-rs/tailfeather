# ts-conformance

Repository-only compatibility measurement for Tailfeather.

```sh
bazel test //:offline_conformance --test_output=all
bazel test //:privileged_lab --test_output=all
```

The offline target consumes committed vectors. The privileged target runs the
full baseline against pinned live reference implementations in a disposable
KVM guest. Paths arrive through `TS_CONFORMANCE_HARNESS`,
`TS_CONFORMANCE_VECTORS`, `TS_CONFORMANCE_EXPECTATIONS`, and
`TS_CONFORMANCE_LAB_STATE`; the program does not discover Cargo output paths.

The matrix distinguishes integrated passes, externally proven checks, declared
work, skips, and failures. Exact expectation JSON—not a handwritten score—is
the gate.
