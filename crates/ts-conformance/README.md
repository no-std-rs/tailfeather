# ts-conformance

The repository's executable compatibility specification for Tailscale and
Headscale behavior.

This is the one `std` crate in `crates/` and is not published. It combines live
reference implementations, captured vectors, the bare harness, and external
interop results into one status matrix.

## Run it

From the repository root:

```sh
scripts/conformance.sh
```

Or invoke the binary directly:

```sh
cargo run -p ts-conformance --bin conformance
cargo run -p ts-conformance --bin conformance -- --json
cargo run -p ts-conformance --bin conformance -- \
  --expect tests/expectations/offline.json
```

`tests/lab/lab.sh doctor` explains which live dependencies are available and
which checks will be skipped. See the [test-framework guide](../../tests/README.md)
for starting Headscale, joining a reference `tailscaled`, and refreshing
captured vectors.

## Status model

- `PASS`: verified during this run against a reference or captured evidence
- `PASS*`: verified by a named external interop artifact
- `TODO`: known work that has not been implemented
- `FAIL`: an observed incompatibility
- `SKIP`: the environment could not perform the check; never counted as success

The score alone is intentionally insufficient. CI compares every stable check
ID and status against a committed baseline, so a check that silently changes
from `PASS` to `SKIP` still fails the build.

## Scope

The matrix records whether it targets the local Headscale lab or hosted
Tailscale because success against one is not evidence about the other. New
protocol behavior should be declared in `checks.rs` even before implementation,
then backed by a live reference run or a committed external vector.

See the [repository README](../../README.md) for the implementation this matrix
measures.

## License

MIT OR Apache-2.0, at your option.
