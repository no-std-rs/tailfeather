# tailfeather

`tailfeather` is a `no_std`, allocation-free implementation of the protocol
pieces needed by a small Tailscale-compatible mesh node. It exposes the
`keys`, `noise`, `control`, `netmap`, `disco`, `derp`, and `node` modules, and
reexports `wirefeather` as `tunnel` and `micro-h2` as `http2`.

The transport-agnostic `Node` is driven cooperatively:

```rust
use tailfeather::{Node, keys::{Identity, Rng}};

struct R;
impl Rng for R { fn fill_bytes(&mut self, out: &mut [u8]) { out.fill(42); } }

let mut node = Node::<8>::factory_reset(Identity::generate(&mut R), 1);
assert!(node.requires_persistence());
```

This crate is experimental protocol software, not an audited VPN product.
