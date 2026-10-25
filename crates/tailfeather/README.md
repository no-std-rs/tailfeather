# tailfeather

The default `fast-curve25519` feature retains precomputed basepoint tables.
Use `default-features = false` to trade key-operation speed for smaller code.
The optional `ssh-policy` feature retains the bounded SSH accept-policy subset
used by `tailfeather-ssh`; it adds no policy storage when disabled.

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

X.509 distinguished-name comparison streams UTF8String, BMPString,
UniversalString and the basic T.61 graphic repertoire through bounded Unicode
normalization and Unicode 17 default full case folding. Locale-specific Turkic
folding is excluded. T.61 prefix accents, spacing accents, supplementary Latin
characters and nonspacing underline are supported; malformed sequences,
presentation controls and optional national/escape repertoires fail closed.
Normalization keeps at most 64 combining scalars per sequence and rejects
overflow. Unicode data and its license are bundled in `src/unicode_normalization`;
regenerate the pinned folding tables with `python3 scripts/generate-case-folding.py`
from the repository checkout. The mapping sources are [Unicode CaseFolding.txt](https://www.unicode.org/Public/17.0.0/ucd/CaseFolding.txt)
and [ITU-T T.61 (1988)](https://www.itu.int/rec/T-REC-T.61-198811-S/en).
