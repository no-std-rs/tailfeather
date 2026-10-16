// Unicode 17.0.0 decomposition and combining-class tables vendored from
// unicode-normalization 0.1.25. The upstream iterator requires `alloc`; this
// module exposes only the table-backed primitives used by our bounded,
// allocation-free X.509 name comparator.

#[allow(dead_code)]
mod lookups;
#[allow(dead_code)]
mod normalize;
#[allow(dead_code)]
mod perfect_hash;
#[allow(dead_code)]
#[allow(clippy::match_like_matches_macro)]
mod tables;

#[allow(dead_code)]
#[derive(Clone, Copy)]
enum IsNormalized {
    Yes,
    No,
    Maybe,
}

pub(crate) use lookups::canonical_combining_class;
pub(crate) use normalize::decompose_compatible;
