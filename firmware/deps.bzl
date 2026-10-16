"""Firmware dependency helpers for the generated Cargo metadata closure."""

load("@firmware_deps//:data.bzl", "DEP_DATA")

_GENERATED_FIRST_PARTY = [
    "@firmware_deps//:micro-h2-0.0.1",
    "@firmware_deps//:tailfeather-0.0.1",
    "@firmware_deps//:tailfeather-gateway-0.0.1",
    "@firmware_deps//:wirefeather-0.0.1",
]

def third_party_deps():
    """Returns firmware deps while leaving first-party crates Bazel-native."""
    metadata = DEP_DATA["firmware"]
    shared = [dep for dep in metadata["deps"] if dep not in _GENERATED_FIRST_PARTY]
    branches = {
        platform: [dep for dep in deps if dep not in _GENERATED_FIRST_PARTY]
        for platform, deps in metadata["deps_by_platform"].items()
    }
    branches["//conditions:default"] = []
    return shared + select(branches)
