# Release evidence

No release evidence is pre-filled: a template that says `pass` is worse than no
evidence. For a candidate commit, create `release/evidence/<commit>.json`
conforming to `evidence.schema.json`. Every artifact record contains an HTTPS
URL or repository-root-relative `artifacts/` path plus the output's SHA-256. The
validator downloads HTTPS artifacts and reads local artifacts, then verifies the
recorded digest before the gate passes. Never store OAuth secrets, auth keys,
private keys, or bearer tokens here.

The gate requires live hosted, pinned Headscale, physical-device, and
adversarial runs, resource measurements, successful run-scoped cleanup, and
permission-review identifiers.

Evidence and `artifacts/` files may be untracked post-commit inputs, but every
tracked file must match `HEAD` and no other untracked files are allowed. The
release gate therefore rejects staged, unstaged, or untracked source changes so
the tested and packaged bytes remain bound to the candidate commit.

The resource record must include measured RAM and image sizes, the pinned radio
heap size, at least 25% minimum task-stack headroom, and the immutable artifact
containing those measurements.
