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

## Automated crate releases

The release-plz workflow requires two repository secrets before it reaches
`main`:

- `RELEASE_PLZ_APP_CLIENT_ID`: the Client ID of the installed GitHub App.
- `RELEASE_PLZ_APP_PRIVATE_KEY`: that App's private key.

Create or replace that App from the checked-in manifest helper:

```console
python3 .github/setup-release-plz-app.py
```

Open the loopback URL it prints, create the private App, then install it for only
the `tailfeather` repository. The manifest grants `Contents` and `Pull requests`
read/write access, disables webhooks and OAuth user authorization, and sends the
generated Client ID and private key directly to `gh secret set` over stdin. The
credentials are neither printed nor written to the checkout. The helper stops
after GitHub redirects back from installation.

When the browser runs on another host, bind a fixed port on all interfaces:

```console
python3 .github/setup-release-plz-app.py --listen 0.0.0.0 --port 40423
```

Replace `<reachable-host>` in the printed URL with this machine's reachable
hostname or address. The random path is a one-use capability: do not share it,
and expose the port only for the duration of the setup.

Crates.io does not allow a trusted publisher to be configured before a crate's
first release. For the one-shot bootstrap, set
`RELEASE_PLZ_BOOTSTRAP_ENABLED=true` and store a short-lived crates.io token as
`CARGO_REGISTRY_TOKEN_BOOTSTRAP`. On the next push to `main`, release-plz
publishes `0.0.1` in dependency-safe order:

1. `wirefeather`
2. `micro-h2`
3. `tailfeather`
4. `tailfeather-testkit`

While the bootstrap variable is `true`, the normal publish and release-PR jobs
do not run on pushes. A failed bootstrap can be rerun safely: release-plz skips
versions that crates.io already has and attempts the remaining unpublished
versions.

After all four crates exist, immediately set
`RELEASE_PLZ_BOOTSTRAP_ENABLED=false`, delete the GitHub bootstrap secret, and
revoke its crates.io token. Then add the same trusted publisher to each crate:

- GitHub owner: `pawelchcki`
- repository: `tailfeather`
- workflow: `release-plz.yml`
- environment: `release`

Only after all four trusted publishers exist, set
`RELEASE_PLZ_PUBLISH_ENABLED=true`. The normal publish job uses the `release`
GitHub environment and exchanges GitHub's OIDC identity for a short-lived
crates.io token; it stores no long-lived registry credential. Later changes
release each crate independently. At `0.0.x`, Cargo treats every patch increment
as incompatible, so an internal crate patch necessarily updates and releases
its dependents, cascading through the graph.

`main` accepts squash merges only, and the squash commit subject is the pull
request title. Pull request titles must use Conventional Commit syntax so
release-plz can classify each merged change; the required `conventional PR title`
check enforces that policy before merge.
