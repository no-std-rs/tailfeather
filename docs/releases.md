# Releases

Runnerless owns independent release PRs, tags, GitHub Releases, and crates.io
publication for these libraries:

| Crate | Version and changelog directory | Tags |
| --- | --- | --- |
| wirefeather | `crates/wirefeather/` | `wirefeather-vX.Y.Z` |
| tailfeather | `crates/tailfeather/` | `tailfeather-vX.Y.Z` |
| tailfeather-gateway | `crates/tailfeather-gateway/` | `tailfeather-gateway-vX.Y.Z` |

Each directory contains `version.txt` and `CHANGELOG.md`. The track owns one
`release-please--branches--main--tracks--CRATE` branch and release PR. Its path
filters select source changes; Conventional Commits select the version bump.
Release-file changes are excluded so merging a release never releases itself.
The Tailfeather track also owns the browser, firmware, and harness adapters.
Testkit, conformance tools, and application packages are not published.

The existing Tailfeather and Wirefeather `0.0.1` tags remain the history floors.
Gateway has never had its own release, so its initial `0.0.1` version is an
unreleased baseline with a one-time `tailfeather-v0.0.1` bootstrap anchor.
No historical release or tag is moved. The only moving tag is the explicitly
prerelease `tailfeather-main` browser download.

## Release PRs and packages

On main, `.runnerless-ci.ts` runs the shared `releasePlease()` recipe. It
finalizes merged release PRs before proposing the next release for each track.
Review and merge each release PR normally; main requires a PR for everyone.

Runnerless changes only a track's version file and changelog. Packaging and web
builds run `scripts/prepare-release.py` to align the Cargo package versions,
local dependency requirements, and all five Cargo locks with those authoritative
version files. The preparation happens in the build checkout. Internal package
versions are preserved; the web application receives the Tailfeather version or
its main-preview variant. Source manifests are development metadata.

`release.yml` tests release PRs and verifies their selected Cargo package. After
a stable GitHub Release is published, it repeats the checks at the immutable
tag, captures only that crate's Cargo upload against a loopback registry, and
attaches the `.cargo-upload` body and `SHA256SUMS` to that GitHub Release.
Actions has no crates.io publishing credential. The successful workflow event
lets Runnerless verify the release, build revision, package identity, and
checksums, then publish using its Production credential.

For the first releases, merge and publish **Wirefeather first**, then refresh
the Tailfeather and gateway release PRs. Their package-verification checks use
the published dependency, so a release that needs the new Wirefeather API
cannot pass before that version is available on crates.io. Future dependency
updates use the same ordering. A failed package build publishes nothing.

To retry packaging, dispatch the workflow at the existing release tag:

```sh
gh workflow run release.yml --repo no-std-rs/tailfeather --ref CRATE-vX.Y.Z
```

The workflow's ref must be the release tag so Runnerless can bind the completed
build to that exact release. Attached stable assets are not overwritten. Inspect
partial uploads before a retry; registry publication itself is reconciled by
Runnerless and never overwrites an existing crate version.

## Browser releases and previews

- Stable: <https://no-std-rs.github.io/tailfeather/>
- Main preview: <https://no-std-rs.github.io/tailfeather/main/>
- Main download: <https://github.com/no-std-rs/tailfeather/releases/tag/tailfeather-main>

Publishing a Tailfeather release builds and tests its browser client, attaches
immutable web assets and their checksum to that release, then updates the normal
Pages URL. Other crate releases do not replace the stable browser.

Main pushes and the current App-authored Tailfeather release PR publish a tested
`X.Y.Z-main.COMMIT` build. Other PRs only build and test. The publisher checks
the current main or release-PR head before moving `tailfeather-main`; stale
builds cannot replace it. Each composed Pages deployment fetches the highest
complete stable Tailfeather web release and preserves it at the normal URL.
The preview is copied under `main/`. Stable release assets are stored before
the serialized Pages job, so a replaced pending deployment can be recovered by
the next publication without losing the stable build.

The historical releases predate the browser. Until a Tailfeather release has
web assets, the normal URL retains the first tested bootstrap build. Its
`build.json` identifies it as a main build; it is not presented as a stable
release. After the first browser release, preview updates keep the stable
version at the root.

To rebuild a stable browser release, run `pages.yml` at its Tailfeather tag.
To refresh the composed site and main preview, run it at main:

```sh
gh workflow run pages.yml --repo no-std-rs/tailfeather --ref main
```

`build.json` at either URL records the compiled version, source commit, and
channel. Web tarballs reject links and unsafe paths and have reproducible
metadata and SHA-256 manifests. Publication runs the trusted main-branch script
in a separate job from compilation. The Pages environment permits `main`,
`tailfeather-v*` tags, and `refs/pull/*/merge` for PR events. GitHub checks the
PR merge ref against this policy, not the source branch name. The workflow
allows publication only for the App-authored Tailfeather release branch, and
the trusted publisher verifies its current head again before updating assets.

## Runnerless activation

Connect `no-std-rs/tailfeather` through the existing Runnerless organization and
GitHub App. The native API supports operator adoption without a GitHub user
token. Configure its three package destinations and enable Production with:

```sh
python3 scripts/configure-runnerless-publishing.py --organization ORGANIZATION_ID --dry-run
python3 scripts/configure-runnerless-publishing.py --organization ORGANIZATION_ID
```

The destination grants only the three package names and maps each one to its
own `CRATE-v` tag prefix. Store a crates.io token in Runnerless's write-only
publishing UI, or use Runl's hidden-input prompt:

```sh
runl publishing token REPOSITORY_ID crates --enable-production
```

The token needs `publish-update` for existing crates and `publish-new` for the
first gateway release, scoped to `wirefeather`, `tailfeather`, and
`tailfeather-gateway`. One repository registry token can serve all three
destinations. Never place the token in source, a workflow, command arguments,
or a GitHub Actions secret. A missing credential leaves crate publication
unconfigured; release PR generation and browser previews remain independent.

After activation, verify three separate release PRs, a passing
`Runnerless / Release` check on main, current-head preview artifacts, and
`Runnerless / crates-CRATE` after each stable package publication.
