#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

untracked_source=()
while IFS= read -r -d '' path; do
    case "$path" in
        release/evidence/*|artifacts/*) ;;
        *) untracked_source+=("$path") ;;
    esac
done < <(git ls-files --others --exclude-standard -z)
if ! git diff --quiet -- || ! git diff --cached --quiet -- || (( ${#untracked_source[@]} )); then
    echo "BLOCKED: source differs from HEAD; release evidence would not cover the packaged bytes"
    git status --short --untracked-files=no
    if (( ${#untracked_source[@]} )); then
        printf '?? %s\n' "${untracked_source[@]}"
    fi
    exit 1
fi

cargo fmt --all -- --check
find harness/src firmware/src -type f -name '*.rs' -print0 | \
    xargs -0 rustfmt --edition 2024 --check
cargo test --workspace --all-targets
cargo test --workspace --doc
cargo clippy --workspace --all-targets -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
scripts/no-alloc-guard.sh
(cd harness && cargo build --release)
(cd firmware && cargo build --release)
scripts/resource-check.sh
scripts/fixture-audit.sh
scripts/package-check.sh

commit="$(git rev-parse HEAD)"
evidence="release/evidence/$commit.json"
[[ -f "$evidence" ]] || {
    echo "BLOCKED: missing same-commit hosted/Headscale/hardware release evidence: $evidence"
    exit 1
}
python3 scripts/validate-release-evidence.py "$evidence" "$commit"
[[ -f tests/expectations/hosted.json ]] || {
    echo "BLOCKED: no exact hosted baseline has been recorded"
    exit 1
}
python3 scripts/validate-trademark-review.py release/trademark-review.toml
echo "PASS: automatic and external release gates are satisfied"
