#!/usr/bin/env bash
# Build the browser client into web/dist/:
#   cargo (wasm32-unknown-unknown, release) -> wasm-bindgen --target web
#   + the static page + vendored xterm.js from node_modules.
#
# Needs a clang that can target wasm32 (ring compiles C). The one used is, in
# order: $CC_wasm32_unknown_unknown, `clang` on PATH if it lists wasm32, or
# Homebrew's llvm@21. The wasm-bindgen CLI matching Cargo.lock is installed
# into web/client/.tools on first use.
set -euo pipefail

static=false
if [[ "${1:-}" == --static && $# == 1 ]]; then
  static=true
elif [[ $# != 0 ]]; then
  echo "usage: $0 [--static]" >&2
  exit 2
fi

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
dist="$(cd "$here/.." && pwd)/dist"
cd "$here"

supports_wasm() {
  "$1" --print-targets 2>/dev/null | grep -q wasm32
}

find_clang() {
  if [[ -n "${CC_wasm32_unknown_unknown:-}" ]]; then
    echo "$CC_wasm32_unknown_unknown"
    return
  fi
  if command -v clang >/dev/null 2>&1 && supports_wasm clang; then
    command -v clang
    return
  fi
  local brew=/home/linuxbrew/.linuxbrew/opt/llvm@21/bin/clang
  if [[ -x "$brew" ]] && supports_wasm "$brew"; then
    echo "$brew"
    return
  fi
  echo "error: no clang with a wasm32 target found. Install LLVM (for example" >&2
  echo "'brew install llvm@21') or set CC_wasm32_unknown_unknown to a wasm-capable clang." >&2
  exit 1
}

clang="$(find_clang)"
export CC_wasm32_unknown_unknown="$clang"
if [[ -z "${AR_wasm32_unknown_unknown:-}" ]]; then
  if [[ -x "$(dirname "$clang")/llvm-ar" ]]; then
    export AR_wasm32_unknown_unknown="$(dirname "$clang")/llvm-ar"
  elif command -v llvm-ar >/dev/null 2>&1; then
    export AR_wasm32_unknown_unknown="$(command -v llvm-ar)"
  else
    echo "error: no llvm-ar found next to $clang or on PATH; set AR_wasm32_unknown_unknown." >&2
    exit 1
  fi
fi
echo "using $CC_wasm32_unknown_unknown"

cargo build --locked --release --target wasm32-unknown-unknown
target_dir="${CARGO_TARGET_DIR:-$here/target}"
wasm="$target_dir/wasm32-unknown-unknown/release/tailfeather_web.wasm"

version="$(awk '/^name = "wasm-bindgen"$/ { getline; gsub(/version = |"/, ""); print; exit }' Cargo.lock)"
tools="$here/.tools"
bindgen="$tools/bin/wasm-bindgen"
if [[ ! -x "$bindgen" ]] || [[ "$("$bindgen" --version)" != "wasm-bindgen $version" ]]; then
  echo "installing wasm-bindgen-cli $version into $tools"
  cargo install --locked --root "$tools" --version "=$version" wasm-bindgen-cli
fi

if [[ ! -d node_modules/@xterm/xterm || ! -d node_modules/@xterm/addon-web-links ]]; then
  npm ci --no-audit --no-fund
fi

rm -rf "$dist"
mkdir -p "$dist/pkg" "$dist/vendor"
"$bindgen" --target web --no-typescript --out-dir "$dist/pkg" "$wasm"
cp www/index.html www/*.js www/style.css "$dist/"
if $static; then
  # Static hosts have no Worker endpoint for minting one-time auth keys.
  node --input-type=module - "$dist/index.html" <<'JS'
import { readFileSync, writeFileSync } from "node:fs";
const path = process.argv[2];
const html = readFileSync(path, "utf8");
writeFileSync(path, html.replace('id="worker-auth"', 'id="worker-auth" hidden'));
JS
fi
touch "$dist/.nojekyll"
cp node_modules/@xterm/xterm/lib/xterm.mjs node_modules/@xterm/xterm/lib/xterm.mjs.map \
   node_modules/@xterm/xterm/css/xterm.css \
   node_modules/@xterm/addon-fit/lib/addon-fit.mjs node_modules/@xterm/addon-fit/lib/addon-fit.mjs.map \
   node_modules/@xterm/addon-web-links/lib/addon-web-links.mjs node_modules/@xterm/addon-web-links/lib/addon-web-links.mjs.map \
   "$dist/vendor/"
echo "built $dist ($(du -h "$dist/pkg/tailfeather_web_bg.wasm" | cut -f1) wasm)"
