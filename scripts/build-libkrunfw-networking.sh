#!/usr/bin/env bash
# Builds libkrunfw's kernel support artifact. Invoked by //bazel/kernel:krunfw_kernel,
# which passes every tool as a declared Bazel input; nothing here is resolved from
# the ambient environment or from packages that happen to be on the executor.
set -euo pipefail

CONFIG_EDITS=()
HOST_PACKAGES=()
HOST_CFLAGS=()
HOST_LDFLAGS=()

usage() {
    echo "usage: $0 --libkrunfw-archive F --linux-archive F --output F --python F --bundler F ..." >&2
    exit 2
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --libkrunfw-archive) LIBKRUNFW_ARCHIVE="$2"; shift 2 ;;
        --linux-archive) LINUX_ARCHIVE="$2"; shift 2 ;;
        --output) OUTPUT="$2"; shift 2 ;;
        --python) PYTHON="$2"; shift 2 ;;
        --bundler) BUNDLER="$2"; shift 2 ;;
        --kconfig-lexer) KCONFIG_LEXER="$2"; shift 2 ;;
        --kconfig-parser) KCONFIG_PARSER="$2"; shift 2 ;;
        --kconfig-header) KCONFIG_HEADER="$2"; shift 2 ;;
        --cc) TOOL_CC="$2"; shift 2 ;;
        --soname) SONAME="$2"; shift 2 ;;
        --abi-version) ABI_VERSION="$2"; shift 2 ;;
        --host-package) HOST_PACKAGES+=("$2"); shift 2 ;;
        --host-cflag) HOST_CFLAGS+=("$2"); shift 2 ;;
        --host-ldflag) HOST_LDFLAGS+=("$2"); shift 2 ;;
        --config-edit) CONFIG_EDITS+=("$2"); shift 2 ;;
        *) echo "unknown argument: $1" >&2; usage ;;
    esac
done

for required in LIBKRUNFW_ARCHIVE LINUX_ARCHIVE OUTPUT PYTHON BUNDLER \
    KCONFIG_LEXER KCONFIG_PARSER KCONFIG_HEADER TOOL_CC SONAME ABI_VERSION; do
    if [[ -z "${!required:-}" ]]; then
        echo "missing required argument for $required" >&2
        usage
    fi
done

abspath() { (cd "$(dirname "$1")" && printf '%s/%s\n' "$PWD" "$(basename "$1")"); }

PYTHON="$(abspath "$PYTHON")"
BUNDLER="$(abspath "$BUNDLER")"
TOOL_CC="$(abspath "$TOOL_CC")"
# ld.lld and the llvm-* binaries Kbuild's LLVM=1 looks up by name live beside
# clang in the toolchain Bazel declared as an input.
TOOLCHAIN_BIN="$(dirname "$TOOL_CC")"
TOOL_STRIP="$TOOLCHAIN_BIN/llvm-strip"

# The toolchain flags arrive execroot-relative, but Kbuild invokes the compiler
# from inside the kernel tree. Rewrite the `external/` and `bazel-out/` paths
# they carry into absolute ones before handing them to make.
EXECROOT="$PWD"
absolutize_flags() {
    local flag prefix rest
    for flag in "$@"; do
        matched=""
        for prefix in -L -B -I -isystem -F --sysroot=; do
            rest="${flag#"$prefix"}"
            if [[ "$flag" != "$rest" ]]; then
                case "$rest" in
                    external/*|bazel-out/*) printf '%s%s/%s\n' "$prefix" "$EXECROOT" "$rest"; matched=1 ;;
                esac
                [[ -n "$matched" ]] && break
            fi
        done
        [[ -n "$matched" ]] && continue
        case "$flag" in
            external/*|bazel-out/*) printf '%s/%s\n' "$EXECROOT" "$flag" ;;
            *) printf '%s\n' "$flag" ;;
        esac
    done
}
mapfile -t HOST_CFLAGS < <(absolutize_flags "${HOST_CFLAGS[@]}")
mapfile -t HOST_LDFLAGS < <(absolutize_flags "${HOST_LDFLAGS[@]}")

export PYTHONHOME
PYTHONHOME="$(dirname "$(dirname "$PYTHON")")"
# Keep the large kernel tree on the action filesystem. Some bare KVM workers
# mount /tmp as an inode-limited tmpfs, which is too small for a Linux checkout.
WORK="$(mktemp -d "${LIBKRUNFW_WORK_ROOT:-$PWD}/.libkrunfw-networking.XXXXXX")"
cleanup() { rm -rf "$WORK"; }
trap cleanup EXIT HUP INT TERM

# Unpack the pinned Debian packages into one host root. These supply the tools
# and libraries Kbuild needs that the bare executor image does not carry: make,
# and libelf for x86 objtool.
HOST_ROOT="$WORK/host-root"
for package in "${HOST_PACKAGES[@]}"; do
    "$PYTHON" "$BUNDLER" --extract-deb "$package" "$HOST_ROOT"
done
HOST_LIB="$HOST_ROOT/usr/lib/x86_64-linux-gnu"
export LD_LIBRARY_PATH="$HOST_LIB${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
export PATH="$TOOLCHAIN_BIN:$HOST_ROOT/usr/bin:$PATH"

# Kbuild hardcodes `bc` when generating include/generated/timeconst.h -- the
# documented BC= variable is not consulted there -- so the reimplementation has
# to be reachable under that name rather than passed as a make variable. It
# reads CONFIG_HZ on stdin and ignores bc's own arguments.
mkdir -p "$HOST_ROOT/usr/bin"
cat >"$HOST_ROOT/usr/bin/bc" <<EOF
#!/usr/bin/env bash
exec "$PYTHON" "$BUNDLER" --timeconst "\$@"
EOF
chmod +x "$HOST_ROOT/usr/bin/bc"

tar -xzf "$LIBKRUNFW_ARCHIVE" -C "$WORK"
SOURCE="$WORK/libkrunfw-5.5.0"
mkdir -p "$SOURCE/tarballs"
cp "$LINUX_ARCHIVE" "$SOURCE/tarballs/linux-6.12.91.tar.xz"

KERNEL="$SOURCE/linux-6.12.91"
# Apply libkrunfw's pinned patch series and baseline config without allowing
# its Makefile to download anything. The hermetic Python tool handles xz because
# the deliberately small RBE image has no system xz executable.
"$PYTHON" "$BUNDLER" --extract "$SOURCE/tarballs/linux-6.12.91.tar.xz" "$SOURCE"
for kernel_patch in "$SOURCE"/patches/*.patch; do
    "$PYTHON" "$BUNDLER" --apply "$kernel_patch" "$KERNEL"
done
# Linux release archives intentionally omit generated Kconfig C sources.
# Supply outputs generated from this exact pinned tree so the executor does not
# need ambient flex or bison packages.
cp "$KCONFIG_LEXER" "$KERNEL/scripts/kconfig/lexer.lex.c"
cp "$KCONFIG_PARSER" "$KERNEL/scripts/kconfig/parser.tab.c"
cp "$KCONFIG_HEADER" "$KERNEL/scripts/kconfig/parser.tab.h"
cp "$SOURCE/config-libkrunfw_x86_64" "$KERNEL/.config"
"$KERNEL/scripts/config" --file "$KERNEL/.config" "${CONFIG_EDITS[@]}"

# LLVM=1 points every stage of Kbuild -- host tools included -- at the toolchain
# Bazel declared as an input, rather than at an ambient gcc/binutils. LLVM_PREFIX
# makes each of those tool names absolute, so resolution never depends on PATH
# or on which shell make happens to spawn.
#
# Kbuild parses Makefile.vdsoinst, which probes $(READELF), and llvm-readelf is
# not among the tools rules_cc declares in the toolchain's input set -- so that
# probe reports "not found". Only the vdso_install target consumes the result
# and we build vmlinux, so this is inert; it is left undeclared rather than
# silenced so a real dependency on it would still surface.
KBUILD_TOOLS=(
    LLVM=1
    LLVM_PREFIX="$TOOLCHAIN_BIN/"
    CC="$TOOL_CC"
    HOSTCC="$TOOL_CC"
    LEX=:
    YACC=:
    HOSTCFLAGS="${HOST_CFLAGS[*]} -I$HOST_ROOT/usr/include"
    HOSTLDFLAGS="${HOST_LDFLAGS[*]} -L$HOST_LIB -Wl,-rpath-link,$HOST_LIB"
)

make -C "$KERNEL" "${KBUILD_TOOLS[@]}" olddefconfig
for option in BPF_EVENTS DEBUG_FS FTRACE KPROBES TRACING UPROBE_EVENTS; do
    grep -qx "CONFIG_${option}=y" "$KERNEL/.config" || {
        echo "libkrunfw networking kernel is missing CONFIG_${option}=y" >&2
        exit 1
    }
done
# Kbuild is the dominant cold-cache E2E cost. Eight jobs fit the standard RBE
# executor and keep the trace-capable guest kernel below the uprobe test's
# deadline; callers may still lower this on constrained local machines.
make -C "$KERNEL" -j"${LIBKRUNFW_JOBS:-8}" "${KBUILD_TOOLS[@]}" \
    KBUILD_BUILD_TIMESTAMP='Mon Jun  1 16:28:39 CEST 2026' \
    KBUILD_BUILD_USER=root \
    KBUILD_BUILD_HOST=libkrunfw \
    vmlinux

VMLINUX="$KERNEL/vmlinux"
"$PYTHON" "$BUNDLER" "$VMLINUX" "$SOURCE/kernel.bin" "$SOURCE/kernel.meta"
LOAD_HEX=""
ENTRY_HEX=""
while IFS='=' read -r key value; do
    case "$key" in
        load) LOAD_HEX="$value" ;;
        entry) ENTRY_HEX="$value" ;;
    esac
done <"$SOURCE/kernel.meta"
if [[ -z "$LOAD_HEX" || -z "$ENTRY_HEX" ]]; then
    echo "kernel.meta is missing load/entry addresses" >&2
    exit 1
fi

cat >"$SOURCE/kernel.S" <<'EOF'
/* libkrun maps this storage directly as x86_64 guest RAM. Match upstream's
 * writable char[]; a read-only section lets the VMM start but faults before the
 * kernel can emit console output. */
.section .data,"aw",@progbits
.balign 65536
.global KERNEL_BUNDLE
.type KERNEL_BUNDLE,@object
KERNEL_BUNDLE:
.incbin "kernel.bin"
.global KERNEL_BUNDLE_END
KERNEL_BUNDLE_END:
.byte 0
.size KERNEL_BUNDLE, . - KERNEL_BUNDLE
.section .note.GNU-stack,"",@progbits
EOF
cat >"$SOURCE/wrapper.c" <<EOF
#include <stddef.h>
extern char KERNEL_BUNDLE[];
extern char KERNEL_BUNDLE_END[];
char *krunfw_get_kernel(size_t *load_addr, size_t *entry_addr, size_t *size) {
    *load_addr = ${LOAD_HEX};
    *entry_addr = ${ENTRY_HEX};
    *size = (size_t)(KERNEL_BUNDLE_END - KERNEL_BUNDLE);
    return KERNEL_BUNDLE;
}
int krunfw_get_version(void) { return ${ABI_VERSION}; }
EOF

# The wrapper is ordinary host userspace, so it links with the same toolchain
# flags Kbuild's host tools used -- without them clang cannot even find a
# linker on the bare executor image. Assembling from $SOURCE is what lets
# kernel.S resolve its `.incbin "kernel.bin"` beside it.
(cd "$SOURCE" && "$TOOL_CC" "${HOST_CFLAGS[@]}" "${HOST_LDFLAGS[@]}" \
    -fPIC "-DABI_VERSION=${ABI_VERSION}" -shared \
    "-Wl,-soname,${SONAME}" -o libkrunfw.so.5.5.0 wrapper.c kernel.S)
"$TOOL_STRIP" "$SOURCE/libkrunfw.so.5.5.0"
cp "$SOURCE/libkrunfw.so.5.5.0" "$OUTPUT"
