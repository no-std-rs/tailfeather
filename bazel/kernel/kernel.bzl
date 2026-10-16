"""Builds libkrunfw's kernel support artifact as a remotely executable action.

The kernel build used to be a genrule tagged `no-remote-exec`, which pushed it
onto the BuildBuddy workflow runner and made it depend on whatever packages that
image happened to carry. This rule declares every tool instead: the compiler,
linker and strip come from the registered `@llvm` toolchain via `all_files`,
and the remaining host tools (make, libelf) are checksum-pinned Debian packages
passed as `host_packages`. Nothing is read from the ambient environment, so the
action runs on the standard pinned executor like every other target.
"""

load("@rules_cc//cc:action_names.bzl", "ACTION_NAMES")
load("@rules_cc//cc:find_cc_toolchain.bzl", "find_cc_toolchain", "use_cc_toolchain")
load("@rules_cc//cc/common:cc_common.bzl", "cc_common")

def _krunfw_kernel_impl(ctx):
    cc_toolchain = find_cc_toolchain(ctx)
    output = ctx.actions.declare_file(ctx.label.name + ".so")

    # The @llvm toolchain leaves the legacy cc_toolchain.*_executable fields
    # empty, so resolve clang through the feature configuration. Every other
    # tool Kbuild wants (ld.lld, llvm-ar, llvm-nm, llvm-objcopy, llvm-strip)
    # ships in the same bin directory, so the script derives them from clang's
    # location via Kbuild's LLVM_PREFIX rather than taking six more flags.
    feature_configuration = cc_common.configure_features(
        ctx = ctx,
        cc_toolchain = cc_toolchain,
        requested_features = ctx.features,
        unsupported_features = ctx.disabled_features,
    )
    compiler = cc_common.get_tool_for_action(
        feature_configuration = feature_configuration,
        action_name = ACTION_NAMES.c_compile,
    )

    # Kbuild's host tools (fixdep, objtool, ...) are ordinary userspace programs,
    # so they need the toolchain's own sysroot flags; the bare executor image has
    # no libc headers or libraries of its own. The kernel proper builds
    # -nostdinc against its own headers and does not take these.
    host_cflags = cc_common.get_memory_inefficient_command_line(
        feature_configuration = feature_configuration,
        action_name = ACTION_NAMES.c_compile,
        variables = cc_common.create_compile_variables(
            feature_configuration = feature_configuration,
            cc_toolchain = cc_toolchain,
        ),
    )
    host_ldflags = cc_common.get_memory_inefficient_command_line(
        feature_configuration = feature_configuration,
        action_name = ACTION_NAMES.cpp_link_executable,
        variables = cc_common.create_link_variables(
            feature_configuration = feature_configuration,
            cc_toolchain = cc_toolchain,
        ),
    )

    args = ctx.actions.args()
    args.add("--libkrunfw-archive", ctx.file.libkrunfw_archive)
    args.add("--linux-archive", ctx.file.linux_archive)
    args.add("--output", output)
    args.add("--python", ctx.file._python)
    args.add("--bundler", ctx.file._bundler)
    args.add("--kconfig-lexer", ctx.file.kconfig_lexer)
    args.add("--kconfig-parser", ctx.file.kconfig_parser)
    args.add("--kconfig-header", ctx.file.kconfig_header)
    args.add("--cc", compiler)
    args.add_all(host_cflags, before_each = "--host-cflag")
    args.add_all(host_ldflags, before_each = "--host-ldflag")
    args.add("--soname", ctx.attr.soname)
    args.add("--abi-version", str(ctx.attr.abi_version))
    args.add_all(ctx.files.host_packages, before_each = "--host-package")
    args.add_all(ctx.attr.config_edits, before_each = "--config-edit")

    inputs = depset(
        ctx.files.host_packages + [
            ctx.file.libkrunfw_archive,
            ctx.file.linux_archive,
            ctx.file._bundler,
            ctx.file._python,
            ctx.file.kconfig_lexer,
            ctx.file.kconfig_parser,
            ctx.file.kconfig_header,
        ],
        transitive = [
            cc_toolchain.all_files,
            ctx.attr._python_files[DefaultInfo].files,
        ],
    )

    ctx.actions.run(
        # The FilesToRunProvider, not ctx.executable: the launcher alone is just
        # a stub, and its runfiles carry the script it execs.
        executable = ctx.attr._builder[DefaultInfo].files_to_run,
        arguments = [args],
        inputs = inputs,
        outputs = [output],
        mnemonic = "KrunfwKernel",
        progress_message = "Building libkrunfw kernel %{label}",
        # Deliberately no execution_requirements: this action is meant to be
        # remotely executable and cacheable like anything else.
    )
    return [DefaultInfo(files = depset([output]))]

krunfw_kernel = rule(
    implementation = _krunfw_kernel_impl,
    doc = "Builds a libkrunfw-compatible shared library embedding a Linux kernel.",
    attrs = {
        "abi_version": attr.int(
            default = 5,
            doc = "libkrunfw ABI version reported by krunfw_get_version.",
        ),
        "config_edits": attr.string_list(
            doc = "scripts/config edits applied to libkrunfw's baseline config, " +
                  "as `-e OPTION` / `-d OPTION` pairs.",
        ),
        "host_packages": attr.label_list(
            allow_files = True,
            doc = "Checksum-pinned Debian packages unpacked into the action's host root.",
        ),
        "kconfig_header": attr.label(allow_single_file = True, mandatory = True),
        "kconfig_lexer": attr.label(allow_single_file = True, mandatory = True),
        "kconfig_parser": attr.label(allow_single_file = True, mandatory = True),
        "libkrunfw_archive": attr.label(allow_single_file = True, mandatory = True),
        "linux_archive": attr.label(allow_single_file = True, mandatory = True),
        "soname": attr.string(
            default = "libkrunfw.so.5",
            doc = "SONAME recorded in the produced shared library.",
        ),
        "_builder": attr.label(
            default = Label("//scripts:build-libkrunfw-networking"),
            executable = True,
            cfg = "exec",
        ),
        "_bundler": attr.label(
            default = Label("//scripts:elf-kernel-bundle.py"),
            allow_single_file = True,
        ),
        # A source-file alias, not an executable target, so it is declared as a
        # file and the interpreter tree is pulled in via _python_files.
        "_python": attr.label(
            default = Label("@python_3_13//:python3"),
            allow_single_file = True,
        ),
        "_python_files": attr.label(default = Label("@python_3_13//:files")),
    },
    toolchains = use_cc_toolchain(),
    fragments = ["cpp"],
)
