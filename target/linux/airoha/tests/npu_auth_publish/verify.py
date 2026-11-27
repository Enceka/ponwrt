import argparse
import os
from pathlib import Path
import resource
import shlex
import shutil
import subprocess
import tempfile


MUTANTS = (
    (
        "accept-zero-token",
        "raw[1] != epoch || !raw[2] ||",
        "raw[1] != epoch ||",
    ),
    (
        "truncate-endpoint-to-12-bits",
        "raw[7] > 0xffffu",
        "raw[7] > 0xfffu",
    ),
    (
        "compare-full-key-instead-of-firmware-tuple",
        "11u * sizeof(auth_u32)",
        "19u * sizeof(auth_u32)",
    ),
    (
        "accept-duplicate-row",
        "raw[2] == other[2] || raw[4] == other[4] ||",
        "raw[2] == other[2] ||",
    ),
    (
        "skip-rule-echo",
        "AM_STATUS * sizeof(auth_u32)",
        "AM_RULE * sizeof(auth_u32)",
    ),
    (
        "accept-inexact-count",
        "message.w[AM_COUNT] != count",
        "message.w[AM_COUNT] > count",
    ),
    (
        "ignore-status",
        "message.w[AM_STATUS] ||",
        "0u ||",
    ),
    (
        "return-positive-callback-result",
        "return error < 0 ? error : -EPROTO;",
        "return error;",
    ),
    (
        "retry-command",
        "error = command(ctx, &message);",
        "error = command(ctx, &message);\n"
        "\tif (error)\n"
        "\t\terror = command(ctx, &message);",
    ),
    (
        "byte-swap-numeric-ports",
        "if (rule)\n"
        "\t\tmemcpy(message.w + AM_RULE, rule->raw, sizeof(rule->raw));",
        "if (rule) {\n"
        "\t\tmemcpy(message.w + AM_RULE, rule->raw, sizeof(rule->raw));\n"
        "\t\tmessage.w[AM_RULE + 19] = __builtin_bswap32(message.w[AM_RULE + 19]);\n"
        "\t}",
    ),
    (
        "skip-preflight-rejection",
        "error = airoha_npu_auth_rules_validate(epoch, generation, rules, count);\n"
        "\tif (error)\n"
        "\t\treturn error;",
        "error = airoha_npu_auth_rules_validate(epoch, generation, rules, count);",
    ),
)


def run(arguments, environment):
    result = subprocess.run(
        [str(argument) for argument in arguments],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    if result.returncode:
        raise RuntimeError(
            "command failed: " + shlex.join([str(value) for value in arguments])
            + "\n" + result.stdout
        )
    return result.stdout


def main():
    repository = Path(__file__).resolve().parents[5]
    parser = argparse.ArgumentParser(description="Exercise the applied 995 production header.")
    parser.add_argument(
        "--source-snapshot",
        type=Path,
        default=repository.parent / "pon-er-consumer-20261127" / "owner-source-final",
    )
    parser.add_argument(
        "--firmware",
        type=Path,
        default=repository.parent.parent / "an7581-npu-firmware",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    arguments = parser.parse_args()
    firmware = arguments.firmware.resolve()
    snapshot = arguments.source_snapshot.resolve()
    patch_file = repository / "target/linux/airoha/patches-6.18/995-net-airoha-validate-pon-authorization-publication.patch"
    relative_header = Path("drivers/net/ethernet/airoha/airoha_npu_auth_publish.h")
    abi_name = "npu_auth_mailbox_abi.h"
    abi_file = snapshot / relative_header.parent / abi_name
    patch_text = patch_file.read_text()
    if patch_text.splitlines()[0] != "From: Enceka <enceka@yeah.net>":
        raise RuntimeError("unexpected patch author")
    targets = [line[6:] for line in patch_text.splitlines() if line.startswith("+++ b/")]
    if targets != [str(relative_header)] or patch_text.count("--- /dev/null\n") != 1:
        raise RuntimeError("995 must add only the production publication header")
    if abi_file.read_bytes() != (firmware / "include" / abi_name).read_bytes():
        raise RuntimeError("snapshot and firmware mailbox ABI headers differ")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ)
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    compiler = shlex.split(arguments.cc)
    flags = [
        "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-Wshadow", "-Wstrict-prototypes", "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        "-DNPU_CT_FE_PON_AUTH=1",
    ]
    print("Compiler: " + run(compiler + ["--version"], environment).splitlines()[0], flush=True)
    print("Flags: " + shlex.join(flags), flush=True)
    with tempfile.TemporaryDirectory(prefix="npu-auth-publish-") as directory:
        temporary = Path(directory)
        header = temporary / relative_header
        header.parent.mkdir(parents=True)
        print(run(
            ["patch", "--batch", "-p1", "-d", temporary, "-i", patch_file],
            environment,
        ).strip(), flush=True)
        original = header.read_text()
        shutil.copyfile(abi_file, header.parent / abi_name)
        includes = ["-I", str(header.parent), "-I", str(firmware / "include")]
        firmware_object = temporary / "ingress_auth.o"
        run(
            compiler + flags + includes
            + ["-c", str(firmware / "src/ingress_auth.c"), "-o", str(firmware_object)],
            environment,
        )
        executable = temporary / "publish_test"
        build = (
            compiler + flags + includes
            + [str(Path(__file__).with_name("publish_test.c")), str(firmware_object),
               "-o", str(executable)]
        )
        run(build, environment)
        print(run([executable], environment).strip(), flush=True)
        for name, before, after in MUTANTS:
            if original.count(before) != 1:
                raise RuntimeError("mutant anchor is not unique: " + name)
            header.write_text(original.replace(before, after, 1))
            run(build, environment)
            result = subprocess.run(
                [str(executable)],
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=120,
            )
            if result.returncode == 0 or "CHECK failed [" not in result.stdout:
                raise RuntimeError("mutant was not caught by a runtime assertion: "
                                   + name + "\n" + result.stdout)
            failure = next(line for line in result.stdout.splitlines()
                           if "CHECK failed [" in line)
            print("KILLED " + name + ": " + failure, flush=True)
        header.write_text(original)
    print("PASS: applied production header; ASan/UBSan; "
          + str(len(MUTANTS)) + "/" + str(len(MUTANTS))
          + " compiled runtime mutants killed; temporary outputs removed", flush=True)


if __name__ == "__main__":
    main()
