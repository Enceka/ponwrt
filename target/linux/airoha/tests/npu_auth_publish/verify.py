import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import resource
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "npu_ingress"))
from source_binding import SourceBinding

FINAL_PATCH = "999-zw-net-airoha-align-pon-auth-bank-metadata.patch"


MUTANTS = (
    ("reject-bank0", "raw[3] > 1u", "raw[3] != 1u"),
    ("reject-bank1", "raw[3] > 1u", "raw[3] != 0u"),
    ("accept-invalid-bank", "raw[3] > 1u", "0u"),
    ("allow-cross-bank-duplicate-row", "raw[4] == other[4]",
     "(raw[3] == other[3] && raw[4] == other[4])"),
    ("allow-cross-bank-duplicate-token", "raw[2] == other[2]",
     "(raw[3] == other[3] && raw[2] == other[2])"),
    ("allow-cross-bank-duplicate-tuple",
     "!memcmp(key, other + 9, 11u * sizeof(auth_u32))",
     "(raw[3] == other[3] && !memcmp(key, other + 9, 11u * sizeof(auth_u32)))"),
    ("rewrite-published-bank",
     "memcpy(message.w + AM_RULE, rule->raw, sizeof(rule->raw));",
     "memcpy(message.w + AM_RULE, rule->raw, sizeof(rule->raw));\n"
     "\tmessage.w[AM_RULE + 3] = 1u;"),
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


def run(arguments, environment, log, expect_success=True):
    result = subprocess.run(
        [str(argument) for argument in arguments],
        env=environment,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=120,
    )
    log.write_text(result.stdout)
    if expect_success and result.returncode:
        raise RuntimeError(
            "command failed: " + shlex.join([str(value) for value in arguments])
            + "\n" + result.stdout
        )
    return result


def main():
    tests = Path(__file__).resolve().parent
    repository = tests.parents[4]
    parser = argparse.ArgumentParser(description="Exercise the production AUTH header through ZW against firmware.")
    parser.add_argument(
        "--source-snapshot", "--source", dest="source_snapshot",
        type=Path,
        default=repository.parent / "pon-npu-diag-20261127/auth-bank-metadata/source",
    )
    parser.add_argument(
        "--firmware",
        type=Path,
        default=repository.parent.parent / "an7581-npu-firmware",
    )
    parser.add_argument("--cc", default=os.environ.get("CC", "clang"))
    parser.add_argument("--output", type=Path,
                        default=repository.parent / "pon-npu-diag-20261127/auth-bank-metadata" /
                        ("publish-" + datetime.now().strftime("%Y%m%d-%H%M%S")))
    arguments = parser.parse_args()
    firmware = arguments.firmware.resolve()
    snapshot = arguments.source_snapshot.resolve()
    output = arguments.output.resolve()
    if (output.is_relative_to(repository) or any(
            output == root or output.is_relative_to(root) or root.is_relative_to(output)
            for root in (snapshot, firmware))):
        parser.error("output must be new, outside ponwrt, and separate from source and firmware")
    output.mkdir(parents=True, exist_ok=False)
    relative_header = Path("drivers/net/ethernet/airoha/airoha_npu_auth_publish.h")
    abi_name = "npu_auth_mailbox_abi.h"
    abi_file = snapshot / relative_header.parent / abi_name
    inputs = {path: path.read_bytes() for path in (
        snapshot / relative_header, abi_file, firmware / "src/ingress_auth.c",
        firmware / "include/npu_ingress_auth.h", firmware / "include" / abi_name,
    )}
    test_inputs = {tests / name: (tests / name).read_bytes()
                   for name in ("verify.py", "publish_test.c", "README.md")}
    helper = tests.parent / "npu_ingress/source_binding.py"
    helper_bytes = helper.read_bytes()
    binding = SourceBinding(repository / "target/linux/airoha/patches-6.18", output, FINAL_PATCH)
    binding.bind(snapshot / relative_header.parent, (relative_header.name,))
    if inputs[abi_file] != inputs[firmware / "include" / abi_name]:
        raise RuntimeError("snapshot and firmware mailbox ABI headers differ")
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    environment = dict(os.environ)
    environment["ASAN_OPTIONS"] = "halt_on_error=1:abort_on_error=1"
    environment["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
    temporary = output / "tmp"
    temporary.mkdir()
    environment["TMPDIR"] = str(temporary)
    compiler = shlex.split(arguments.cc)
    flags = [
        "-std=c11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
        "-Wshadow", "-Wstrict-prototypes", "-fno-omit-frame-pointer",
        "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
        "-DNPU_CT_FE_PON_AUTH=1",
    ]
    version = run(compiler + ["--version"], environment, output / "compiler.log").stdout
    print("Compiler: " + version.splitlines()[0], flush=True)
    print("Flags: " + shlex.join(flags), flush=True)
    print("PASS exact source binding through " + FINAL_PATCH, flush=True)
    original = inputs[snapshot / relative_header].decode()
    firmware_object = output / "ingress_auth.o"
    firmware_build = compiler + flags + ["-I", str(firmware / "include"),
        "-c", str(firmware / "src/ingress_auth.c"), "-o", str(firmware_object)]
    run(firmware_build, environment, output / "firmware-build.log")
    commands = [firmware_build]

    def build_run(name, header_text):
        directory = output / name
        directory.mkdir()
        (directory / relative_header.name).write_text(header_text)
        (directory / abi_name).write_bytes(inputs[abi_file])
        executable = directory / "publish_test"
        build = compiler + flags + ["-I", str(directory), "-I", str(firmware / "include"),
            str(tests / "publish_test.c"), str(firmware_object), "-o", str(executable)]
        commands.extend((build, [str(executable)]))
        run(build, environment, directory / "build.log")
        return run([executable], environment, directory / "run.log", expect_success=False)

    baseline = build_run("baseline", original)
    if baseline.returncode:
        raise RuntimeError("baseline failed:\n" + baseline.stdout)
    summary = json.loads(baseline.stdout)
    assert summary["passed"]
    print("PASS baseline " + baseline.stdout.strip(), flush=True)
    detected = []
    for name, before, after in MUTANTS:
        if original.count(before) != 1:
            raise RuntimeError("mutant anchor is not unique: " + name)
        result = build_run(name, original.replace(before, after, 1))
        if (result.returncode != 1 or "CHECK failed [" not in result.stdout or
                "Sanitizer" in result.stdout or "runtime error:" in result.stdout):
            raise RuntimeError("mutant requires a runtime CHECK failure: " + name + "\n" + result.stdout)
        failure = next(line for line in result.stdout.splitlines() if "CHECK failed [" in line)
        detected.append({"name": name, "exit_code": result.returncode, "assertion": failure})
        print("KILLED " + name + ": " + failure, flush=True)
    binding.verify_unchanged()
    for path, data in {**inputs, **test_inputs, helper: helper_bytes}.items():
        if path.read_bytes() != data:
            raise RuntimeError("input changed during run: " + str(path))
    report = {
        "passed": True, "baseline": summary, "source_binding": binding.report(),
        "sanitizers": ["address", "undefined"], "negative_controls": detected,
        "source_binding_helper_sha256": hashlib.sha256(helper_bytes).hexdigest(),
        "inputs_sha256": {str(path): hashlib.sha256(data).hexdigest() for path, data in inputs.items()},
        "tests_sha256": {path.name: hashlib.sha256(data).hexdigest() for path, data in test_inputs.items()},
        "compiler": version, "commands": commands,
        "scope": "Public AUTH validator/publication helper linked with unchanged firmware ingress_auth.c; owner admission and diagnostic publication are tested separately.",
    }
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print("PASS: source binding; address/undefined sanitizers; " + str(len(detected)) +
          "/" + str(len(MUTANTS)) + " runtime mutants; report: " + str(output / "report.json"), flush=True)


if __name__ == "__main__":
    main()
