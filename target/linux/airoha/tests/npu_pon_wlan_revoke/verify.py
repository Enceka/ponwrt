"""Replay ZZA exactly, then exercise the production WLAN revoke/cleanup code."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / "npu_ingress"))
from source_binding import SourceBinding, exact_hunks

DRIVER = Path("drivers/net/ethernet/airoha")
PATCH = "999-zza-net-airoha-preserve-pon-session-on-wlan-revoke.patch"
FILES = ("airoha_eth.h", "airoha_ppe.c", "airoha_npu_owner.h", "airoha_ct_native_pair.h")


def function(source, name):
    match = re.search(r"^(?:static )?[^;{}\n]+\b" + name + r"\([^;{}]*\)\n\{", source, re.M)
    if not match:
        raise ValueError("missing function: " + name)
    opening = source.index("{", match.start())
    depth, cursor = 1, opening + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[match.start():cursor] + "\n"


def bind(source, output):
    patch_path = REPOSITORY / "target/linux/airoha/patches-6.18" / PATCH
    patch = patch_path.read_bytes()
    assert patch.startswith(b"From: Enceka <enceka@yeah.net>\n")
    targets = re.findall(r"^\+\+\+ b/(.+)$", patch.decode(), re.M)
    assert targets == [str(DRIVER / "airoha_ct_native_pair.h")], targets
    inputs = {source / DRIVER / name: (source / DRIVER / name).read_bytes() for name in FILES}
    inputs[patch_path] = patch
    kernel = output / "kernel"
    (kernel / DRIVER).mkdir(parents=True)
    for name in FILES:
        (kernel / DRIVER / name).write_bytes(inputs[source / DRIVER / name])
    binding = SourceBinding(patch_path.parent, output, PATCH)
    sections = list(binding.sections(patch, ["airoha_ct_native_pair.h"]))
    assert len(sections) == 1 and not sections[0][1]
    exact_hunks(inputs[source / DRIVER / "airoha_ct_native_pair.h"], sections[0][2])
    patch_copy = output / PATCH
    patch_copy.write_bytes(patch)
    result = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0",
                             "--no-backup-if-mismatch", "-p1", "-d", str(kernel), "-i", str(patch_copy)],
                            text=True, capture_output=True, check=True, timeout=30)
    assert not re.search(r"offset|fuzz|FAILED|reversed", result.stdout + result.stderr, re.I)
    print("binding: complete ZZA exact replay; baseline source unchanged", flush=True)
    print("PATCH sha256=" + hashlib.sha256(patch).hexdigest(), flush=True)
    return kernel / DRIVER, inputs


def render(driver):
    files = {name: (driver / name).read_text() for name in FILES}
    types = files["airoha_eth.h"]
    start = types.index("enum {\n\tAIROHA_FOE_STATE_INVALID,")
    end = types.index("struct airoha_foe_stats {", start)
    entry_size = re.search(r"^#define PPE_ENTRY_SIZE\s+\d+$", types, re.M)[0]
    port_start = types.index("enum {\n\tFE_PSE_PORT_CDM1,")
    port_end = types.index("};", port_start) + 2
    ppe_functions = ("airoha_ppe_foe_compare_entry", "airoha_ppe_ct_wlan_dest",
                     "airoha_ppe_ct_wlan_entry", "airoha_ppe_ct_epoch_locked",
                     "airoha_ppe_ct_wlan_epoch", "airoha_ppe_ct_bridge_row_matches",
                     "airoha_ppe_ct_remove_wlan_flow_locked", "airoha_ppe_ct_remove_wlan_flow",
                     "airoha_ppe_ct_flush_wlan")
    replacements = {
        "@FOE_TYPES@": entry_size + "\n" + types[start:end] + types[port_start:port_end],
        "@PRODUCTION_ACTIVE@": function(files["airoha_npu_owner.h"], "airoha_ppe_npu_production_active"),
        "@REVOKE@": function(files["airoha_ct_native_pair.h"], "airoha_ct_native_pair_revoke"),
        "@PPE_FUNCTIONS@": "\n".join(function(files["airoha_ppe.c"], name) for name in ppe_functions),
    }
    template = (HERE / "revoke_test.c").read_text()
    for marker, content in replacements.items():
        assert template.count(marker) == 1, marker
        template = template.replace(marker, content)
    return template, replacements


def exercise(cc, source, binary, flags=()):
    compilation = subprocess.run(
        [cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
         "-Wno-unused-function", "-Wno-unused-parameter", *flags,
         "-x", "c", "-", "-o", str(binary)],
        input=source, text=True, capture_output=True, timeout=60)
    if compilation.returncode:
        raise RuntimeError("compilation failed:\n" + compilation.stdout + compilation.stderr)
    environment = dict(os.environ, ASAN_OPTIONS="halt_on_error=1:abort_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    return subprocess.run([binary], env=environment, text=True, capture_output=True, timeout=30)


def mutations(source):
    return (
        ("require-production-session", "airoha_ppe_npu_production_active(ppe, ppe->ct_npu_owner))",
         "true)"),
        ("negative-band-is-global", "band >= 0 && band <= 1 && wcid", "band <= 1 && wcid"),
        ("band-limit", "band >= 0 && band <= 1 && wcid", "band >= 0 && band <= 2 && wcid"),
        ("zero-wcid", "band <= 1 && wcid && wcid <= 150", "band <= 1 && wcid <= 150"),
        ("wcid-limit", "band <= 1 && wcid && wcid <= 150", "band <= 1 && wcid && wcid <= 151"),
        ("epoch-exhaustion", "airoha_ct_pair_fail(ppe, -EOVERFLOW) : 0", "0 : 0"),
        ("epoch-increments-once", "ppe->ct_wlan_epoch[band][wcid]++;", "ppe->ct_wlan_epoch[band][wcid] += 2;"),
        ("global-owner-notification", "err = airoha_npu_owner_notify(ppe, NULL);", "err = 0;"),
        ("bridge-source-cleanup", "e->ct_bridge && e->ct_src.band == band && e->ct_src.wcid == wcid",
         "false"),
        ("stale-row-invalidated", "err = airoha_ppe_foe_commit_entry(ppe, &invalid, e->hash, false);",
         "err = 0; (void)invalid;"),
        ("station-unblocked", "ppe->ct_wlan_blocked[band][wcid] = false;", "(void)0;"),
        ("exclusive-policy", "ppe->ct_pon_qualified || READ_ONCE(ppe->ct_pair_policy_allowed) ||",
         "ppe->ct_pon_qualified ||"),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True,
                        help="Kernel source immediately before the ZZA patch")
    parser.add_argument("--cc", default="clang")
    parser.add_argument("--mutations", action="store_true", help="Also reject 12 targeted code regressions")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="npu-pon-wlan-revoke-") as temporary:
        output = Path(temporary)
        driver, inputs = bind(args.source.resolve(), output)
        inputs.update({path: path.read_bytes() for path in HERE.iterdir() if path.is_file()})
        source, replacements = render(driver)
        for label, flags in (("plain", ()), ("sanitized", ("-fsanitize=address,undefined", "-fno-sanitize-recover=all"))):
            result = exercise(args.cc, source, output / label, flags)
            print(label + ": " + result.stdout.strip(), flush=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
        if args.mutations:
            for name, original, replacement in mutations(source):
                assert source.count(original) == 1, name
                mutated = source.replace(original, replacement)
                result = exercise(args.cc, mutated, output / name)
                assert result.returncode, "mutation escaped: " + name
                print("rejected: " + name, flush=True)
        for marker, content in replacements.items():
            print(marker.strip("@") + " sha256=" + hashlib.sha256(content.encode()).hexdigest())
        for path, original in inputs.items():
            assert path.read_bytes() == original, "input changed during test: " + str(path)
        print("inputs unchanged: canonical source, ZZA patch, test files", flush=True)


if __name__ == "__main__":
    main()
