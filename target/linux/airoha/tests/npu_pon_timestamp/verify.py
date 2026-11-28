"""Replay ZZB exactly and test dynamic production row construction/lifecycle."""
import argparse
import hashlib
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
PRODUCTION = HERE.parent / "npu_pon_production"
sys.path.insert(0, str(PRODUCTION))
from verify import function
from source_binding import SourceBinding, exact_hunks

DRIVER = Path("drivers/net/ethernet/airoha")
PATCH = "999-zzb-net-airoha-refresh-production-pon-row-timestamps.patch"


def replace_once(source, original, replacement):
    assert source.count(original) == 1, original
    return source.replace(original, replacement)


def bind(baseline, applied, output):
    patches = HERE.parents[4] / "target/linux/airoha/patches-6.18"
    binding = SourceBinding(patches, output, PATCH)
    patch = binding.snapshot[PATCH]
    targets = re.findall(r"^\+\+\+ b/(.+)$", patch.decode(), re.M)
    assert targets == [str(DRIVER / "airoha_npu_production.h")], targets
    inputs = {path: path.read_bytes() for path in (baseline / DRIVER).iterdir() if path.is_file()}
    inputs.update({path: path.read_bytes() for path in (applied / DRIVER).iterdir() if path.is_file()})
    inputs[patches / PATCH] = patch
    kernel = output / "kernel"
    shutil.copytree(baseline / DRIVER, kernel / DRIVER)
    sections = list(binding.sections(patch, ["airoha_npu_production.h"]))
    assert len(sections) == 1 and not sections[0][1]
    exact_hunks(inputs[baseline / DRIVER / sections[0][0]], sections[0][2])
    patch_copy = output / PATCH
    patch_copy.write_bytes(patch)
    result = subprocess.run(["patch", "--batch", "--forward", "--fuzz=0",
                             "--no-backup-if-mismatch", "-p1", "-d", str(kernel), "-i", str(patch_copy)],
                            text=True, capture_output=True, check=True, timeout=30)
    assert not re.search(r"offset|fuzz|FAILED|reversed", result.stdout + result.stderr, re.I)
    for path in (kernel / DRIVER).iterdir():
        if path.is_file():
            assert path.read_bytes() == inputs[applied / DRIVER / path.name], path.name
    print("binding: complete ZZB exact replay; reconstructed driver matches applied source", flush=True)
    print("PATCH sha256=" + hashlib.sha256(patch).hexdigest(), flush=True)
    return kernel / DRIVER, inputs


def render(driver):
    files = {name: (driver / name).read_text() for name in (
        "airoha_eth.h", "airoha_ppe.c", "airoha_npu_owner.h",
        "airoha_npu_production.h", "airoha_npu_health.h")}
    types = files["airoha_eth.h"]
    start = types.index("enum {\n\tAIROHA_FOE_STATE_INVALID,")
    end = types.index("struct airoha_foe_stats {", start)
    entry_size = re.search(r"^#define PPE_ENTRY_SIZE\s+\d+$", types, re.M)[0]
    selected_types = "\n".join(re.search(r"struct " + name + r" \{.*?^};", types, re.M | re.S)[0]
        for name in ("airoha_pon_flow_entry", "airoha_pon_candidate_snapshot", "airoha_pon_unbound_event"))
    production = files["airoha_npu_production.h"]
    core = production[:production.index("static int airoha_npu_production_show(")] + "\n#endif\n"
    core = replace_once(core, function(core, "airoha_npu_production_idle"), "")
    replacements = {
        "@FOE_TYPES@": entry_size + "\n" + types[start:end] + selected_types,
        "@PRODUCTION_ACTIVE@": function(files["airoha_npu_owner.h"], "airoha_ppe_npu_production_active"),
        "@OWNER_CLOSE@": function(files["airoha_npu_owner.h"], "airoha_ppe_npu_owner_close_locked"),
        "@PRODUCTION_CORE@": core,
        "@REMOVE_FLOW@": function(files["airoha_ppe.c"], "airoha_ppe_ct_remove_pon_flow"),
        "@HEALTH_WORK@": function(files["airoha_npu_health.h"], "airoha_npu_owner_health_work"),
        "@SHOW@": function(production, "airoha_npu_production_show"),
    }
    source = (PRODUCTION / "production_test.c").read_text()
    source = replace_once(source, "CHECK(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC);",
                          "CHECK(!(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC));")
    source = replace_once(source, function(source, "main"), (HERE / "timestamp_test.c").read_text())
    for marker, content in replacements.items():
        source = replace_once(source, marker, content)
    print("PRODUCTION_STEP sha256=" + hashlib.sha256(
        function(production, "airoha_npu_production_step").encode()).hexdigest(), flush=True)
    return source


def exercise(cc, source, driver, binary, flags=()):
    subprocess.run([cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                    "-Wno-unused-function", "-Wno-unused-parameter", "-I", str(driver),
                    *flags, "-x", "c", "-", "-o", str(binary)],
                   input=source, text=True, check=True, timeout=60)
    environment = dict(os.environ, ASAN_OPTIONS="halt_on_error=1:abort_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    return subprocess.run([binary], env=environment, text=True, capture_output=True, timeout=30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True, help="Kernel source immediately before ZZB")
    parser.add_argument("--source", type=Path, required=True, help="Kernel source with ZZB applied")
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix=".run-", dir=HERE) as temporary:
        output = Path(temporary)
        driver, inputs = bind(args.baseline.resolve(), args.source.resolve(), output)
        inputs.update({path: path.read_bytes() for path in (
            Path(__file__).resolve(), HERE / "timestamp_test.c", HERE / "README.md",
            PRODUCTION / "production_test.c", PRODUCTION / "verify.py",
            HERE.parent / "npu_ingress/source_binding.py")})
        source = render(driver)
        for label, flags in (("plain", ()), ("sanitized", ("-fsanitize=address,undefined",
                                                             "-fno-sanitize-recover=all"))):
            result = exercise(args.cc, source, driver, output / label, flags)
            print(label + ": " + result.stdout.strip(), flush=True)
            assert result.returncode == 0, result.stderr
        step = function(source, "airoha_npu_production_step")
        baseline_step = function((args.baseline / DRIVER / "airoha_npu_production.h").read_text(),
                                 "airoha_npu_production_step")
        inherited_static = replace_once(step,
            "AIROHA_FOE_IB1_BIND_TIMESTAMP |\n\t\t       AIROHA_FOE_IB1_BIND_STATIC",
            "AIROHA_FOE_IB1_BIND_TIMESTAMP")
        for label, mutated_step, failure in (
            ("restore-static-bound", baseline_step, "test_lifecycle:"),
            ("inherit-snapshot-static", inherited_static, "test_static_snapshot:"),
        ):
            assert mutated_step != step, label
            result = exercise(args.cc, replace_once(source, step, mutated_step), driver, output / label)
            assert result.returncode == 1 and failure in result.stderr, label + ": " + result.stderr
            assert "!(hardware.ib1 & AIROHA_FOE_IB1_BIND_STATIC)" in result.stderr, result.stderr
            print("rejected: " + label + " at installed hardware STATIC check", flush=True)
        for path, original in inputs.items():
            assert path.read_bytes() == original, "input changed during test: " + str(path)
        print("inputs unchanged; 2/2 production-step mutations rejected", flush=True)


if __name__ == "__main__":
    main()
