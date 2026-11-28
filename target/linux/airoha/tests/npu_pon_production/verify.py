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
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks

DRIVER = Path('drivers/net/ethernet/airoha')
PATCH = '999-zz8-net-airoha-run-selected-pon-candidate-session.patch'


def verify_patch_source(baseline, applied, output):
    """Replay the complete submitted patch before extracting any test inputs."""
    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    patch = binding.snapshot[PATCH]
    targets = re.findall(r'^\+\+\+ b/(.+)$', patch.decode(), re.M)
    assert targets and len(targets) == len(set(targets))
    assert all(Path(name).parent == DRIVER for name in targets)
    kernel = output / 'kernel'
    shutil.copytree(baseline / DRIVER, kernel / DRIVER)
    inputs = {path: path.read_bytes() for path in (baseline / DRIVER).iterdir() if path.is_file()}
    inputs.update({applied / name: (applied / name).read_bytes() for name in targets})
    sections = list(binding.sections(patch, [Path(name).name for name in targets]))
    assert len(sections) == len(targets)
    for name, added, section in sections:
        path = kernel / DRIVER / name
        assert not added or not path.exists(), name
        exact_hunks(b'' if added else path.read_bytes(), section)
    patch_file = output / PATCH
    patch_file.write_bytes(patch)
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0',
                             '--no-backup-if-mismatch', '-p1', '-d', str(kernel), '-i', str(patch_file)],
                            text=True, capture_output=True, check=True, timeout=30)
    assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    for name in targets:
        assert (kernel / name).read_bytes() == inputs[applied / name], 'source differs from patch: ' + name
    for path in (kernel / DRIVER).iterdir():
        if path.is_file() and path.suffix in ('.h', '.inc'):
            assert (applied / DRIVER / path.name).read_bytes() == path.read_bytes(), 'dependency differs: ' + path.name
    inputs[binding.patches / PATCH] = patch
    print('binding: complete ZZ8 exact replay and ' + str(len(targets)) + ' source files matched', flush=True)
    print('PATCH sha256=' + hashlib.sha256(patch).hexdigest(), flush=True)
    return kernel / DRIVER, inputs


def function(source, name):
    match = re.search(r"^(?:static )?[^;{}\n]+\b" + name + r"\([^;{}]*\)\n\{", source, re.M)
    if not match:
        raise ValueError(name)
    opening = source.index("{", match.start())
    depth, cursor = 1, opening + 1
    while depth:
        depth += (source[cursor] == "{") - (source[cursor] == "}")
        cursor += 1
    return source[match.start():cursor] + "\n"


def main():
    parser = argparse.ArgumentParser(description="Test selected PON production sessions from applied driver source")
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--baseline", type=Path, required=True,
                        help="Kernel source immediately before the ZZ8 patch")
    parser.add_argument("--cc", default="clang")
    args = parser.parse_args()
    here = HERE
    with tempfile.TemporaryDirectory(prefix=".binding-", dir=here) as output:
        driver, inputs = verify_patch_source(args.baseline.resolve(), args.source.resolve(), Path(output))
        inputs.update({path: path.read_bytes() for path in here.iterdir() if path.is_file()})
        exercise(args, here, driver, inputs)


def exercise(args, here, driver, inputs):
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
    replacements = {
        "@FOE_TYPES@": entry_size + "\n" + types[start:end] + selected_types,
        "@PRODUCTION_ACTIVE@": function(files["airoha_npu_owner.h"], "airoha_ppe_npu_production_active"),
        "@OWNER_CLOSE@": function(files["airoha_npu_owner.h"], "airoha_ppe_npu_owner_close_locked"),
        "@PRODUCTION_CORE@": core,
        "@REMOVE_FLOW@": function(files["airoha_ppe.c"], "airoha_ppe_ct_remove_pon_flow"),
        "@HEALTH_WORK@": function(files["airoha_npu_health.h"], "airoha_npu_owner_health_work"),
        "@SHOW@": function(production, "airoha_npu_production_show"),
    }
    source = (here / "production_test.c").read_text()
    for marker, content in replacements.items():
        assert source.count(marker) == 1, marker
        source = source.replace(marker, content)
    environment = dict(os.environ, ASAN_OPTIONS="halt_on_error=1:abort_on_error=1",
                       UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    with tempfile.TemporaryDirectory(prefix=".run-", dir=here) as output:
        for label, flags in (("plain", []), ("sanitized", ["-fsanitize=address,undefined",
                                                           "-fno-sanitize-recover=all"])):
            binary = Path(output) / label
            command = [args.cc, "-std=gnu11", "-O1", "-g", "-Wall", "-Wextra", "-Werror",
                       "-Wno-unused-function", "-Wno-unused-parameter", "-I", str(driver),
                       *flags, "-x", "c", "-", "-o", str(binary)]
            subprocess.run(command, input=source, text=True, check=True, timeout=60)
            result = subprocess.run([binary], env=environment, text=True, capture_output=True, timeout=60)
            print(label + ": " + result.stdout.strip(), flush=True)
            if result.returncode:
                raise RuntimeError(result.stderr)
    for marker, content in replacements.items():
        if marker != "@FOE_TYPES@":
            print(marker.strip("@") + " sha256=" + hashlib.sha256(content.encode()).hexdigest())
    for path, original in inputs.items():
        assert path.read_bytes() == original, 'input changed during test: ' + str(path)


if __name__ == "__main__":
    main()
