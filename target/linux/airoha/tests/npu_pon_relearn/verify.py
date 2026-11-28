"""Replay ZZD exactly and exercise production idle-row relearning on the host."""
import argparse
import hashlib
import importlib.util
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location('timestamp_runner', HERE.parent / 'npu_pon_timestamp/verify.py')
timestamp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(timestamp)
function = timestamp.function
replace_once = timestamp.replace_once
DRIVER = timestamp.DRIVER
PATCH = '999-zzd-net-airoha-relearn-idle-production-pon-rows.patch'


def bind(baseline, applied, output):
    patches = HERE.parents[4] / 'target/linux/airoha/patches-6.18'
    binding = timestamp.SourceBinding(patches, output, PATCH)
    patch = binding.snapshot[PATCH]
    targets = re.findall(r'^\+\+\+ b/(.+)$', patch.decode(), re.M)
    assert targets == [str(DRIVER / 'airoha_npu_production.h')], targets
    inputs = {path: path.read_bytes() for path in (baseline / DRIVER).iterdir() if path.is_file()}
    inputs[patches / PATCH] = patch
    kernel = output / 'kernel'
    shutil.copytree(baseline / DRIVER, kernel / DRIVER)
    sections = list(binding.sections(patch, ['airoha_npu_production.h']))
    assert len(sections) == 1 and not sections[0][1]
    timestamp.exact_hunks(inputs[baseline / DRIVER / sections[0][0]], sections[0][2])
    patch_copy = output / PATCH
    patch_copy.write_bytes(patch)
    result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '--no-backup-if-mismatch',
                             '-p1', '-d', str(kernel), '-i', str(patch_copy)],
                            text=True, capture_output=True, check=True, timeout=30)
    assert not re.search(r'offset|fuzz|FAILED|reversed', result.stdout + result.stderr, re.I)
    if applied:
        for path in (kernel / DRIVER).iterdir():
            if path.is_file():
                actual = applied / DRIVER / path.name
                inputs[actual] = actual.read_bytes()
                assert path.read_bytes() == inputs[actual], path.name
    print('binding: complete ZZD exact replay; PATCH sha256=' + hashlib.sha256(patch).hexdigest(), flush=True)
    return kernel / DRIVER, inputs


def render(driver):
    source = timestamp.render(driver)
    source = replace_once(source, function(source, 'main'), (HERE / 'relearn_test.c').read_text())
    source = replace_once(source, 'static unsigned int checks, cases;',
                          'static unsigned int checks, cases, row_reads;\n'
                          'static unsigned int fail_read, fail_ack;\n'
                          'static u32 timestamp_now = 37;')
    source = replace_once(source, '{ return 37; }', '{ return timestamp_now; }')
    source = replace_once(source,
        '{ CHECK(ppe_lock && airoha_ppe_bank0_hash(hash)); shadow = hardware; return &shadow; }',
        '{ CHECK(ppe_lock && airoha_ppe_bank0_hash(hash)); row_reads++; '
        'if (fail_read && !--fail_read) return NULL; shadow = hardware; return &shadow; }')
    source = replace_once(source, '{ CHECK(ppe_lock); return true; }',
        '{ CHECK(ppe_lock); if (fail_ack && !--fail_ack) return false; return true; }')
    return source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, type=Path, help='Kernel source-v4 before ZZD')
    parser.add_argument('--source', type=Path, help='Optional applied source for byte comparison')
    parser.add_argument('--cc', default='clang')
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix='.run-', dir=HERE) as temporary:
        output = Path(temporary)
        driver, inputs = bind(args.baseline.resolve(), args.source.resolve() if args.source else None, output)
        for directory in (HERE, HERE.parent / 'npu_pon_production', HERE.parent / 'npu_pon_timestamp'):
            inputs.update({path: path.read_bytes() for path in directory.iterdir() if path.is_file()})
        shared = HERE.parent / 'npu_ingress/source_binding.py'
        inputs[shared] = shared.read_bytes()
        source = render(driver)
        for label, flags in (('plain', ()), ('sanitized', ('-fsanitize=address,undefined',
                                                         '-fno-sanitize-recover=all'))):
            result = timestamp.exercise(args.cc, source, driver, output / label, flags)
            print(label + ': ' + result.stdout.strip(), flush=True)
            assert result.returncode == 0, result.stderr
        helper = function(source, 'airoha_npu_production_check_event')
        step = function(source, 'airoha_npu_production_step')
        mutations = (
            ('bound-early-return', step, replace_once(step,
                '\terror = airoha_ppe_pon_take_unbound(',
                '\tif (owner->production_bound) return 0;\n\terror = airoha_ppe_pon_take_unbound(')),
            ('ignore-bound-conflict', helper, replace_once(helper,
                'return memcmp(&observed, &owner->production_entry, sizeof(observed)) ? -ESTALE : 1;',
                'return 1;')),
            ('ignore-owned-hash', helper, replace_once(helper,
                'if (hash != owner->production_hash)', 'if (false)')),
            ('ignore-read-ack', helper, replace_once(helper,
                'if (!airoha_ppe_ct_sram_ack(ppe->eth, hash, false))', 'if (false)')),
        )
        for label, original, replacement in mutations:
            result = timestamp.exercise(args.cc, replace_once(source, original, replacement),
                                        driver, output / label)
            assert result.returncode == 1 and re.search(r'(test_\w+|expect_closed):\d+:', result.stderr), label + ': ' + result.stderr
            print('rejected: ' + label, flush=True)
        for path, original in inputs.items():
            assert path.read_bytes() == original, 'input changed during test: ' + str(path)
        print('inputs unchanged; 4/4 production mutations rejected', flush=True)


if __name__ == '__main__':
    main()
