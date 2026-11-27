#!/usr/bin/env python3
"""Execute the production optical IFC owner with exhaustive transport faults."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import shutil
import signal
import subprocess


def mutate_function(text, name, old, new, last=False):
    start = text.index(name + '(')
    begin = text.index('{', start)
    depth = 1
    end = begin + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    body = text[start:end]
    assert old in body, (name, old)
    position = body.rindex(old) if last else body.index(old)
    body = body[:position] + new + body[position + len(old):]
    return text[:start] + body + text[end:]


def execute(directory, test, sanitized):
    binary = directory / 'test'
    command = ['clang', '-O1', '-g', '-std=gnu11', '-Wall', '-Wextra', '-Werror']
    if sanitized:
        command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                    '-fno-omit-frame-pointer']
    command += ['-I', str(directory), str(test), '-o', str(binary)]
    (directory / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
    compiled = subprocess.run(command, capture_output=True, text=True)
    (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    tested = subprocess.run([str(binary)], capture_output=True, text=True)
    (directory / 'stdout.txt').write_text(tested.stdout)
    (directory / 'stderr.txt').write_text(tested.stderr)
    (directory / 'exit-status.json').write_text(json.dumps({'returncode': tested.returncode}) + '\n')
    return tested


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    headers = args.source.resolve() / 'drivers/net/ethernet/airoha'
    owner = (headers / 'airoha_ct_pon_ifc_owner.h').read_text()
    words = (headers / 'airoha_ct_pon_ifc_words.h').read_text()
    test = output / 'ifc_owner_test.c'
    shutil.copyfile(Path(__file__).with_name(test.name), test)
    results = []
    for mode in ('plain', 'sanitized'):
        directory = output / mode
        directory.mkdir()
        (directory / 'airoha_ct_pon_ifc_owner.h').write_text(owner)
        (directory / 'airoha_ct_pon_ifc_words.h').write_text(words)
        tested = execute(directory, test, mode == 'sanitized')
        tested.check_returncode()
        result = json.loads(tested.stdout)
        expected_faults = result['fault_modes'] * (
            result['snapshot_positions'] + 4 * result['publish_positions_per_slot'] +
            result['restore_positions'] + 2 * result['withdraw_positions_per_slot'])
        direct_restore_faults = result['fault_modes'] * 4 * result['direct_restore_positions_per_slot']
        retry_faults = result['fault_modes'] * (
            result['snapshot_positions'] + 2 * result['publish_positions_per_slot'] +
            2 * result['withdraw_positions_per_slot'] + result['restore_positions'] // 4)
        assert result['retry_fault_cases'] == retry_faults
        assert result['passed'] and result['fault_cases'] == (
            expected_faults + direct_restore_faults + retry_faults)
        assert result['failed_drain_checks'] >= expected_faults * 2 + retry_faults * 4
        results.append(dict(mode=mode, **result))
    assert {key: value for key, value in results[0].items() if key != 'mode'} == {
        key: value for key, value in results[1].items() if key != 'mode'}

    prefix = 'airoha_ct_pon_ifc_'
    mutations = [
        ('snapshot_accepts_enabled', 'snapshot',
         'if (owner->saved[row].action[2][0] & BIT(31))', 'if (false)', False),
        ('snapshot_premature_shadow', 'snapshot',
         'owner->saved[row] = (struct airoha_ct_pon_ifc_words) {};',
         'owner->saved_valid = true;\n\t\towner->saved[row] = (struct airoha_ct_pon_ifc_words) {};', False),
        ('snapshot_loses_pending', 'snapshot', 'owner->pending = true;', 'owner->pending = false;', False),
        ('skips_drain', 'sync', 'if (!owner->pending)', 'if (true)', False),
        ('ignores_drain_error', 'sync', 'return err;', 'return 0;', False),
        ('clears_pending_on_drain_error', 'sync', 'if (!err)', 'if (true)', False),
        ('publish_missing_dirty', 'publish', 'owner->dirty |= mask;', 'owner->dirty |= 0;', False),
        ('publish_premature_active', 'publish', 'owner->active &= ~mask;', 'owner->active |= mask;', False),
        ('publish_closes_one_row', 'publish', 'index < 2', 'index < 1', False),
        ('publish_missing_dependency', 'publish', 'page < 9', 'page < 8', False),
        ('publish_enables_one_row', 'publish', 'index < 2', 'index < 1', True),
        ('publish_wrong_slot', 'publish', 'first = slot * 2;', 'first = 0;', False),
        ('publish_overwrites_shadow', 'publish', 'owner->dirty |= mask;',
         'owner->saved[first] = rows[0];\n\towner->dirty |= mask;', False),
        ('restore_closes_one_row', 'restore_mask',
         'row < AIROHA_CT_PON_IFC_ROW_COUNT', 'row < 1', False),
        ('restore_action2_before_dependencies', 'restore_mask', 'page < 2', 'page < 3', False),
        ('restore_loses_dirty', 'restore_mask', 'owner->dirty |= dirty;', 'owner->dirty &= ~dirty;', False),
        ('restore_loses_shadow_on_error', 'restore_mask', 'owner->pending = true;',
         'owner->saved_valid = false;\n\towner->pending = true;', False),
        ('restore_never_clears_dirty', 'restore_mask',
         'owner->dirty &= ~BIT(row);', 'owner->dirty |= BIT(row);', False),
        ('withdraw_releases_reservation', 'withdraw',
         'return airoha_ct_pon_ifc_restore_mask(owner, io, 3 << (slot * 2));',
         'int err = airoha_ct_pon_ifc_restore_mask(owner, io, 3 << (slot * 2));\n'
         '\tif (!err)\n\t\towner->saved_valid = false;\n\treturn err;', False),
        ('restore_releases_on_error', 'restore',
         'if (!err)\n\t\towner->saved_valid = false;', 'owner->saved_valid = false;', False),
    ]

    def negative(specification):
        name, function, old, new, last = specification
        directory = output / 'mutations' / name
        directory.mkdir(parents=True)
        mutated = mutate_function(owner, prefix + function, old, new, last)
        (directory / 'airoha_ct_pon_ifc_owner.h').write_text(mutated)
        (directory / 'airoha_ct_pon_ifc_words.h').write_text(words)
        tested = execute(directory, test, True)
        assert tested.returncode == -signal.SIGABRT, (name, tested.returncode, tested.stderr)
        assert 'assert' in tested.stderr.lower() and 'failed' in tested.stderr.lower(), (name, tested.stderr)
        assert not any(marker in tested.stderr for marker in
                       ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'runtime error:')), (name, tested.stderr)
        return dict(name=name, compile_passed=True, caught_runtime=True,
                    returncode=tested.returncode, failure=tested.stderr.strip(),
                    mutated_header_sha256=hashlib.sha256(mutated.encode()).hexdigest())

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        rejected = list(executor.map(negative, mutations))
    report = dict(passed=True, modes=results, runtime_mutations=rejected,
                  source=str(args.source.resolve()),
                  production_sha256={name: hashlib.sha256((headers / name).read_bytes()).hexdigest()
                                     for name in ('airoha_ct_pon_ifc_owner.h', 'airoha_ct_pon_ifc_words.h')},
                  test_sha256=hashlib.sha256(test.read_bytes()).hexdigest(),
                  sanitizers=['address', 'undefined'])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, cases=results[0]['cases'],
                          fault_cases=results[0]['fault_cases'],
                          failed_drain_checks=results[0]['failed_drain_checks'],
                          runtime_mutations=len(rejected), report=str(output / 'report.json')), indent=2))


if __name__ == '__main__':
    main()
