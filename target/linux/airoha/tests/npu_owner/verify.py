#!/usr/bin/env python3
"""Exercise the production NPU owner and return lifetime with boundary failures."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess


def main():
    tests = Path(__file__).resolve().parent
    spec = importlib.util.spec_from_file_location(
        'core_verifier', tests.parent / 'npu_transaction_core' / 'verify.py')
    helper = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(helper)
    route_spec = importlib.util.spec_from_file_location(
        'route_verifier', tests.parent / 'bank1_routes' / 'verify.py')
    route_helper = importlib.util.module_from_spec(route_spec)
    route_spec.loader.exec_module(route_helper)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, default=tests / 'out')
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--source', type=Path, required=True,
                        help='Kernel tree with patches through 996 applied')
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    if report_path.exists():
        report_path.unlink()
    patches = tests.parents[1] / 'patches-6.18'
    paths = {number: next(patches.glob(number + '-*.patch'))
             for number in ('988', '989', '990', '993', '994', '995', '996')}
    inputs = {number: path.read_bytes() for number, path in paths.items()}
    sources = {}
    for name in (*helper.ABIS, 'airoha_npu_transaction.h'):
        sources[name] = helper.added_file(inputs['988'].decode(), name)
    sources[helper.CORE] = helper.added_file(inputs['990'].decode(), helper.CORE)
    sources['airoha_eth_return.h'] = helper.added_file(inputs['989'].decode(), 'airoha_eth_return.h')
    owner_name = 'airoha_npu_owner.h'
    sources[owner_name] = helper.added_file(inputs['993'].decode(), owner_name)
    expected = output / 'expected/drivers/net/ethernet/airoha'
    expected.mkdir(parents=True, exist_ok=True)
    (expected / owner_name).write_bytes(sources[owner_name])
    return_patch = inputs['994'].decode()
    for number in ('994', '996'):
        owner_patch = '--- a/drivers/net/ethernet/airoha/' + owner_name + '\n'
        owner_patch += inputs[number].decode().split(owner_patch, 1)[1].split('--- /dev/null', 1)[0]
        applied = subprocess.run(['patch', '--batch', '-p1'], input=owner_patch,
                                 cwd=output / 'expected', capture_output=True, text=True)
        (output / ('apply-' + number + '.log')).write_text(applied.stdout + applied.stderr)
        if applied.returncode:
            raise RuntimeError('cannot apply ' + number + ' owner: ' + applied.stdout + applied.stderr)
    sources[owner_name] = (expected / owner_name).read_bytes()
    return_name = 'airoha_npu_return.h'
    sources[return_name] = helper.added_file(return_patch, return_name)
    admission_name = 'airoha_npu_admission.h'
    sources[admission_name] = helper.added_file(inputs['996'].decode(), admission_name)
    publish_name = 'airoha_npu_auth_publish.h'
    sources[publish_name] = helper.added_file(inputs['995'].decode(), publish_name)
    driver = args.source.resolve() / 'drivers/net/ethernet/airoha'
    if (driver / owner_name).read_bytes() != sources[owner_name]:
        raise RuntimeError('kernel owner differs from current 993/994/996')
    if (driver / return_name).read_bytes() != sources[return_name]:
        raise RuntimeError('kernel return owner differs from current 994')
    for name in (admission_name, publish_name):
        if (driver / name).read_bytes() != sources[name]:
            raise RuntimeError('kernel admission source differs: ' + name)
    ppe_source = (driver / 'airoha_ppe.c').read_text()
    sources['commit_entry.inc'] = route_helper.extract_function(
        ppe_source, 'airoha_ppe_foe_commit_entry').encode()
    sources['stop_entry.inc'] = route_helper.extract_function(
        ppe_source, 'airoha_ppe_ct_stop').encode()
    sources['shutdown_entry.inc'] = route_helper.extract_function(
        ppe_source.replace('int airoha_ppe_ct_shutdown(', 'static int airoha_ppe_ct_shutdown('),
        'airoha_ppe_ct_shutdown').encode()
    extracted = output / 'source'
    extracted.mkdir(exist_ok=True)
    for name, data in sources.items():
        (extracted / name).write_bytes(data)
    command = [args.cc, '-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
               '-Wno-unused-parameter', '-fsanitize=address,undefined',
               '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
               '-I', str(extracted), str(tests / 'owner_test.c'),
               '-o', str(output / 'owner_test')]
    helper.execute(command, output, 'build')
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    result = helper.execute([str(output / 'owner_test')], output, 'owner_test', environment)
    mutants = {
        'drain_wrong_bank': ('REG_PPE_PPE_FLOW_CFG(1)', 'REG_PPE_PPE_FLOW_CFG(0)'),
        'resnapshot_on_retry': ('if (!owner->bank1_saved)', 'if (true)'),
        'truncate_generation': ('if (generation > U32_MAX)', 'if (false)'),
        'release_before_closed': ('if (owner->txn.phase != NPU_TXN_CLOSED || !owner->bank1_saved ||\n'
                                 '\t    owner->return_path || owner->epoch_dirty)',
                                  'if (false)'),
        'reuse_return_epoch': ('if (owner->epoch_dirty && owner->txn.phase == NPU_TXN_CLOSED)',
                              'if (false)'),
    }
    return_mutants = {
        'return_ignore_config': ('memcmp(config, &path->config, sizeof(*config))', 'false'),
        'return_ignore_mapping': ('rcu_dereference(dev->pon_flow_table) == path->table', 'true'),
        'return_truncate_service': ('(service & 0xffff)', '(service & 0xfff)'),
        'return_reuse_retiring': ('smp_store_release(&path->bound, false);', ''),
    }
    mutants.update(return_mutants)
    admission_mutants = {
        'auth_repeat_publish': (' || owner->auth_attempted)', ')'),
        'ignore_auth_service': ('ER_SERVICE_VALID | rules[index].raw[7]', 'ER_SERVICE_VALID'),
        'ignore_post_auth_generation': ('if (!error)\n\t\terror = airoha_npu_owner_return_ready(owner, &owner->txn.id);', ''),
        'ignore_auth_state': ('message.w[AM_COUNT] != owner->auth_count', 'false'),
        'ignore_ready_query_race': ('return airoha_npu_owner_return_ready(owner, id);', 'return 0;'),
        'renew_before_retiring': ('error = airoha_ppe_npu_owner_close_locked(eth);\n\tif (error)\n\t\treturn error;', 'error = 0;'),
    }
    mutants.update(admission_mutants)
    mutation_results = {}
    mutants['repeat_restored_stop'] = (
        'if (ppe->ct_npu_owner && ppe->ct_npu_owner->stop_completed)', 'if (false)')
    mutants['repeat_native_stop'] = (
        'if (ppe->ct_npu_owner && ppe->ct_npu_owner->native_stopped)', 'if (false)')
    for name, (before, after) in mutants.items():
        target_name = ('stop_entry.inc' if name.startswith('repeat_') else
                       return_name if name in return_mutants else
                       admission_name if name in admission_mutants else owner_name)
        original = sources[target_name].decode()
        if before not in original:
            raise RuntimeError('missing mutation target: ' + name)
        (extracted / target_name).write_text(original.replace(before, after))
        helper.execute(command, output, name + '-build')
        run = subprocess.run([str(output / 'owner_test')], capture_output=True,
                             text=True, cwd=output, env=environment)
        (output / (name + '.log')).write_text(run.stdout + run.stderr)
        if run.returncode == 0 or 'CHECK failed:' not in run.stderr:
            raise RuntimeError('mutation was not rejected by a runtime assertion: ' + name)
        mutation_results[name] = 'caught'
        (extracted / target_name).write_bytes(sources[target_name])
    (extracted / owner_name).write_bytes(sources[owner_name])
    helper.execute(command, output, 'build-final')
    for number, path in paths.items():
        if path.read_bytes() != inputs[number]:
            raise RuntimeError(number + ' changed during testing')
    sha256 = lambda data: hashlib.sha256(data).hexdigest()
    report = {
        'passed': True, 'sanitizers': ['address', 'undefined'], 'result': result,
        'mutations': mutation_results,
        'patch_sha256': {number: sha256(data) for number, data in inputs.items()},
        'source_sha256': {name: sha256(data) for name, data in sources.items()},
        'test_sha256': {name: sha256((tests / name).read_bytes())
                        for name in ('verify.py', 'owner_test.c', 'return_types.h',
                                     'return_stubs.inc', 'return_test.inc', 'admission_test.inc')},
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(result)
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
