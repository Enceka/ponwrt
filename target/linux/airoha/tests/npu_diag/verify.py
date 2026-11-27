#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import sys


FUNCTIONS = {
    'airoha_npu_owner.h': {'active': 'airoha_ppe_npu_diag_active',
                           'retire': 'airoha_npu_owner_retire_locked'},
    'airoha_npu_diag.h': {'platform': 'airoha_npu_diag_platform',
                         'snapshot': 'airoha_npu_diag_snapshot',
                         'start': 'airoha_npu_diag_start', 'close': 'airoha_npu_diag_close'},
    'airoha_npu_admission.h': {'authorize': 'airoha_ppe_npu_owner_authorize_locked',
                              'ready': 'airoha_npu_owner_ready'},
    'airoha_npu_reopen.h': {'open_check': 'airoha_npu_owner_open_check',
                           'restore': 'airoha_npu_owner_bank1_restore'},
    'airoha_bank1_routes.h': {'routes': 'airoha_bank1_routes_open'},
    'airoha_eth_return.c': {'er_stats': 'airoha_er_get_stats', 'er_observe': 'airoha_er_observe',
                           'er_enable': 'airoha_er_enable_observation'},
}
HEADERS = ['airoha_npu_transaction_core.h', 'airoha_npu_auth_publish.h',
           'npu_auth_mailbox_abi.h', 'npu_bank1_gate_abi.h', 'npu_eth_return_abi.h']


def digest(data):
    return hashlib.sha256(data).hexdigest()


def function(source, name):
    match = re.search(r'^(?:static )?[^;{}\n]+\b' + name + r'\([^;{}]*\)\n\{', source, re.M)
    assert match, name
    opening = source.index('{', match.start())
    depth, cursor = 1, opening + 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[match.start():cursor] + '\n'


def run(command, output, name):
    result = subprocess.run(command, text=True, capture_output=True, timeout=45)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    output = args.output.resolve()
    source = args.source.resolve()
    if output.is_relative_to(repo) or output == source or source.is_relative_to(output):
        parser.error('output must be new, outside ponwrt and separate from source')
    output.mkdir(parents=True, exist_ok=False)
    extracted = output / 'source'
    extracted.mkdir()
    driver = source / 'drivers/net/ethernet/airoha'
    inputs = {name: (driver / name).read_bytes() for name in [*FUNCTIONS, *HEADERS]}
    patch = repo / 'target/linux/airoha/patches-6.18/999-zk-net-airoha-add-ram-pon-npu-return-diagnostic.patch'
    patch_data = patch.read_bytes()
    for name, functions in FUNCTIONS.items():
        for target, symbol in functions.items():
            (extracted / (target + '.inc')).write_text(function(inputs[name].decode(), symbol))
    for name in HEADERS:
        (extracted / name).write_bytes(inputs[name])
    build = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-function', '-Wno-unused-parameter', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-I', str(extracted), str(tests / 'diag_test.c')]
    binary = output / 'npu-diag'
    run(build + ['-o', str(binary)], output, 'build')
    result = json.loads(run([str(binary)], output, 'diag'))
    review = json.loads(run([str(binary), '--review-platform'], output, 'review-platform'))
    mutations = {
        'ignore_controller': ('active.inc', 'dev->pon_link_ops == owner->diag_controller', 'true'),
        'ignore_controller_priv': ('active.inc', 'dev->pon_link_priv == owner->diag_priv', 'true'),
        'ignore_token': ('active.inc', 'owner != token ||', 'false ||'),
        'ignore_policy': ('active.inc', 'ppe->ct_pair_policy_allowed ||', 'false ||'),
        'ignore_qualification': ('active.inc', 'ppe->ct_pon_qualified ||', 'false ||'),
        'ignore_auth_count': ('active.inc', 'owner->auth_count)', 'false)'),
        'ignore_platform_dt': ('platform.inc', '!of_property_read_bool(ppe->eth->dev->of_node, "airoha,connac2-pon-er-diagnostic")', 'false'),
        'ignore_hog_available': ('platform.inc', 'node && of_device_is_available(node) &&', 'node && true &&'),
        'ignore_hog_count': ('platform.inc', 'of_property_count_u32_elems(node, "gpios") == 2', 'true'),
        'ignore_hog_gpio': ('platform.inc', 'gpios[0] == 38', 'true'),
        'ignore_hog_flags': ('platform.inc', '!gpios[1]', 'true'),
        'ignore_netdev_parent': ('start.inc', 'lower->dev.parent != eth->dev', 'false'),
        'allow_production_auth': ('authorize.inc', 'if (owner->diag_lower)', 'if (false)'),
        'ignore_empty_auth_reply': ('ready.inc', 'message.w[AM_COUNT] != owner->auth_count', 'false'),
        'ignore_restore_error': ('close.inc', 'return error ?: airoha_npu_owner_retire_locked(ppe);', 'return airoha_npu_owner_retire_locked(ppe);'),
        'ignore_release_ack': ('close.inc', '!owner->closed_ack ||', 'false ||'),
        'leak_lower_ref': ('retire.inc', 'dev_put(owner->diag_lower);', '(void)owner->diag_lower;'),
        'ignore_restore_flow': ('restore.inc', '!airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) &&', 'true &&'),
        'ignore_route_flow': ('routes.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) ||', 'false ||'),
        'ignore_route_busy': ('routes.inc', '(airoha_fe_rr(eth, REG_PPE_GLO_CFG(1)) & PPE_GLO_CFG_BUSY_MASK)', 'false'),
    }
    caught = {}
    for name, (filename, before, after) in mutations.items():
        path = extracted / filename
        original = path.read_text()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            target = output / name
            run(build + ['-o', str(target)], output, name + '-build')
            outcome = subprocess.run([str(target)], text=True, capture_output=True, timeout=30)
            (output / (name + '.log')).write_text(outcome.stdout + outcome.stderr)
            assert outcome.returncode and re.search('assertion|Assertion', outcome.stderr), name
            caught[name] = outcome.returncode
        finally:
            path.write_text(original)
    assert patch.read_bytes() == patch_data, 'production patch changed during tests; rerun'
    assert all((driver / name).read_bytes() == data for name, data in inputs.items()), 'source changed during tests; rerun'
    passed = review['accepted_invalid_hogs'] == 0
    report = {'passed': passed, 'regression_passed': True, 'result': result, 'review': review,
              'caught_mutations': caught, 'patch_sha256': digest(patch_data),
              'source_sha256': {name: digest(data) for name, data in inputs.items()},
              'tests_sha256': {path.name: digest(path.read_bytes()) for path in tests.iterdir() if path.is_file()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
