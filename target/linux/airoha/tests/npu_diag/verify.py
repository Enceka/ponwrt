#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import sys

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'npu_ingress'))
from source_binding import SourceBinding


FUNCTIONS = {
    'airoha_npu_owner.h': {'active': 'airoha_ppe_npu_diag_active',
                           'diag_flow': 'airoha_ppe_npu_diag_flow',
                           'retire': 'airoha_npu_owner_retire_locked'},
    'airoha_npu_diag.h': {'platform': 'airoha_npu_diag_platform',
                         'snapshot': 'airoha_npu_diag_snapshot',
                         'diag_authorize': 'airoha_npu_diag_authorize',
                         'start_mode': 'airoha_npu_diag_start_mode',
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
    if (output.is_relative_to(repo) or
            output == source or source.is_relative_to(output) or output.is_relative_to(source)):
        parser.error('output must be new, outside ponwrt, and separate from source')
    output.mkdir(parents=True, exist_ok=False)
    extracted = output / 'source'
    extracted.mkdir()
    driver = source / 'drivers/net/ethernet/airoha'
    inputs = {name: (driver / name).read_bytes() for name in [*FUNCTIONS, *HEADERS]}
    binding = SourceBinding(repo / 'target/linux/airoha/patches-6.18', output,
                            '999-zr-net-airoha-add-pon-ppe-learning-diagnostic.patch')
    binding.bind(driver, ('airoha_npu_owner.h', 'airoha_npu_diag.h',
                         'airoha_npu_reopen.h', 'airoha_bank1_routes.h'))
    binding_module = tests.parent / 'npu_ingress/source_binding.py'
    binding_bytes = binding_module.read_bytes()
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
        'ignore_auth_count': ('active.inc', 'owner->auth_count > (owner->diag_auth ? 1 : 0)', 'false'),
        'ignore_platform_dt': ('platform.inc', '!of_property_read_bool(ppe->eth->dev->of_node, "airoha,connac2-pon-er-diagnostic")', 'false'),
        'ignore_hog_available': ('platform.inc', 'node && of_device_is_available(node) &&', 'node && true &&'),
        'ignore_hog_count': ('platform.inc', 'of_property_count_u32_elems(node, "gpios") == 2', 'true'),
        'ignore_hog_gpio': ('platform.inc', 'gpios[0] == 38', 'true'),
        'ignore_hog_flags': ('platform.inc', '!gpios[1]', 'true'),
        'ignore_netdev_parent': ('start_mode.inc', 'lower->dev.parent != eth->dev', 'false'),
        'allow_production_auth': ('authorize.inc', 'if (owner->diag_lower)', 'if (false)'),
        'ignore_empty_auth_reply': ('ready.inc', 'message.w[AM_COUNT] != owner->auth_count', 'false'),
        'ignore_restore_error': ('close.inc', 'return error ?: airoha_npu_owner_retire_locked(ppe);', 'return airoha_npu_owner_retire_locked(ppe);'),
        'ignore_release_ack': ('close.inc', '!owner->closed_ack ||', 'false ||'),
        'leak_lower_ref': ('retire.inc', 'dev_put(owner->diag_lower);', '(void)owner->diag_lower;'),
        'ignore_restore_flow': ('restore.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) ||', 'false ||'),
        'ignore_route_flow': ('routes.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) != diagnostic_flow ||', 'false ||'),
        'ignore_route_busy': ('routes.inc', '(airoha_fe_rr(eth, REG_PPE_GLO_CFG(1)) & PPE_GLO_CFG_BUSY_MASK)', 'false'),
        'allow_two_diagnostic_rules': ('active.inc', '(owner->diag_auth ? 1 : 0)', '(owner->diag_auth ? 2 : 0)'),
        'ignore_explicit_auth_mode': ('diag_authorize.inc', '!owner->diag_auth ||', 'false ||'),
        'ignore_closed_phase': ('diag_authorize.inc', 'owner->txn.phase != NPU_TXN_CLOSED', 'false'),
        'allow_repeated_auth': ('diag_authorize.inc', 'owner->auth_attempted ||', 'false ||'),
        'ignore_start_service_range': ('start_mode.inc', 'service > U16_MAX ||', 'false ||'),
        'lose_auth_mode': ('start_mode.inc', 'owner->diag_auth = mode != 0;', 'owner->diag_auth = false;'),
        'truncate_service': ('diag_authorize.inc', '0, 4, 2, service,', '0, 4, 2, service & 0x7fffu,'),
        'omit_service_valid': ('diag_authorize.inc', 'ER_SERVICE_VALID | service', 'service'),
        'ignore_binding_result': ('diag_authorize.inc', '? 0 : -ESTALE', '? 0 : 0'),
        'wrong_ipv4_source': ('diag_authorize.inc', '0xc0000201', '0xc0000203'),
        'wrong_ipv4_destination': ('diag_authorize.inc', '0xc0000202', '0xc0000203'),
        'wrong_udp_ports': ('diag_authorize.inc', '0xc000c001', '0xc001c000'),
        'wrong_l4_protocol': ('diag_authorize.inc', '4, IPPROTO_UDP,', '4, 6,'),
        'wrong_source_mac': ('diag_authorize.inc', '{ 2, 0, 0, 0, 0, 1 }', '{ 2, 0, 0, 0, 0, 2 }'),
        'ignore_post_auth_readiness': ('diag_authorize.inc',
            'error = airoha_npu_owner_return_ready(owner, &owner->txn.id);', 'error = 0;'),
        'lose_published_rule_count': ('diag_authorize.inc', 'owner->auth_count = 1;', 'owner->auth_count = 0;'),
        'ignore_ack_count': ('airoha_npu_auth_publish.h', 'message.w[AM_COUNT] != count ||', 'false ||'),
        'ignore_ack_rule_echo': ('airoha_npu_auth_publish.h', 'AM_STATUS * sizeof(auth_u32)', 'AM_RULE * sizeof(auth_u32)'),
        'ignore_start_mode_range': ('start_mode.inc', 'mode > 2', 'false'),
        'lose_learning_mode': ('start_mode.inc', 'owner->diag_learn = mode == 2;', 'owner->diag_learn = false;'),
        'learn_in_auth_only_mode': ('start_mode.inc', 'owner->diag_learn = mode == 2;', 'owner->diag_learn = mode != 0;'),
        'flow_ignore_token': ('diag_flow.inc', 'airoha_ppe_npu_diag_active(ppe, token)', 'airoha_ppe_npu_diag_active(ppe, owner)'),
        'flow_ignore_auth': ('diag_flow.inc', '&& owner->diag_auth', '&& true'),
        'flow_ignore_learn': ('diag_flow.inc', '&& owner->diag_learn', '&& true'),
        'flow_enable_extra_protocol': ('diag_flow.inc', 'PPE_FLOW_CFG_IP4_NAPT_MASK : 0', '(PPE_FLOW_CFG_IP4_NAPT_MASK | BIT(14)) : 0'),
        'ignore_restore_cursor': ('restore.inc', 'owner->bank1_next_row != PPE_SRAM_NUM_ENTRIES ||', 'false ||'),
        'ignore_restore_miss': ('restore.inc', 'FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, table) != 2', 'false'),
        'ignore_restore_busy': ('restore.inc', '(status & PPE_GLO_CFG_BUSY_MASK) ||', 'false ||'),
        'ignore_restore_enabled': ('restore.inc', '!(status & PPE_GLO_CFG_EN_MASK) ||', 'false ||'),
        'skip_learning_writes': ('restore.inc', 'if (!flow)', 'if (true)'),
        'retain_stale_retirement_cursor': ('restore.inc', '\t\towner->bank1_next_row = 0;', '\t\towner->bank1_next_row = PPE_SRAM_NUM_ENTRIES;'),
        'wrong_learning_miss': ('restore.inc', 'FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 3)', 'FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 2)'),
        'clobber_other_table_fields': ('restore.inc', '(table & ~PPE_TB_CFG_SEARCH_MISS_MASK) |', '0 |'),
        'skip_table_readback': ('restore.inc', 'error = airoha_fe_rr(eth, REG_PPE_TB_CFG(1)) == table ? 0 : -EIO;', 'error = 0;'),
        'write_flow_after_table_failure': ('restore.inc', 'if (!error) {', 'if (true) {'),
        'skip_flow_readback': ('restore.inc', 'error = airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) == flow ? 0 : -EIO;', 'error = 0;'),
        'skip_learning_postcheck': ('restore.inc',
            '\t\treturn error ?: airoha_npu_owner_open_check(owner, id, NPU_TXN_PPE_RESTORE);', '\t\treturn error;'),
        'allow_extra_route_flows': ('routes.inc',
            'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) != diagnostic_flow ||',
            '(airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) & diagnostic_flow) != diagnostic_flow ||'),
        'ignore_route_miss': ('routes.inc',
            'FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, airoha_fe_rr(eth, REG_PPE_TB_CFG(1))) != (diagnostic_flow ? 3 : 2) ||', 'false ||'),
        'route_learning_accepts_miss_two': ('routes.inc', '(diagnostic_flow ? 3 : 2)', '2'),
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
    binding.verify_unchanged()
    assert binding_module.read_bytes() == binding_bytes, 'source-binding helper changed during tests; rerun'
    assert all((driver / name).read_bytes() == data for name, data in inputs.items()), 'source changed during tests; rerun'
    passed = review['accepted_invalid_hogs'] == 0
    report = {'passed': passed, 'regression_passed': True, 'result': result, 'review': review,
              'caught_mutations': caught, 'source_binding': binding.report(),
              'source_binding_helper_sha256': digest(binding_bytes),
              'source_sha256': {name: digest(data) for name, data in inputs.items()},
              'tests_sha256': {path.name: digest(path.read_bytes()) for path in tests.iterdir() if path.is_file()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
