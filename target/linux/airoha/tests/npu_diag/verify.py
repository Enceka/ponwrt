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
                           'bank0_owned': 'airoha_ppe_npu_bank0_owned',
                           'diag_flow': 'airoha_ppe_npu_diag_flow',
                           'bank0_drain': 'airoha_npu_diag_bank0_drain',
                           'bank1_drain': 'airoha_npu_owner_bank1_drain',
                           'retire': 'airoha_npu_owner_retire_locked'},
    'airoha_npu_diag.h': {'platform': 'airoha_npu_diag_platform',
                         'install': 'airoha_npu_diag_install',
                         'bind': 'airoha_npu_diag_bind',
                         'bind_command': 'airoha_npu_diag_bind_command',
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
    'airoha_npu_bank1.h': {'bank0_hash': 'airoha_ppe_bank0_hash'},
    'airoha_ppe.c': {'sram_ack': 'airoha_ppe_ct_sram_ack',
                    'ipv4_tuple': 'airoha_ppe_foe_entry_set_ipv4_tuple'},
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
    inputs = {name: (driver / name).read_bytes()
              for name in [*FUNCTIONS, *HEADERS, 'airoha_eth.h', 'airoha_regs.h']}
    test_inputs = {name: (tests / name).read_bytes() for name in ('verify.py', 'diag_test.c')}
    binding = SourceBinding(repo / 'target/linux/airoha/patches-6.18', output,
                            '999-zw-net-airoha-align-pon-auth-bank-metadata.patch')
    binding_error = None
    try:
        binding.bind(driver, ('airoha_npu_owner.h', 'airoha_npu_diag.h',
                             'airoha_npu_reopen.h', 'airoha_bank1_routes.h', 'airoha_npu_bank1.h',
                             'airoha_npu_admission.h', 'airoha_npu_auth_publish.h'))
    except ValueError as error:
        binding_error = str(error)
        print('Source binding failed: ' + binding_error, file=sys.stderr)
    binding_module = tests.parent / 'npu_ingress/source_binding.py'
    binding_bytes = binding_module.read_bytes()
    host_guards = {
        'airoha_ppe_foe_commit_entry': '''
            if (ppe->ct_npu_owner &&
                ((hash >= PPE_SRAM_NUM_ENTRIES && hash < 2 * PPE_SRAM_NUM_ENTRIES) ||
                 (hash < PPE_SRAM_NUM_ENTRIES && airoha_ppe_npu_bank0_owned(ppe))) &&
                FIELD_GET(AIROHA_FOE_IB1_BIND_STATE, e->ib1) == AIROHA_FOE_STATE_BIND)
                return -EBUSY;
        ''',
        'airoha_ppe_foe_insert_entry': '''
            if (ppe->ct_host_ppe &&
                (hash >= airoha_ppe_get_total_sram_num_entries(ppe) ||
                 (ppe->ct_npu_owner &&
                  (hash >= PPE_SRAM_NUM_ENTRIES || airoha_ppe_npu_bank0_owned(ppe)))))
                goto unlock;
        ''',
    }
    for symbol, guard in host_guards.items():
        body = function(inputs['airoha_ppe.c'].decode(), symbol)
        assert re.sub(r'\s+', '', guard) in re.sub(r'\s+', '', body), symbol + ': ownership guard differs'
        assert body.count('airoha_ppe_npu_bank0_owned(ppe)') == 1, symbol
    for name, functions in FUNCTIONS.items():
        for target, symbol in functions.items():
            (extracted / (target + '.inc')).write_text(function(inputs[name].decode(), symbol))
    for name in HEADERS:
        (extracted / name).write_bytes(inputs[name])
    eth_header = inputs['airoha_eth.h'].decode()
    entry_start = eth_header.index('enum {\n\tAIROHA_FOE_STATE_INVALID,')
    entry_end = eth_header.index('struct airoha_foe_stats {', entry_start)
    data_start = eth_header.index('struct airoha_flow_data {')
    data_end = eth_header.index('enum airoha_flow_entry_type {', data_start)
    entry_size = re.search(r'^#define PPE_ENTRY_SIZE\s+\d+$', eth_header, re.M)
    assert entry_size
    (extracted / 'foe_types.inc').write_text(entry_size[0] + '\n' +
        eth_header[entry_start:entry_end] + eth_header[data_start:data_end])
    register_header = inputs['airoha_regs.h'].decode()
    sram_masks = ['PPE_SRAM_CTRL_ACK_MASK', 'PPE_SRAM_CTRL_ENTRY_MASK',
                  'PPE_SRAM_CTRL_WR_MASK', 'PPE_SRAM_CTRL_REQ_MASK']
    (extracted / 'sram_masks.inc').write_text(''.join(
        re.search(r'^#define ' + name + r'\s+[^\n]+$', register_header, re.M)[0] + '\n'
        for name in sram_masks))
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
        'allow_production_bank0': ('authorize.inc', 'if (rules[index].raw[3] != 1u)', 'if (false)'),
        'check_only_first_production_bank': ('authorize.inc', 'if (rules[index].raw[3] != 1u)', 'if (rules[0].raw[3] != 1u)'),
        'reject_production_bank1': ('authorize.inc', 'if (rules[index].raw[3] != 1u)', 'if (rules[index].raw[3] != 0u)'),
        'diag_auth_wrong_bank': ('diag_authorize.inc', 'AUTH_MBOX_ABI, owner->txn.id.epoch, 1, 0,', 'AUTH_MBOX_ABI, owner->txn.id.epoch, 1, 1,'),
        'diag_auth_wrong_bound_row': ('diag_authorize.inc', 'owner->diag_bound ? owner->diag_hash : 0', '0'),
        'diag_auth_learn_uses_stale_row': ('diag_authorize.inc', 'owner->diag_bound ? owner->diag_hash : 0', 'owner->diag_hash'),
        'ignore_empty_auth_reply': ('ready.inc', 'message.w[AM_COUNT] != owner->auth_count', 'false'),
        'ignore_restore_error': ('close.inc', 'return error ?: airoha_npu_owner_retire_locked(ppe);', 'return airoha_npu_owner_retire_locked(ppe);'),
        'ignore_release_ack': ('close.inc', '!owner->closed_ack ||', 'false ||'),
        'leak_lower_ref': ('retire.inc', 'dev_put(owner->diag_lower);', '(void)owner->diag_lower;'),
        'ignore_restore_flow': ('restore.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) ||', 'false ||'),
        'ignore_route_flow': ('routes.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) ||', 'false ||'),
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
        'ignore_restore_miss': ('restore.inc', 'FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, table) != 2', 'false', 0),
        'ignore_restore_busy': ('restore.inc', '(status & PPE_GLO_CFG_BUSY_MASK) ||', 'false ||', 0),
        'ignore_restore_enabled': ('restore.inc', '!(status & PPE_GLO_CFG_EN_MASK) ||', 'false ||', 0),
        'skip_learning_writes': ('restore.inc', 'if (!flow)', 'if (true)'),
        'retain_stale_retirement_cursor': ('restore.inc', '\t\towner->bank0_next_row = 0;', '\t\towner->bank0_next_row = PPE_SRAM_NUM_ENTRIES;'),
        'wrong_learning_miss': ('restore.inc', 'FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 3)', 'FIELD_PREP(PPE_TB_CFG_SEARCH_MISS_MASK, 2)'),
        'clobber_other_table_fields': ('restore.inc', '(table & ~PPE_TB_CFG_SEARCH_MISS_MASK) |', '0 |'),
        'skip_table_readback': ('restore.inc', 'error = airoha_fe_rr(eth, REG_PPE_TB_CFG(0)) == table ? 0 : -EIO;', 'error = 0;'),
        'write_flow_after_table_failure': ('restore.inc', 'if (!error) {', 'if (true) {'),
        'skip_flow_readback': ('restore.inc', 'error = airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) == flow ? 0 : -EIO;', 'error = 0;'),
        'skip_learning_postcheck': ('restore.inc',
            '\t\treturn error ?: airoha_npu_owner_open_check(owner, id, NPU_TXN_PPE_RESTORE);', '\t\treturn error;'),
        'allow_extra_route_flows': ('routes.inc',
            'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) != diagnostic_flow ||',
            '(airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) & diagnostic_flow) != diagnostic_flow ||'),
        'ignore_route_miss': ('routes.inc',
            'FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, airoha_fe_rr(eth, REG_PPE_TB_CFG(1))) != 2 ||', 'false ||'),
        'route_learning_accepts_miss_two': ('routes.inc', 'REG_PPE_TB_CFG(0))) != 3', 'REG_PPE_TB_CFG(0))) != 2'),
        'ignore_bank0_route_flow': ('routes.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) != diagnostic_flow ||', 'false ||'),
        'ignore_bank0_route_busy': ('routes.inc', '(airoha_fe_rr(eth, REG_PPE_GLO_CFG(0)) & PPE_GLO_CFG_BUSY_MASK) ||', 'false ||'),
        'ignore_bank0_route_enabled': ('routes.inc', '!(airoha_fe_rr(eth, REG_PPE_GLO_CFG(0)) & PPE_GLO_CFG_EN_MASK) ||', 'false ||'),
        'ignore_bank0_restore_saved': ('restore.inc', '!owner->bank0_saved ||', 'false ||'),
        'ignore_bank0_restore_cursor': ('restore.inc', 'owner->bank0_next_row != PPE_SRAM_NUM_ENTRIES ||', 'false ||'),
        'ignore_bank0_restore_flow': ('restore.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) ||', 'false ||'),
        'ignore_bank0_restore_miss': ('restore.inc', 'FIELD_GET(PPE_TB_CFG_SEARCH_MISS_MASK, table) != 2', 'false', 1),
        'ignore_bank0_restore_busy': ('restore.inc', '(status & PPE_GLO_CFG_BUSY_MASK) ||', 'false ||', 1),
        'ignore_bank0_restore_enabled': ('restore.inc', '!(status & PPE_GLO_CFG_EN_MASK) ||', 'false ||', 1),
        'learn_on_bank1': ('restore.inc', 'airoha_fe_wr(eth, REG_PPE_PPE_FLOW_CFG(0), flow);', 'airoha_fe_wr(eth, REG_PPE_PPE_FLOW_CFG(1), flow);'),
        'skip_start_bank0_drain': ('start_mode.inc', 'error = airoha_npu_diag_bank0_drain(owner);', 'error = 0;'),
        'skip_close_bank0_drain': ('bank1_drain.inc', 'error = airoha_npu_diag_bank0_drain(owner);', 'error = 0;'),
        'skip_bank0_clear': ('bank0_drain.inc', 'error = airoha_ppe_bank0_clear_rows(owner->ppe, &owner->bank0_next_row);', 'error = 0;'),
        'overwrite_bank0_snapshot': ('bank0_drain.inc', 'if (!owner->bank0_saved)', 'if (true)'),
        'ignore_bank0_drain_flow': ('bank0_drain.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) ||', 'false ||'),
        'ignore_bank0_drain_miss': ('bank0_drain.inc', '(airoha_fe_rr(eth, REG_PPE_TB_CFG(0)) & PPE_TB_CFG_SEARCH_MISS_MASK) != no_foe', 'false'),
        'ignore_bank0_drain_busy': ('bank0_drain.inc', '!(status & PPE_GLO_CFG_BUSY_MASK)', 'true'),
        'ignore_bank0_drain_enabled': ('bank0_drain.inc', '!(status & PPE_GLO_CFG_EN_MASK)', 'false'),
        'ignore_bank0_release_cursor': ('close.inc', 'owner->bank0_next_row != PPE_SRAM_NUM_ENTRIES)) ||', 'false)) ||'),
        'ignore_bank0_retire_cursor': ('retire.inc', 'owner->bank0_next_row != PPE_SRAM_NUM_ENTRIES)) ||', 'false)) ||'),
        'skip_bank0_host_retirement': ('bank0_drain.inc', 'error = airoha_ppe_bank0_retire_flows(owner->ppe);', 'error = 0;'),
        'repeat_bank0_host_retirement': ('bank0_drain.inc', '!error && !owner->bank0_host_retired', '!error'),
        'ignore_bank0_retirement_failure': ('bank0_drain.inc', 'error = airoha_ppe_bank0_retire_flows(owner->ppe);', '(void)airoha_ppe_bank0_retire_flows(owner->ppe);'),
        'forget_bank0_retirement': ('bank0_drain.inc', 'owner->bank0_host_retired = true;', 'owner->bank0_host_retired = false;'),
        'ignore_bank0_restore_retirement': ('restore.inc', '!owner->bank0_host_retired ||', 'false ||'),
        'ignore_bank0_install_retirement': ('install.inc', '!owner->bank0_host_retired ||', 'false ||'),
        'ignore_bank0_release_retirement': ('close.inc', '!owner->bank0_host_retired ||', 'false ||'),
        'ignore_bank0_owner_retirement': ('retire.inc', '!owner->bank0_host_retired ||', 'false ||'),
        'skip_bank0_release': ('close.inc', 'if (!error && owner->bank0_saved)', 'if (false)'),
        'skip_bank0_table_readback': ('close.inc', 'airoha_fe_rr(eth, REG_PPE_TB_CFG(0)) != owner->bank0_tb', 'false'),
        'skip_bank0_flow_readback': ('close.inc', 'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(0)) == owner->bank0_flow ? 0 : -EIO', '0'),
        'leak_egress_ref': ('retire.inc', 'dev_put(owner->diag_egress);', '(void)owner->diag_egress;'),
        'ignore_install_saved': ('install.inc', '!owner->bank0_saved ||', 'false ||'),
        'ignore_install_hash': ('install.inc', '!airoha_ppe_bank0_hash(owner->diag_hash) ||', 'false ||'),
        'ignore_install_cursor': ('install.inc', 'owner->bank0_next_row != PPE_SRAM_NUM_ENTRIES ||', 'false ||'),
        'ignore_install_invalidated': ('install.inc', 'if (owner->invalidated)', 'if (false)'),
        'skip_install': ('restore.inc', 'error = airoha_npu_diag_install(owner);', 'error = 0;'),
        'ignore_install_empty': ('install.inc', 'memcmp(entry, &invalid, sizeof(invalid))', '((void)invalid, 0)'),
        'ignore_install_readback': ('install.inc', 'memcmp(entry, &owner->diag_entry, sizeof(*entry))', '0'),
        'ignore_install_read_ack': ('install.inc', '!airoha_ppe_ct_sram_ack(ppe->eth, owner->diag_hash, false)', 'false', 0),
        'ignore_install_write_ack': ('install.inc', '!airoha_ppe_ct_sram_ack(ppe->eth, owner->diag_hash, true)', 'false'),
        'ignore_install_verify_ack': ('install.inc', '!airoha_ppe_ct_sram_ack(ppe->eth, owner->diag_hash, false)', 'false', 1),
        'ignore_bind_tuple': ('bind.inc', 'memcmp(&learned->ipv4.orig_tuple, &bound.ipv4.orig_tuple,\n\t\t\tsizeof(bound.ipv4.orig_tuple))', 'false'),
        'ignore_bind_ack': ('bind.inc', '!airoha_ppe_ct_sram_ack(eth, hash, false)', 'false'),
        'ignore_bind_hash': ('bind.inc', '!airoha_ppe_bank0_hash(hash) ||', 'false ||'),
        'lose_bind_service': ('bind.inc', 'owner->diag_service);', 'owner->diag_service ^ 1u);'),
        'ownership_requires_active': ('bank0_owned.inc', 'return owner &&', 'return airoha_ppe_npu_diag_active(ppe, owner) &&'),
        'ownership_requires_flow': ('bank0_owned.inc', 'return owner &&', 'return airoha_ppe_npu_diag_flow(ppe, owner) &&'),
        'ownership_ignores_saved': ('bank0_owned.inc', 'owner->bank0_saved ||', 'false ||'),
        'ownership_ignores_learning': ('bank0_owned.inc', '|| owner->diag_learn', '|| false'),
        'ownership_requires_both': ('bank0_owned.inc', 'owner->bank0_saved || owner->diag_learn', 'owner->bank0_saved && owner->diag_learn'),
        'ownership_after_release': ('bank0_owned.inc', 'return owner &&', 'return !owner ||'),
    }
    caught = {}
    for name, mutation in mutations.items():
        filename, before, after, *occurrence = mutation
        path = extracted / filename
        original = path.read_text()
        assert original.count(before) == (2 if occurrence else 1), name
        position = original.index(before)
        if occurrence and occurrence[0]:
            position = original.index(before, position + len(before))
        try:
            path.write_text(original[:position] + after + original[position + len(before):])
            target = output / name
            run(build + ['-o', str(target)], output, name + '-build')
            outcome = subprocess.run([str(target)], text=True, capture_output=True, timeout=30)
            (output / (name + '.log')).write_text(outcome.stdout + outcome.stderr)
            assert outcome.returncode and re.search('assertion|Assertion', outcome.stderr), name
            caught[name] = outcome.returncode
        finally:
            path.write_text(original)
    if binding_error is None:
        binding.verify_unchanged()
    else:
        assert binding.read_patches() == binding.snapshot, 'patches changed during tests; rerun'
    assert binding_module.read_bytes() == binding_bytes, 'source-binding helper changed during tests; rerun'
    assert all((driver / name).read_bytes() == data for name, data in inputs.items()), 'source changed during tests; rerun'
    assert all((tests / name).read_bytes() == data for name, data in test_inputs.items()), 'tests changed during run; rerun'
    passed = binding_error is None and review['accepted_invalid_hogs'] == 0
    report = {'passed': passed, 'regression_passed': True, 'result': result, 'review': review,
              'caught_mutations': caught,
              'host_ownership_guards': list(host_guards),
              'sanitizers': ['address', 'undefined'],
              'source_binding': binding.report() if binding_error is None else {'error': binding_error},
              'source_binding_helper_sha256': digest(binding_bytes),
              'source_sha256': {name: digest(data) for name, data in inputs.items()},
              'tests_sha256': {name: digest(data) for name, data in test_inputs.items()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == '__main__':
    sys.exit(main())
