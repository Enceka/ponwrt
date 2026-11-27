#!/usr/bin/env python3
"""Exercise the production NPU owner and return lifetime with boundary failures."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
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
    parser.add_argument('--health', action='store_true',
                        help='Apply the 999-z owner health extension and run its fault matrix')
    parser.add_argument('--bank1', action='store_true',
                        help='Include 999-zc bank1 retirement and the owner health matrix')
    parser.add_argument('--ingress', action='store_true',
                        help='Include 999-zd/999-ze ingress lifecycle and the bank1 matrix')
    parser.add_argument('--source', type=Path, required=True,
                        help='Kernel tree with patches through 999 applied')
    args = parser.parse_args()
    args.bank1 |= args.ingress
    args.health |= args.bank1
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    if report_path.exists():
        report_path.unlink()
    patches = tests.parents[1] / 'patches-6.18'
    paths = {number: next(patches.glob(number + '-net-airoha-*.patch'))
             for number in ('988', '989', '990', '993', '994', '995', '996', '999')}
    if args.health:
        paths['999-z'] = patches / '999-z-net-airoha-monitor-npu-owner-invalidation.patch'
    if args.bank1:
        paths['999-zc'] = patches / '999-zc-net-airoha-retire-host-bank1-before-npu-reuse.patch'
    if args.ingress:
        for number in ('975', '976', '977', '981', '982', '983', '984', '986', '987', '991'):
            paths[number] = next(patches.glob(number + '-net-airoha-*.patch'))
        paths['999-zd'] = patches / '999-zd-net-airoha-prepare-authorized-pon-npu-ingress.patch'
        paths['999-ze'] = patches / '999-ze-net-airoha-connect-pon-npu-ingress-lifecycle.patch'
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
    for number in ('994', '996', '999'):
        owner_patch = '--- a/drivers/net/ethernet/airoha/' + owner_name + '\n'
        owner_patch += re.split(r'^--- ', inputs[number].decode().split(owner_patch, 1)[1],
                               maxsplit=1, flags=re.MULTILINE)[0]
        applied = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'], input=owner_patch,
                                 cwd=output / 'expected', capture_output=True, text=True)
        (output / ('apply-' + number + '.log')).write_text(applied.stdout + applied.stderr)
        if applied.returncode:
            raise RuntimeError('cannot apply ' + number + ' owner: ' + applied.stdout + applied.stderr)
    sources[owner_name] = (expected / owner_name).read_bytes()
    return_name = 'airoha_npu_return.h'
    sources[return_name] = helper.added_file(return_patch, return_name)
    admission_name = 'airoha_npu_admission.h'
    sources[admission_name] = helper.added_file(inputs['996'].decode(), admission_name)
    (expected / admission_name).write_bytes(sources[admission_name])
    admission_patch = '--- a/drivers/net/ethernet/airoha/' + admission_name + '\n'
    admission_patch += re.split(r'^--- ', inputs['999'].decode().split(admission_patch, 1)[1],
                               maxsplit=1, flags=re.MULTILINE)[0]
    applied = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'], input=admission_patch,
                             cwd=output / 'expected', capture_output=True, text=True)
    if applied.returncode:
        raise RuntimeError('cannot apply admission: ' + applied.stdout + applied.stderr)
    sources[admission_name] = (expected / admission_name).read_bytes()
    reopen_name = 'airoha_npu_reopen.h'
    sources[reopen_name] = helper.added_file(inputs['999'].decode(), reopen_name)
    publish_name = 'airoha_npu_auth_publish.h'
    sources[publish_name] = helper.added_file(inputs['995'].decode(), publish_name)
    health_name = 'airoha_npu_health.h'
    if args.ingress:
        for number, name in (('975', 'airoha_ct_pon_ifc_words.h'),
                             ('976', 'airoha_ct_pon_ifc_owner.h'),
                             ('977', 'airoha_ct_pon_ifc_cpu.h')):
            sources[name] = helper.added_file(inputs[number].decode(), name)
    extensions = ((('981', '982', '983', '984', '986', '987', '991') if args.ingress else ()) +
                  (('999-z',) if args.health else ()) +
                  (('999-zc',) if args.bank1 else ()) +
                  (('999-zd', '999-ze') if args.ingress else ()))
    for extension in extensions:
        for name, data in sources.items():
            (expected / name).write_bytes(data)
        sections = re.split(r'(?=^--- )', inputs[extension].decode(), flags=re.MULTILINE)
        for section in sections:
            match = re.search(r'^\+\+\+ b/drivers/net/ethernet/airoha/'
                              r'(airoha_(?:npu|ct_pon_ifc)_\w+\.h)$',
                              section, flags=re.MULTILINE)
            if not match:
                continue
            name = match[1]
            if name not in sources and not section.startswith('--- /dev/null\n'):
                raise RuntimeError(extension + ' modifies an unknown header: ' + name)
            if section.startswith('--- /dev/null\n'):
                (expected / name).unlink(missing_ok=True)
            applied = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'], input=section,
                                     cwd=output / 'expected', capture_output=True, text=True)
            (output / ('apply-' + extension + '-' + name + '.log')).write_text(
                applied.stdout + applied.stderr)
            if applied.returncode:
                raise RuntimeError('cannot apply ' + extension + ' header ' + name + ': ' +
                                   applied.stdout + applied.stderr)
            sources[name] = (expected / name).read_bytes()
        if extension == '999-z' and health_name not in sources:
            raise RuntimeError('health patch does not add ' + health_name)
    driver = args.source.resolve() / 'drivers/net/ethernet/airoha'
    if (driver / owner_name).read_bytes() != sources[owner_name]:
        raise RuntimeError('kernel owner differs from the selected owner patches')
    if (driver / return_name).read_bytes() != sources[return_name]:
        raise RuntimeError('kernel return owner differs from the selected owner patches')
    for name in (admission_name, publish_name, reopen_name,
                 *((health_name,) if args.health else ()),
                 *(('airoha_npu_bank1.h',) if args.bank1 else ())):
        if (driver / name).read_bytes() != sources[name]:
            raise RuntimeError('kernel admission source differs: ' + name)
    checked_headers = {}
    if args.ingress:
        if 'airoha_npu_ingress.h' not in sources:
            raise RuntimeError('ingress patch does not add airoha_npu_ingress.h')
        for name, data in sources.items():
            checked_headers[name] = (driver / name).read_bytes()
            if checked_headers[name] != data:
                raise RuntimeError('kernel ingress source differs: ' + name)
        for name, function in (('ingress_busy.inc', 'airoha_ct_pon_ifc_busy'),
                               ('ingress_probe.inc', 'ct_pon_cpu_probe_store')):
            sources[name] = route_helper.extract_function(
                sources['airoha_ct_pon_ifc_cpu.h'].decode(), function).encode()
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
    if args.health:
        command.insert(1, '-DNPU_OWNER_HEALTH_TEST')
    if args.bank1:
        command.insert(1, '-DNPU_OWNER_BANK1_TEST')
    if args.ingress:
        command.insert(1, '-DNPU_OWNER_INGRESS_TEST')
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
    if args.bank1:
        mutants['release_before_closed'] = (
            'if (owner->txn.phase != NPU_TXN_CLOSED || !owner->bank1_saved ||\n'
            '\t    owner->return_path || owner->epoch_dirty || !owner->bank1_host_retired ||\n'
            '\t    owner->bank1_next_row != PPE_SRAM_NUM_ENTRIES)', 'if (false)')
    if args.ingress:
        mutants['release_before_closed'] = (
            'if (owner->txn.phase != NPU_TXN_CLOSED || !owner->bank1_saved ||\n'
            '\t    owner->return_path || owner->epoch_dirty || !owner->bank1_host_retired ||\n'
            '\t    owner->bank1_next_row != PPE_SRAM_NUM_ENTRIES ||\n'
            '\t    owner->ingress.saved_valid || owner->ingress.dirty ||\n'
            '\t    owner->ingress.active || owner->ingress.pending)', 'if (false)')
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
    reopen_mutants = {
        'restore_wrong_bank': ('REG_PPE_TB_CFG(1)', 'REG_PPE_TB_CFG(0)'),
        'ignore_restore_tb_readback': (
            'airoha_fe_rr(eth, REG_PPE_TB_CFG(1)) != owner->bank1_tb', 'false'),
        'ignore_restore_flow_readback': (
            'airoha_fe_rr(eth, REG_PPE_PPE_FLOW_CFG(1)) != owner->bank1_flow', 'false'),
        'skip_post_arm_generation': (
            'return error ?: airoha_npu_owner_open_check(owner, id, NPU_TXN_GATE_OPEN);',
            'return error;'),
        'skip_post_route_generation': (
            'if (!error)\n\t\terror = airoha_npu_owner_open_check(owner, id, NPU_TXN_ROUTES_OPEN);', ''),
        'leave_failed_open_live': ('close_error = airoha_ppe_npu_owner_close_locked(eth);',
                                 'close_error = 0;'),
    }
    mutants.update(reopen_mutants)
    mutants['skip_post_gate_generation'] = (
        'if (!error && opening)\n\t\terror = airoha_npu_owner_open_check(owner, &owner->txn.id, NPU_TXN_GATE_OPEN);', '')
    mutation_results = {}
    mutants['repeat_restored_stop'] = (
        'if (ppe->ct_npu_owner && ppe->ct_npu_owner->stop_completed)', 'if (false)')
    mutants['repeat_native_stop'] = (
        'if (ppe->ct_npu_owner && ppe->ct_npu_owner->native_stopped)', 'if (false)')
    health_mutants = {}
    if args.health:
        health_mutants = {
            'health_no_latch': (owner_name,
                'WRITE_ONCE(owner->invalidated, true);', 'WRITE_ONCE(owner->invalidated, false);'),
            'health_no_sequence': (owner_name,
                'owner->invalidation_seq++;', 'owner->invalidation_seq += 0;'),
            'health_skip_atomic_routes': (owner_name,
                'error = airoha_bank1_routes_revoke(ppe->eth, owner);', 'error = 0;'),
            'health_skip_atomic_gate': (owner_name,
                'if (!owner->closed_ack) {', 'if (false) {'),
            'health_use_unpublished_gate_identity': (owner_name,
                'message.w[GM_EPOCH] = owner->gate_id.epoch;',
                'message.w[GM_EPOCH] = owner->txn.id.epoch;'),
            'health_gate_identity_after_send': (owner_name,
                'owner->gate_id = owner->txn.id;', 'if (false) owner->gate_id = owner->txn.id;'),
            'health_ignore_locked_gate_invalidation': (owner_name,
                'if (opening && owner->invalidated)', 'if (opening && false)'),
            'health_skip_retire_cancel': (owner_name,
                'cancel_delayed_work_sync(&owner->health_work);', '(void)owner;'),
            'health_skip_retiring_flag': (owner_name,
                'owner->retiring = true;', 'owner->retiring = false;'),
            'health_false_close_ack': (owner_name,
                'error = airoha_npu_return_destroy(owner);\n\tif (!error) {',
                'error = airoha_npu_return_destroy(owner);\n\tif (true) {'),
            'health_skip_firmware_fault': (health_name,
                'gate.w[GM_FAULT]', 'false'),
            'health_skip_firmware_auth_count': (health_name,
                'auth.w[AM_COUNT] != owner->auth_count', 'false'),
            'health_skip_post_query_state': (health_name,
                'return airoha_npu_owner_open_check(owner, id, NPU_TXN_OPEN);', 'return 0;'),
            'health_skip_close': (health_name,
                'error = airoha_ppe_npu_owner_close_locked(ppe->eth);', 'error = 0;'),
            'health_skip_post_close_revoke': (health_name,
                'route_error = airoha_bank1_routes_revoke(ppe->eth, owner);', 'route_error = 0;'),
            'health_clear_new_pending': (health_name,
                'owner->invalidation_seq == invalidation_seq)',
                '(owner->invalidation_seq == invalidation_seq || owner->invalidated))'),
            'health_clear_latch_on_close': (health_name,
                'owner->close_pending = false;',
                'owner->close_pending = owner->invalidated = false;'),
            'health_no_periodic_retry': (health_name,
                'schedule_delayed_work(&owner->health_work, msecs_to_jiffies(100));', '(void)owner;'),
            'health_block_on_flow_mutex': (health_name,
                'if (!mutex_trylock(&flow_offload_mutex))\n\t\tgoto requeue;',
                'if (!mutex_trylock(&flow_offload_mutex)) {\n'
                '\t\tmutex_lock(&flow_offload_mutex);\n\t\tgoto requeue;\n\t}'),
            'health_renew_ignore_sequence': (admission_name,
                'owner->invalidation_seq == invalidation_seq ?',
                '(owner->invalidation_seq == invalidation_seq || owner->invalidated) ?'),
            'health_renew_allow_saturated_sequence': (admission_name,
                'invalidation_seq != U64_MAX &&', ''),
            'health_renew_skip_route_claim': (admission_name,
                'error = airoha_bank1_routes_claim(eth, owner);', 'error = 0;'),
            'health_skip_pair_fault': (admission_name,
                'ppe->ct_pair_failed ||', 'false ||'),
            'health_skip_fe_health_stop': (admission_name,
                'ppe->ct_fe.health_stopping ||', 'false ||'),
            'health_skip_ifc_fault': (admission_name,
                'READ_ONCE(ppe->eth->ct_ifc_cpu_port_failed)', 'false'),
            'health_skip_mapping_latch': (return_name,
                '!READ_ONCE(path->owner->invalidated) &&', ''),
            'health_skip_bind_ack_race': (return_name,
                'if (owner->invalidated)\n\t\t\terror = -ESTALE;',
                'if (false)\n\t\t\terror = -ESTALE;'),
            'health_keep_closed_ack_for_bind': (return_name,
                'owner->closed_ack = false;', 'owner->closed_ack = true;'),
            'health_notify_without_drain': (return_name,
                '(owner->closed_ack ? 0 : -EAGAIN)', '(owner->closed_ack ? 0 : 0)'),
            'health_skip_locked_fe_invalidation': (reopen_name,
                'error = owner->invalidated ? -ESTALE :', 'error = false ? -ESTALE :'),
            'health_skip_notifier_guard': (reopen_name,
                ' || !owner->ppe->ct_pair_wired_registered', ''),
            'health_skip_closed_cpu_fallback': (health_name,
                'READ_ONCE(owner->ppe->eth->ct_cpu_fallback)', 'false'),
            'health_skip_cpu_route_retry': (health_name,
                'airoha_ct_cpu_fallback(ppe->eth);', '(void)ppe;'),
            'health_repeat_completed_cpu_routes': (health_name,
                '!READ_ONCE(ppe->eth->ct_cpu_routes_ready)', 'true'),
        }
        mutants.update({name: (before, after)
                        for name, (_, before, after) in health_mutants.items()})
    bank1_mutants = {}
    if args.bank1:
        bank1_mutants = {
            'bank1_skip_cookie_retirement': (owner_name,
                'error = airoha_ppe_bank1_retire_flows(owner->ppe);',
                'error = false ? airoha_ppe_bank1_retire_flows(owner->ppe) : 0;'),
            'bank1_repeat_cookie_retirement': (owner_name,
                'if (!error && !owner->bank1_host_retired)', 'if (!error)'),
            'bank1_skip_row_clear': (owner_name,
                'error = airoha_ppe_bank1_clear_rows(owner->ppe, &owner->bank1_next_row);',
                'error = false ? airoha_ppe_bank1_clear_rows(owner->ppe, &owner->bank1_next_row) : 0;'),
            'bank1_ignore_retirement_failure': (owner_name,
                'error = airoha_ppe_bank1_retire_flows(owner->ppe);',
                'error = (airoha_ppe_bank1_retire_flows(owner->ppe), 0);'),
            'bank1_ignore_row_failure': (owner_name,
                'error = airoha_ppe_bank1_clear_rows(owner->ppe, &owner->bank1_next_row);',
                'error = (airoha_ppe_bank1_clear_rows(owner->ppe, &owner->bank1_next_row), 0);'),
            'bank1_no_sram_ownership': (owner_name, ' || !ppe->ct_owns_sram', ''),
            'bank1_release_incomplete_rows': (owner_name,
                'owner->bank1_next_row != PPE_SRAM_NUM_ENTRIES', 'false'),
            'bank1_open_before_retirement': (reopen_name, ' || !owner->bank1_host_retired', ''),
            'bank1_forget_reopen_cursor': (reopen_name,
                'owner->bank1_next_row = 0;', '(void)owner;'),
        }
        mutants.update({name: (before, after)
                        for name, (_, before, after) in bank1_mutants.items()})
    ingress_mutants = {}
    if args.ingress:
        ingress_mutants = {
            'ingress_restore_before_claim': (owner_name,
                'error = airoha_bank1_routes_claim(owner->ppe->eth, owner);\n'
                '\treturn error ?: airoha_npu_owner_ingress_restore(owner);',
                'error = airoha_npu_owner_ingress_restore(owner);\n'
                '\treturn error ?: airoha_bank1_routes_claim(owner->ppe->eth, owner);'),
            'ingress_skip_restore': (owner_name,
                'return error ?: airoha_npu_owner_ingress_restore(owner);',
                'return error ?: (false ? airoha_npu_owner_ingress_restore(owner) : 0);'),
            'ingress_ignore_claim_failure': (owner_name,
                'return error ?: airoha_npu_owner_ingress_restore(owner);',
                'return (void)error, airoha_npu_owner_ingress_restore(owner);'),
            'ingress_ignore_restore_failure': (owner_name,
                'return error ?: airoha_npu_owner_ingress_restore(owner);',
                'return error ?: (airoha_npu_owner_ingress_restore(owner), 0);'),
            'ingress_skip_prepare': (reopen_name,
                'error = airoha_npu_owner_ingress_prepare(owner);',
                'error = false ? airoha_npu_owner_ingress_prepare(owner) : 0;'),
            'ingress_ignore_prepare_failure': (reopen_name,
                'error = airoha_npu_owner_ingress_prepare(owner);',
                'error = (airoha_npu_owner_ingress_prepare(owner), 0);'),
            'ingress_skip_open_check': (reopen_name,
                'error = airoha_npu_owner_ingress_check(owner);', 'error = 0;'),
            'ingress_ignore_open_check_failure': (reopen_name,
                'error = airoha_npu_owner_ingress_check(owner);',
                'error = (airoha_npu_owner_ingress_check(owner), 0);'),
            'ingress_skip_ready': (reopen_name,
                'airoha_bank1_routes_ingress_ready(owner->ppe->eth, owner);',
                '(false ? airoha_bank1_routes_ingress_ready(owner->ppe->eth, owner) : 0);'),
            'ingress_ignore_locked_invalidation': (reopen_name,
                'error = owner->invalidated ? -ESTALE :\n'
                '\t\tairoha_bank1_routes_ingress_ready',
                'error = false ? -ESTALE :\n\t\tairoha_bank1_routes_ingress_ready'),
            'ingress_skip_health_check': (health_name,
                'error = airoha_npu_owner_ingress_check(owner);', 'error = 0;'),
            'ingress_skip_health_routes': (health_name,
                'error = airoha_bank1_routes_check(owner->ppe->eth, owner, true);', 'error = 0;'),
            'ingress_ignore_health_failure': (health_name,
                'error = airoha_npu_owner_ingress_check(owner);',
                'error = (airoha_npu_owner_ingress_check(owner), 0);'),
            'ingress_claim_over_cpu_probe': (owner_name,
                'if (airoha_ct_pon_ifc_busy(ppe))', 'if (false && airoha_ct_pon_ifc_busy(ppe))'),
            'ingress_release_saved_shadow': (owner_name,
                'owner->ingress.saved_valid ||', ''),
            'ingress_release_dirty_rows': (owner_name,
                'owner->ingress.dirty ||', ''),
            'ingress_release_active_rows': (owner_name,
                'owner->ingress.active ||', ''),
            'ingress_release_pending_command': (owner_name,
                ' || owner->ingress.pending)', ')'),
            'ingress_legacy_probe_ignores_owner': ('ingress_probe.inc',
                'if (ppe->ct_npu_owner)', 'if (false)'),
        }
        mutants.update({name: (before, after)
                        for name, (_, before, after) in ingress_mutants.items()})
    for name, (before, after) in mutants.items():
        target_name = (ingress_mutants[name][0] if name in ingress_mutants else
                       bank1_mutants[name][0] if name in bank1_mutants else
                       health_mutants[name][0] if name in health_mutants else
                       'stop_entry.inc' if name.startswith('repeat_') else
                       return_name if name in return_mutants else
                       reopen_name if name in reopen_mutants else
                       admission_name if name in admission_mutants else owner_name)
        original = sources[target_name].decode()
        if before not in original:
            raise RuntimeError('missing mutation target: ' + name)
        (extracted / target_name).write_text(original.replace(before, after))
        try:
            helper.execute(command, output, name + '-build')
            run = subprocess.run([str(output / 'owner_test')], capture_output=True,
                                 text=True, cwd=output, env=environment)
            (output / (name + '.log')).write_text(run.stdout + run.stderr)
            if run.returncode == 0 or 'CHECK failed:' not in run.stderr:
                raise RuntimeError('mutation was not rejected by a runtime assertion: ' + name)
            mutation_results[name] = 'caught'
        finally:
            (extracted / target_name).write_bytes(sources[target_name])
    (extracted / owner_name).write_bytes(sources[owner_name])
    helper.execute(command, output, 'build-final')
    for number, path in paths.items():
        if path.read_bytes() != inputs[number]:
            raise RuntimeError(number + ' changed during testing')
    for name, data in checked_headers.items():
        if (driver / name).read_bytes() != data:
            raise RuntimeError('kernel ingress source changed during testing: ' + name)
    sha256 = lambda data: hashlib.sha256(data).hexdigest()
    report = {
        'passed': True, 'health': args.health, 'bank1': args.bank1, 'ingress': args.ingress,
        'sanitizers': ['address', 'undefined'], 'result': result,
        'mutations': mutation_results,
        'byte_checked_headers': sorted(checked_headers),
        'patch_sha256': {number: sha256(data) for number, data in inputs.items()},
        'source_sha256': {name: sha256(data) for name, data in sources.items()},
        'test_sha256': {name: sha256((tests / name).read_bytes())
                        for name in ('verify.py', 'owner_test.c', 'return_types.h',
                                     'return_stubs.inc', 'return_test.inc', 'admission_test.inc',
                                     'reopen_test.inc',
                                     *(('bank1_stubs.inc', 'bank1_test.inc') if args.bank1 else ()),
                                     *(('ingress_stubs.inc', 'ingress_component.inc',
                                        'ingress_probe_stubs.inc', 'ingress_test.inc')
                                       if args.ingress else ()),
                                     *(('health_test.inc',) if args.health else ()))},
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(result)
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
