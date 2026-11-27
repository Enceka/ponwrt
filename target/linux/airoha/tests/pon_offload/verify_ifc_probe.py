#!/usr/bin/env python3
"""Run production optical probe wrappers and shared IFC transport with MMIO faults."""
import argparse
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import shutil
import signal
import subprocess


def function(text, name):
    match = re.search(r'(?m)^(?:static )?(?:int|bool|void|u16|u32|ssize_t|struct \w+)\s+' +
                      re.escape(name) + r'\(', text)
    assert match, name
    opening = text.index('{', match.end())
    depth, end = 1, opening + 1
    while depth:
        depth += (text[end] == '{') - (text[end] == '}')
        end += 1
    return text[match.start():end] + '\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    headers = args.source.resolve() / 'drivers/net/ethernet/airoha'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    selections = {
        'airoha_ct_ifc.h': ['ct_ifc_access'],
        'airoha_ct_fe_native.h': ['airoha_ct_fe_table', 'airoha_ct_fe_put'],
        'airoha_ct_cpu_fallback.h': [
            'airoha_ct_ifc_cpu_route_close_locked', 'airoha_ct_ifc_cpu_port_change',
            'airoha_ct_ppe_selectors', 'airoha_ct_cpu_selectors', 'airoha_ct_gdm_cpu_locked',
            'airoha_ct_gdm_route_locked', 'airoha_gdm_fwd_cfg_update', 'airoha_ct_cpu_fallback'],
        'airoha_eth.c': ['airoha_ifc_scope_update', 'airoha_ifc_lan_ports_ready',
                         'airoha_en7581_get_sport'],
        'airoha_ct_pon_ifc_cpu.h': [
            'airoha_ct_pon_ifc_read', 'airoha_ct_pon_ifc_put', 'airoha_ct_pon_ifc_drain',
            'airoha_ct_pon_ifc_io', 'airoha_ct_pon_ifc_route_ready',
            'airoha_ct_pon_ifc_dependencies', 'airoha_ct_pon_ifc_authorize',
            'airoha_ct_pon_ifc_fault', 'airoha_ct_pon_ifc_route_close',
            'airoha_ct_pon_ifc_route_open', 'airoha_ct_pon_ifc_cpu_stop',
            'airoha_ct_pon_ifc_cpu_publish',
            'airoha_ct_pon_ifc_cpu_set', 'airoha_ct_pon_ifc_cpu_clear',
            'airoha_ct_pon_ifc_source_set',
            'ct_pon_cpu_probe_store'],
    }
    complete = ['airoha_ct_pon_ifc_words.h', 'airoha_ct_pon_ifc_owner.h',
                'airoha_ct_ifc_command.h']
    sources = {name: (headers / name).read_text() for name in list(selections) + complete + ['airoha_eth.h']}
    constants = '\n'.join(re.findall(r'(?m)^#define CT_IFC_.*$', sources['airoha_ct_ifc.h'])) + '\n'
    guards = re.search(r'static const struct \{\s*u16 udf, min, max;.*?ct_ifc_guard\[\] = \{.*?\n\};',
                       sources['airoha_ct_ifc.h'], re.S)
    actions = re.search(r'static const u8 ct_ifc_action_words\[\] = .*?;', sources['airoha_ct_ifc.h'])
    assert guards and actions
    constants += guards.group() + '\n' + actions.group() + '\n'
    sport_enum = re.search(r'enum\s*\{\s*HSGMII_LAN_7581_PCIE0_SRCPORT.*?\n\};',
                           sources['airoha_eth.h'], re.S)
    assert sport_enum
    constants += sport_enum.group() + '\n'
    pse_enum = re.search(r'enum\s*\{\s*FE_PSE_PORT_CDM1.*?\n\};', sources['airoha_eth.h'], re.S)
    assert pse_enum
    constants += pse_enum.group() + '\n'
    extracted = '#include "airoha_ct_ifc_command.h"\n' + ''.join(
        function(sources[name], selected) for name, names in selections.items() for selected in names)
    test = output / 'verify_ifc_probe.c'
    shutil.copyfile(Path(__file__).with_suffix('.c'), test)

    def run(name, code, sanitized, overrides=None, arguments=()):
        directory = output / name
        directory.mkdir(parents=True)
        for header in complete:
            contents = (overrides or {}).get(header, sources[header])
            (directory / header).write_text(contents)
        (directory / 'probe_constants.inc').write_text(constants)
        (directory / 'probe_production.inc').write_text(code)
        command = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-Wno-unused-parameter',
                   '-I', str(directory), str(test), '-o', str(directory / 'test')]
        if sanitized:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-omit-frame-pointer']
        (directory / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        compiled = subprocess.run(command, capture_output=True, text=True)
        (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        tested = subprocess.run([str(directory / 'test'), *arguments], capture_output=True, text=True)
        (directory / 'stdout.txt').write_text(tested.stdout)
        (directory / 'stderr.txt').write_text(tested.stderr)
        (directory / 'exit-status.json').write_text(json.dumps({'returncode': tested.returncode}) + '\n')
        return tested

    results = []
    for mode in ('plain', 'sanitized'):
        tested = run(mode, extracted, mode == 'sanitized')
        tested.check_returncode()
        result = json.loads(tested.stdout)
        assert result['passed'] and result['transport_faults'] == 1080
        assert result['blocked_retries'] == 2160 and result['readback_faults'] == 156
        assert result['scope_cases'] == 28 and result['fallback_stop_cases'] == 3
        assert result['rejected_set_retries'] == 1276
        assert result['sport_cases'] == 72 and result['sport_close_cases'] == 2
        assert result['store_dispatch_cases'] == 32 and result['store_stop_cases'] == 6
        assert result['store_pending_cases'] == 6
        assert result['cover_cases'] == 71 and result['cover_tamper_cases'] == 70
        assert result['cover_route_faults'] == 12 and result['cover_io_faults'] == 144
        assert result['cover_publish_faults'] == 2630
        assert result['source_cases'] == 186 and result['source_faults'] == 2340
        assert result['sif_match_cases'] == 6400
        results.append(dict(mode=mode, **result))
    assert {key: value for key, value in results[0].items() if key != 'mode'} == {
        key: value for key, value in results[1].items() if key != 'mode'}

    mutations = [
        ('service_partial_sif_mask', 'header:airoha_ct_pon_ifc_words.h',
         '[0] = { BIT(2), U32_MAX }', '[0] = { BIT(2), BIT(2) }'),
        ('cover_partial_sif_mask', 'header:airoha_ct_pon_ifc_words.h',
         '[0] = { BIT(2), U32_MAX },\n\t\t\t[8]',
         '[0] = { BIT(2), BIT(2) },\n\t\t\t[8]'),
        ('source_missing_cover_guard', 'airoha_ct_pon_ifc_source_set',
         '!(ppe->ct_pon_ifc_cover & BIT(1))', 'false'),
        ('source_ignores_native_active', 'airoha_ct_pon_ifc_source_set',
         'ppe->ct_fe.active', 'false'),
        ('source_ignores_policy', 'airoha_ct_pon_ifc_source_set',
         'ppe->ct_pair_policy_allowed', 'false'),
        ('source_wrong_bit', 'airoha_ct_pon_ifc_source_set',
         'BIT(source)', 'BIT(2)'),
        ('source_wrong_mask', 'airoha_ct_pon_ifc_source_set',
         'rows[type].tcam[0][1] = mode == 2 ? U32_MAX : BIT(source);',
         'rows[type].tcam[0][1] = BIT(2);'),
        ('source_invalid_mode', 'airoha_ct_pon_ifc_source_set',
         'mode > 2', 'false'),
        ('source_absent_polarity', 'airoha_ct_pon_ifc_source_set',
         'mode == 1 ? 0 : BIT(source)', 'BIT(source)'),
        ('source_only_missing_full_mask', 'airoha_ct_pon_ifc_source_set',
         'mode == 2 ? U32_MAX : BIT(source)', 'BIT(source)'),
        ('source_declared_cover0', 'airoha_ct_pon_ifc_source_set',
         'ppe->ct_pon_ifc_cover &= ~BIT(0);', 'ppe->ct_pon_ifc_cover |= BIT(0);'),
        ('source_overwrites_cover1', 'airoha_ct_pon_ifc_source_set',
         'airoha_ct_pon_ifc_publish(&ppe->ct_pon_ifc, &io, 0, rows)',
         'airoha_ct_pon_ifc_publish(&ppe->ct_pon_ifc, &io, 1, rows)'),
        ('cover_wildcard_type', 'header:airoha_ct_pon_ifc_words.h',
         '[8] = { type << 6, 0xc0 }', '[8] = { type << 6, 0 }'),
        ('cover_both_type0', 'airoha_ct_pon_ifc_cpu_publish',
         'slot ? 4 : 2, family)', 'slot ? 4 : 2, 0)'),
        ('route_skips_mask_audit', 'airoha_ct_pon_ifc_route_open',
         'actual[1] != expected.tcam[page][1]', 'false'),
        ('route_skips_key_audit', 'airoha_ct_pon_ifc_route_open',
         '((actual[0] ^ expected.tcam[page][0]) & actual[1])', 'false'),
        ('route_skips_action_audit', 'airoha_ct_pon_ifc_route_open',
         'if (memcmp(actual, expected.action[page],', 'if (false && memcmp(actual, expected.action[page],'),
        ('route_partial_cover_returns_success', 'airoha_ct_pon_ifc_route_open',
         'err = -ESHUTDOWN;\n\t\t\tgoto out;', 'err = 0;\n\t\t\tgoto out;'),
        ('route_skips_cfg_owned', 'airoha_ct_pon_ifc_route_open',
         '!ppe->ct_ifc.cfg_owned ||', 'false ||'),
        ('route_skips_exact_scope', 'airoha_ct_pon_ifc_route_open',
         'eth->ct_ifc_port_mask != (XSI_ETH_VIP_PORT_MASK | BIT(2))', 'false'),
        ('route_skips_atomic_fallback', 'airoha_ct_pon_ifc_route_open',
         'eth->ct_cpu_fallback ||', 'false ||'),
        ('route_ownership_after_write', 'airoha_ct_pon_ifc_route_open',
         'ppe->ct_pon_ifc_route_owned = true;\n\tairoha_fe_wr(eth, REG_GDM_FWD_CFG(AIROHA_GDM2_IDX), value);',
         'airoha_fe_wr(eth, REG_GDM_FWD_CFG(AIROHA_GDM2_IDX), value);\n\tppe->ct_pon_ifc_route_owned = true;'),
        ('route_close_ignores_readback', 'airoha_ct_pon_ifc_route_close',
         'if (airoha_fe_rr(eth, REG_GDM_FWD_CFG(AIROHA_GDM2_IDX)) != value)',
         'if (false && airoha_fe_rr(eth, REG_GDM_FWD_CFG(AIROHA_GDM2_IDX)) != value)'),
        ('stop_skips_route_close', 'airoha_ct_pon_ifc_cpu_stop',
         'err = airoha_ct_pon_ifc_route_close(ppe);', 'err = 0;'),
        ('publish_skips_route_close', 'airoha_ct_pon_ifc_cpu_publish',
         'err = airoha_ct_pon_ifc_route_close(ppe);', 'err = 0;'),
        ('clear_skips_route_close', 'airoha_ct_pon_ifc_cpu_clear',
         'err = airoha_ct_pon_ifc_route_close(ppe);', 'err = 0;'),
        ('gate_close_skips_cpu_return', 'airoha_ct_ifc_cpu_route_close_locked',
         'if (eth->ppe->ct_pon_ifc_route_owned)', 'if (false)'),
        ('gdm_setter_resends_native', 'airoha_gdm_fwd_cfg_update',
         'if (eth->ppe->ct_pon_ifc_route_owned)', 'if (false)'),
        ('store_blocks_stopping_off', 'ct_pon_cpu_probe_store',
         'READ_ONCE(ppe->ct_pon_ifc_work_stopping))',
         'READ_ONCE(ppe->ct_pon_ifc_work_stopping) || READ_ONCE(ppe->ct_stopping))'),
        ('store_allows_stopping_clear', 'ct_pon_cpu_probe_store',
         'else if (READ_ONCE(ppe->ct_stopping))', 'else if (false)'),
        ('store_ignores_registration', 'ct_pon_cpu_probe_store',
         '!READ_ONCE(ppe->ct_pon_ifc_registered)', 'false'),
        ('store_ignores_work_stop', 'ct_pon_cpu_probe_store',
         'READ_ONCE(ppe->ct_pon_ifc_work_stopping)', 'false'),
        ('store_off_skips_restore', 'ct_pon_cpu_probe_store',
         'err = airoha_ct_pon_ifc_cpu_stop(ppe);', 'err = 0;'),
        ('store_off_hides_pending', 'ct_pon_cpu_probe_store',
         'err = airoha_ct_pon_ifc_cpu_stop(ppe);',
         '{ err = airoha_ct_pon_ifc_cpu_stop(ppe); if (err == -ETIMEDOUT) err = 0; }'),
        ('missing_gdm2_sport', 'airoha_en7581_get_sport',
         'case AIROHA_GDM2_IDX:\n\t\tif (!nbq)\n\t\t\treturn 2;\n\t\tbreak;\n', ''),
        ('gdm2_accepts_other_nbq', 'airoha_en7581_get_sport', 'if (!nbq)', 'if (true)'),
        ('gdm2_wrong_sport', 'airoha_en7581_get_sport', 'return 2;', 'return 1;'),
        ('clear_both_slots', 'airoha_ct_pon_ifc_cpu_clear',
         'airoha_ct_pon_ifc_withdraw(&ppe->ct_pon_ifc, &io, slot)',
         'airoha_ct_pon_ifc_restore(&ppe->ct_pon_ifc, &io)'),
        ('skip_dependencies', 'airoha_ct_pon_ifc_cpu_publish',
         'err = airoha_ct_pon_ifc_dependencies(ppe);', 'err = 0;'),
        ('missing_optical_scope', 'airoha_ct_pon_ifc_cpu_publish',
         'XSI_ETH_VIP_PORT_MASK | BIT(2)', 'XSI_ETH_VIP_PORT_MASK'),
        ('skip_route_revalidation', 'airoha_ct_pon_ifc_cpu_publish',
         'err = airoha_ct_pon_ifc_route_ready(ppe) ?', 'err = true ?'),
        ('duplicate_service_allowed', 'airoha_ct_pon_ifc_cpu_publish',
         'ppe->ct_pon_ifc_services[slot ^ 1] == service', 'false'),
        ('release_service_on_failed_clear', 'airoha_ct_pon_ifc_cpu_clear',
         'err = airoha_ct_pon_ifc_withdraw(&ppe->ct_pon_ifc, &io, slot);',
         'err = airoha_ct_pon_ifc_withdraw(&ppe->ct_pon_ifc, &io, slot);\n\tif (err) ppe->ct_pon_ifc_services[slot] = 0;'),
        ('skip_stop_gate', 'airoha_ct_pon_ifc_cpu_stop',
         'if ((scope & BIT(2))', 'if (false && (scope & BIT(2))'),
        ('ignore_stop_gate_error', 'airoha_ct_pon_ifc_cpu_stop',
         'return gate_err;', 'gate_err = 0;'),
        ('release_shadow_on_failed_stop', 'airoha_ct_pon_ifc_cpu_stop',
         'err = airoha_ct_pon_ifc_restore(&ppe->ct_pon_ifc, &io);',
         'err = airoha_ct_pon_ifc_restore(&ppe->ct_pon_ifc, &io);\n\tif (err) ppe->ct_pon_ifc.saved_valid = false;'),
        ('skip_optical_port_close', 'airoha_ct_ifc_cpu_port_change',
         'sport == 2 &&', 'false &&'),
        ('skip_gdm_route_close', 'airoha_gdm_fwd_cfg_update',
         'id == AIROHA_GDM2_IDX &&', 'false &&'),
        ('skip_shared_pending', None, 'if (eth->ct_ifc_command_pending)', 'if (false)'),
        ('missing_command_lock', None, 'lockdep_assert_held(&ppe_lock);',
         'spin_unlock_bh(&ppe_lock);'),
        ('scope_ignores_expected', 'airoha_ifc_scope_update',
         'eth->ct_ifc_port_mask != expected', 'false'),
        ('scope_leaves_optical_port_closed', 'airoha_ifc_scope_update',
         'ports = eth->ifc_port_desired & scope;', 'ports = eth->ifc_port_desired & expected;'),
        ('scope_ignores_authorization', 'airoha_ifc_scope_update',
         '(scope & BIT(AIROHA_GDM2_IDX)) && !eth->ct_ifc_pon_ready', 'false'),
        ('scope_skips_failed_rollback_fallback', 'airoha_ifc_scope_update',
         'recover = true;', 'recover = false;'),
        ('lan_accepts_fallback', 'airoha_ifc_lan_ports_ready',
         '!eth->ct_cpu_fallback &&', 'true &&'),
        ('scope_replaces_desired', 'airoha_ifc_scope_update',
         'eth->ct_ifc_port_mask = scope;',
         'eth->ifc_port_desired = scope;\n\t\teth->ct_ifc_port_mask = scope;'),
    ]

    def negative(specification):
        name, selected, old, new = specification
        overrides = {}
        code = extracted
        if selected and selected.startswith('header:'):
            header = selected.split(':', 1)[1]
            assert old in sources[header], name
            overrides[header] = sources[header].replace(old, new, 1)
        elif selected:
            original = function(code, selected)
            assert old in original, name
            code = code.replace(original, original.replace(old, new, 1), 1)
        else:
            command_header = sources['airoha_ct_ifc_command.h']
            assert old in command_header, name
            overrides['airoha_ct_ifc_command.h'] = command_header.replace(old, new, 1)
        tested = run('mutations/' + name, code, True, overrides)
        assert tested.returncode == -signal.SIGABRT, (name, tested.returncode, tested.stderr)
        assert 'assert' in tested.stderr.lower() and 'failed' in tested.stderr.lower(), (name, tested.stderr)
        assert not any(marker in tested.stderr for marker in
                       ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'runtime error:')), (name, tested.stderr)
        return dict(name=name, compile_passed=True, caught_runtime=True,
                    returncode=tested.returncode, assertion=tested.stderr.strip())

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        rejected = list(executor.map(negative, mutations))
    stuck = []
    for mode in ('plain', 'sanitized'):
        tested = run('stuck-route-' + mode, extracted, mode == 'sanitized', arguments=('stuck-route',))
        stuck.append(dict(mode=mode, passed=tested.returncode == 0,
                          returncode=tested.returncode, stdout=tested.stdout, stderr=tested.stderr))
    passed = all(result['passed'] for result in stuck)
    report = dict(passed=passed, modes=results, stuck_route=stuck, runtime_mutations=rejected,
                  extracted_functions=selections, source=str(args.source.resolve()),
                  source_sha256={name: hashlib.sha256(text.encode()).hexdigest() for name, text in sources.items()},
                  extracted_sha256=hashlib.sha256(extracted.encode()).hexdigest(),
                  test_sha256=hashlib.sha256(test.read_bytes()).hexdigest(),
                  stubs=['MMIO and command completion', 'lock and RCU assertions',
                         'work scheduling and netdev state'],
                  sanitizers=['address', 'undefined'])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=passed, modes=results, stuck_route=stuck, runtime_mutations=len(rejected),
                          report=str(output / 'report.json')), indent=2))
    assert passed, 'owned CPU route must be acknowledged before disabling IFC; see stuck-route logs'


if __name__ == '__main__':
    main()
