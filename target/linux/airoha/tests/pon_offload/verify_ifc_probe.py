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
    match = re.search(r'(?m)^(?:static )?(?:int|bool|void|u16|u32|struct \w+)\s+' +
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
        'airoha_ct_pon_ifc_cpu.h': [
            'airoha_ct_pon_ifc_read', 'airoha_ct_pon_ifc_put', 'airoha_ct_pon_ifc_drain',
            'airoha_ct_pon_ifc_io', 'airoha_ct_pon_ifc_route_ready',
            'airoha_ct_pon_ifc_dependencies', 'airoha_ct_pon_ifc_authorize',
            'airoha_ct_pon_ifc_fault', 'airoha_ct_pon_ifc_cpu_stop',
            'airoha_ct_pon_ifc_cpu_set', 'airoha_ct_pon_ifc_cpu_clear'],
    }
    complete = ['airoha_ct_pon_ifc_words.h', 'airoha_ct_pon_ifc_owner.h',
                'airoha_ct_ifc_command.h']
    sources = {name: (headers / name).read_text() for name in list(selections) + complete}
    constants = '\n'.join(re.findall(r'(?m)^#define CT_IFC_.*$', sources['airoha_ct_ifc.h'])) + '\n'
    guards = re.search(r'static const struct \{\s*u16 udf, min, max;.*?ct_ifc_guard\[\] = \{.*?\n\};',
                       sources['airoha_ct_ifc.h'], re.S)
    actions = re.search(r'static const u8 ct_ifc_action_words\[\] = .*?;', sources['airoha_ct_ifc.h'])
    assert guards and actions
    constants += guards.group() + '\n' + actions.group() + '\n'
    extracted = '#include "airoha_ct_ifc_command.h"\n' + ''.join(
        function(sources[name], selected) for name, names in selections.items() for selected in names)
    test = output / 'verify_ifc_probe.c'
    shutil.copyfile(Path(__file__).with_suffix('.c'), test)

    def run(name, code, sanitized, command_header=None):
        directory = output / name
        directory.mkdir(parents=True)
        for header in complete:
            contents = command_header if header == 'airoha_ct_ifc_command.h' and command_header else sources[header]
            (directory / header).write_text(contents)
        (directory / 'probe_constants.inc').write_text(constants)
        (directory / 'probe_production.inc').write_text(code)
        command = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-I', str(directory), str(test), '-o', str(directory / 'test')]
        if sanitized:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all',
                        '-fno-omit-frame-pointer']
        (directory / 'compile-command.json').write_text(json.dumps(command, indent=2) + '\n')
        compiled = subprocess.run(command, capture_output=True, text=True)
        (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        tested = subprocess.run([str(directory / 'test')], capture_output=True, text=True)
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
        results.append(dict(mode=mode, **result))
    assert {key: value for key, value in results[0].items() if key != 'mode'} == {
        key: value for key, value in results[1].items() if key != 'mode'}

    mutations = [
        ('clear_both_slots', 'airoha_ct_pon_ifc_cpu_clear',
         'airoha_ct_pon_ifc_withdraw(&ppe->ct_pon_ifc, &io, slot)',
         'airoha_ct_pon_ifc_restore(&ppe->ct_pon_ifc, &io)'),
        ('skip_dependencies', 'airoha_ct_pon_ifc_cpu_set',
         'err = airoha_ct_pon_ifc_dependencies(ppe);', 'err = 0;'),
        ('missing_optical_scope', 'airoha_ct_pon_ifc_cpu_set',
         'XSI_ETH_VIP_PORT_MASK | BIT(2)', 'XSI_ETH_VIP_PORT_MASK'),
        ('skip_route_revalidation', 'airoha_ct_pon_ifc_cpu_set',
         'err = airoha_ct_pon_ifc_route_ready(ppe) ?', 'err = true ?'),
        ('duplicate_service_allowed', 'airoha_ct_pon_ifc_cpu_set',
         'ppe->ct_pon_ifc_services[slot ^ 1] == service', 'false'),
        ('release_service_on_failed_clear', 'airoha_ct_pon_ifc_cpu_clear',
         'if (err) {', 'if (err) {\n\t\tppe->ct_pon_ifc_services[slot] = 0;'),
        ('skip_stop_gate', 'airoha_ct_pon_ifc_cpu_stop',
         'if ((scope & BIT(2))', 'if (false && (scope & BIT(2))'),
        ('ignore_stop_gate_error', 'airoha_ct_pon_ifc_cpu_stop',
         'return gate_err;', 'gate_err = 0;'),
        ('release_shadow_on_failed_stop', 'airoha_ct_pon_ifc_cpu_stop',
         'if (err) {', 'if (err) {\n\t\tppe->ct_pon_ifc.saved_valid = false;'),
        ('skip_optical_port_close', 'airoha_ct_ifc_cpu_port_change',
         'sport == 2 &&', 'false &&'),
        ('skip_gdm_route_close', 'airoha_gdm_fwd_cfg_update',
         'id == AIROHA_GDM2_IDX &&', 'false &&'),
        ('skip_shared_pending', None, 'if (eth->ct_ifc_command_pending)', 'if (false)'),
        ('missing_command_lock', None, 'lockdep_assert_held(&ppe_lock);',
         'spin_unlock_bh(&ppe_lock);'),
    ]

    def negative(specification):
        name, selected, old, new = specification
        command_header = sources['airoha_ct_ifc_command.h']
        code = extracted
        if selected:
            original = function(code, selected)
            assert old in original, name
            code = code.replace(original, original.replace(old, new, 1), 1)
        else:
            assert old in command_header, name
            command_header = command_header.replace(old, new, 1)
        tested = run('mutations/' + name, code, True, command_header)
        assert tested.returncode == -signal.SIGABRT, (name, tested.returncode, tested.stderr)
        assert 'assert' in tested.stderr.lower() and 'failed' in tested.stderr.lower(), (name, tested.stderr)
        assert not any(marker in tested.stderr for marker in
                       ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'runtime error:')), (name, tested.stderr)
        return dict(name=name, compile_passed=True, caught_runtime=True,
                    returncode=tested.returncode, assertion=tested.stderr.strip())

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        rejected = list(executor.map(negative, mutations))
    report = dict(passed=True, modes=results, runtime_mutations=rejected,
                  extracted_functions=selections, source=str(args.source.resolve()),
                  source_sha256={name: hashlib.sha256(text.encode()).hexdigest() for name, text in sources.items()},
                  extracted_sha256=hashlib.sha256(extracted.encode()).hexdigest(),
                  test_sha256=hashlib.sha256(test.read_bytes()).hexdigest(),
                  stubs=['MMIO and command completion', 'lock and RCU assertions',
                         'scope update and LAN readiness', 'work scheduling and netdev state'],
                  sanitizers=['address', 'undefined'])
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(dict(passed=True, modes=results, runtime_mutations=len(rejected),
                          report=str(output / 'report.json')), indent=2))


if __name__ == '__main__':
    main()
