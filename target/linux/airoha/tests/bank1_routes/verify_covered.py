#!/usr/bin/env python3
"""Run bounded covered-route regressions against exact production helpers."""

import argparse
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import sys

sys.dont_write_bytecode = True
from verify import DRIVER, FILES, FUNCTIONS, INGRESS_FUNCTIONS, digest, extract_function, run

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'npu_ingress'))
from source_binding import SourceBinding


def negative_controls(output, driver, build, environment):
    controls = (
        ('close_scope_after_failed_cpu', 'airoha_bank1_routes.h', (
            ('airoha_bank1_routes_revoke_locked',
             '\tif (route_error)\n\t\treturn route_error;\n'
             '\terror = airoha_bank1_scope_locked(eth, false);\n\treturn error;',
             '\terror = airoha_bank1_scope_locked(eth, false);\n\treturn route_error ?: error;'),
            ('airoha_bank1_routes_claim',
             '\tif (route_error) {\n\t\terror = route_error;\n\t\tgoto unlock;\n\t}\n'
             '\terror = airoha_bank1_scope_locked(eth, false);',
             '\terror = airoha_bank1_scope_locked(eth, false);\n\tif (route_error)\n\t\terror = route_error;'),
         ), ('claim-drop', 'claim-readback', 'revoke-drop', 'revoke-readback'),
         'eth.regs[REG_FE_IFC_PORT_EN] & BIT(2)'),
        ('fallback_ignores_bank1_owner', 'airoha_ct_cpu_fallback.h', (
            ('airoha_ct_cpu_fallback',
             '(eth->ppe->ct_pon_ifc_route_owned || eth->ct_bank1_routes.owner)',
             'eth->ppe->ct_pon_ifc_route_owned'),
         ), ('fallback-drop', 'fallback-readback'),
         'eth.regs[REG_FE_CSR_IFC_CFG] & FE_IFC_EN_MASK'),
    )
    caught = {}
    for name, filename, replacements, groups, assertion in controls:
        target = driver / filename
        original = target.read_text()
        modified = original
        for symbol, before, after in replacements:
            function = extract_function(modified, symbol)
            if function.count(before) != 1:
                raise RuntimeError('negative control target mismatch: ' + name + ':' + symbol)
            modified = modified.replace(function, function.replace(before, after, 1), 1)
        outcomes = {}
        try:
            target.write_text(modified)
            run(build, output, name + '-build', environment)
            for group in groups:
                result = subprocess.run([str(output / 'routes_test'), 'covered-' + group],
                                        cwd=output, env=environment, text=True,
                                        capture_output=True, timeout=30)
                log = result.stdout + result.stderr
                (output / (name + '-' + group + '.log')).write_text(log)
                if not result.returncode or not result.stderr.strip().endswith(': ' + assertion):
                    raise RuntimeError('negative control missed expected assertion: ' + name + ':' + group)
                outcomes[group] = {'returncode': result.returncode, 'assertion': assertion}
        finally:
            target.write_text(original)
        caught[name] = {'caught': True, 'groups': outcomes}
        print('negative-control ' + name + ': CAUGHT', flush=True)
    run(build, output, 'build-restored', environment)
    run([str(output / 'routes_test')], output, 'restored-all', environment)
    return caught


def main():
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--through-patch', default='999-zo-net-airoha-retain-pon-coverage-on-route-failure.patch')
    parser.add_argument('--negative-controls', action='store_true',
                        help='Revert ZO fixes in test copies and require their specific runtime failures')
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(tests / 'out'):
        parser.error('output must be a new directory within bank1_routes/out')
    output.mkdir(parents=True, exist_ok=False)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    source = args.source.resolve() / DRIVER
    names = FILES + ('airoha_bank1_routes.h',)
    originals = {name: (source / name).read_bytes() for name in names}
    binding = SourceBinding(repo / 'target/linux/airoha/patches-6.18', output, args.through_patch)
    binding.bind(source, [name for name in names if name not in ('airoha_eth.c', 'airoha_eth.h')])
    driver = output / 'bound-source' / DRIVER
    for name in ('airoha_eth.c', 'airoha_eth.h'):
        (driver / name).write_bytes(originals[name])
    header = originals['airoha_eth.h'].decode()
    layout = re.search(r'^struct airoha_bank1_routes \{\n.*?^\};', header, re.M | re.S)
    if not layout:
        raise RuntimeError('production bank1 route layout missing')
    (output / 'route_layout.inc').write_text(layout.group() + '\n')
    eth = originals['airoha_eth.c'].decode()
    if eth.index('#include "airoha_ct_cpu_fallback.h"') > eth.index('#include "airoha_bank1_routes.h"'):
        raise RuntimeError('unexpected production include order')
    extracted = {}
    for filename, symbols in FUNCTIONS.items():
        for symbol in symbols:
            extracted[symbol] = extract_function(originals[filename].decode(), symbol)
    for symbol in (*INGRESS_FUNCTIONS, 'airoha_disable_qos_for_gdm34'):
        extracted[symbol] = extract_function(eth, symbol)
    (output / 'route_functions.inc').write_text('\n'.join(extracted.values()))
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    binary = output / 'routes_test'
    build = ['clang', '-std=gnu11', '-DTEST_PON_INGRESS', '-DTEST_PON_COVERED',
             '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter', '-Wno-sign-compare',
             '-Wno-unused-function', '-O1', '-g', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer',
             '-I', str(output), '-I', str(driver), str(tests / 'routes_test.c'),
             '-o', str(binary)]
    run(build, output, 'build', environment)
    groups = ('normal', 'open-fault', 'recovery', 'claim-drop', 'claim-readback', 'revoke-drop',
              'revoke-readback', 'fallback-drop', 'fallback-readback')
    results = {}
    for group in groups:
        result = subprocess.run([str(binary), 'covered-' + group], cwd=output,
                                env=environment, text=True, capture_output=True, timeout=30)
        log = result.stdout + result.stderr
        (output / (group + '.log')).write_text(log)
        results[group] = {'passed': result.returncode == 0, 'returncode': result.returncode,
                          'output': log.strip()}
        print(group + ': ' + ('PASS' if result.returncode == 0 else 'FAIL'), flush=True)
    controls = {}
    if args.negative_controls:
        if not all(result['passed'] for result in results.values()):
            raise RuntimeError('negative controls require all baseline groups to pass')
        controls = negative_controls(output, driver, build, environment)
    binding.verify_unchanged()
    for name, data in originals.items():
        if (source / name).read_bytes() != data:
            raise RuntimeError('source changed during run: ' + name)
    report = {'passed': all(result['passed'] for result in results.values()),
              'source': str(source), 'groups': results, 'binding': binding.report(),
              'negative_controls': controls,
              'upstream_files_sha256': {name: digest(originals[name])
                                       for name in ('airoha_eth.c', 'airoha_eth.h')},
              'extracted_sha256': {name: digest(text.encode()) for name, text in extracted.items()},
              'test_sha256': {name: digest((tests / name).read_bytes())
                              for name in ('verify_covered.py', 'routes_test.c', 'covered_test.inc')},
              'scope': 'Actual route/fallback helpers; MMIO fault model; diagnostic admission is a fixture'}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('report: ' + str(output / 'report.json'))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
