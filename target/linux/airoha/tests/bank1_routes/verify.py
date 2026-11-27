#!/usr/bin/env python3
"""Exercise copied production route helpers with MMIO faults and sanitizer checks."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess


DRIVER = Path('drivers/net/ethernet/airoha')
FILES = ('airoha_eth.h', 'airoha_eth.c', 'airoha_ct_cpu_fallback.h',
         'airoha_ct_pon_ifc_cpu.h', 'airoha_ct_pair_banks.h', 'airoha_ct_pon_ifc_words.h',
         'airoha_ct_fe_native.h', 'airoha_ct_ifc_command.h')
FUNCTIONS = {
    'airoha_eth.c': ('airoha_set_gdm_port_fwd_cfg', 'airoha_dev_set_qdma'),
    'airoha_ct_pair_banks.h': ('airoha_ct_pair_gdm_route', 'airoha_ct_pair_gdm_start',
                              'airoha_ct_pair_gdm_stop'),
    'airoha_ct_fe_native.h': ('airoha_ct_fe_table',),
    'airoha_ct_pon_ifc_cpu.h': ('airoha_ct_pon_ifc_read', 'airoha_ct_pon_ifc_route_open'),
}
INGRESS_FILES = ('airoha_npu_ingress.h', 'airoha_ct_pon_ifc_owner.h')
INGRESS_FUNCTIONS = ('airoha_ifc_update_ports', 'airoha_ifc_scope_ports',
                     'airoha_ifc_scope_update', 'airoha_ifc_lan_ports_ready')


def extract_function(source, name):
    matches = list(re.finditer(r'^(?:static )?[A-Za-z_][\w \t*]*\b' + re.escape(name) + r'\([^;{}]*\)\n\{',
                               source, re.MULTILINE))
    if len(matches) != 1:
        raise ValueError('expected one function definition: ' + name)
    start = matches[0].start()
    opening = matches[0].end() - 1
    depth = 1
    end = opening + 1
    while depth and end < len(source):
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    if depth:
        raise ValueError('unterminated function: ' + name)
    return source[start:end] + '\n'


def run(command, output, label, env=None, cwd=None):
    result = subprocess.run(command, capture_output=True, text=True,
                            cwd=cwd or output, env=env)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout.strip()


def digest(data):
    return hashlib.sha256(data).hexdigest()


def select_patch(patch_bytes, filenames):
    sections = re.findall(r'^--- [^\n]+\n\+\+\+ b/([^\n]+)\n(.*?)(?=^--- |\Z)',
                          patch_bytes.decode(), re.MULTILINE | re.DOTALL)
    selected = []
    for filename, hunks in sections:
        if filename in {str(DRIVER / name) for name in filenames}:
            selected.append('--- a/' + filename + '\n+++ b/' + filename + '\n' + hunks)
    if not selected:
        raise RuntimeError('patch contains no selected production files')
    return ''.join(selected)


def ingress_mutations(output, driver, build, environment):
    targets = {
        'guard_gdm2_only_while_open': ('airoha_ct_cpu_fallback.h',
            'airoha_ct_gdm_route_write_locked', 'if (id == AIROHA_GDM2_IDX) {',
            'if (id == AIROHA_GDM2_IDX && eth->ct_bank1_routes.pon_open) {'),
        'default_bypasses_auth': ('airoha_ct_cpu_fallback.h',
            'airoha_ct_gdm_route_write_locked', 'mask = GENMASK(15, 0);',
            'cfg = (cfg & ~GENMASK(15, 0)) | FE_PSE_PORT_PPE2 * 0x1111; mask = 0;'),
        'open_without_ingress_ready': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_open', 'if (!routes->ingress_ready || routes->pon_open)',
            'if (routes->pon_open)'),
        'keep_ingress_ready_on_close': ('airoha_bank1_routes.h',
            'airoha_bank1_scope_locked', 'eth->ct_bank1_routes.ingress_ready = false;', ''),
        'skip_scope_readback': ('airoha_bank1_routes.h',
            'airoha_bank1_scope_locked',
            'if (airoha_fe_rr(eth, REG_FE_IFC_PORT_EN) != ports)', 'if (false)'),
        'revoke_without_scope_close': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_revoke_locked',
            'error = airoha_bank1_scope_locked(eth, false);', 'error = 0;'),
        'forbid_fallback_close': ('airoha_bank1_routes.h',
            'airoha_bank1_scope_locked', 'scope = eth->ct_ifc_port_mask;',
            'scope = eth->ct_ifc_port_mask; if (eth->ct_cpu_fallback || eth->ppe->ct_stopping) '
            '{ error = -ESHUTDOWN; goto unlock; }'),
        'revoke_foreign_ingress_owner': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_revoke', 'eth->ct_bank1_routes.owner == owner ?', 'true ?'),
        'check_ignores_cpu_defaults': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_check', 'FE_PSE_PORT_CDM2 * 0x1111',
            '(airoha_fe_rr(eth, REG_GDM_FWD_CFG(AIROHA_GDM2_IDX)) & GENMASK(15, 0))'),
        'allow_other_scope_update': ('route_functions.inc',
            'airoha_ifc_scope_update', 'if (eth->ct_bank1_routes.owner) {', 'if (false) {'),
        'allow_other_scope_ports': ('route_functions.inc',
            'airoha_ifc_scope_ports', 'if (eth->ct_bank1_routes.owner &&',
            'if (false && eth->ct_bank1_routes.owner &&'),
        'release_live_source2': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_release',
            '(airoha_fe_rr(eth, REG_FE_IFC_PORT_EN) & BIT(2))', 'false'),
        'retain_unexpected_scope_ports': ('airoha_bank1_routes.h',
            'airoha_bank1_scope_locked', 'scope &= XSI_ETH_VIP_PORT_MASK;', 'scope &= ~BIT(2);'),
        'drop_owner_on_restore_failure': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_release', 'airoha_bank1_routes_write_all(eth, true);',
            'routes->owner = NULL; airoha_bank1_routes_write_all(eth, true);'),
        'fallback_ignores_scope_failure': ('airoha_ct_cpu_fallback.h',
            'airoha_ct_cpu_fallback', 'err = airoha_bank1_routes_revoke_locked(eth);',
            'airoha_bank1_routes_revoke_locked(eth);'),
        'claim_requires_host_ppe_during_stop': ('airoha_bank1_routes.h',
            'airoha_bank1_routes_claim', 'if (!eth->ppe || eth->soc->num_ppe < 2)',
            'if (!eth->ppe || !eth->ppe->ct_host_ppe || eth->soc->num_ppe < 2)'),
    }
    caught = {}
    for name, (filename, function, before, after) in targets.items():
        target = (output if filename.endswith('.inc') else driver) / filename
        original = target.read_text()
        definition = extract_function(original, function)
        if definition.count(before) != 1:
            raise RuntimeError('expected one ingress mutation target: ' + name)
        try:
            target.write_text(original.replace(definition, definition.replace(before, after), 1))
            run(build, output, name + '-build')
            attempt = subprocess.run([str(output / 'routes_test'), 'ingress'],
                                     capture_output=True, text=True, cwd=output, env=environment)
            (output / (name + '.log')).write_text(attempt.stdout + attempt.stderr)
            if attempt.returncode == 0 or 'case ' not in attempt.stderr:
                raise RuntimeError('ingress mutation did not hit runtime assertion: ' + name)
            caught[name] = 'caught'
        finally:
            target.write_text(original)
    run(build, output, 'build-final')
    return caught


def main():
    tests = Path(__file__).resolve().parent
    repo = tests.parents[4]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path,
                        help='Read-only kernel source through 987, 996, or 999-zd for ingress')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--case', help='Run one named test group')
    parser.add_argument('--reopen', action='store_true',
                        help='Apply 998 to --source through 996 and test PON reopening')
    parser.add_argument('--invalidation', action='store_true',
                        help='Also apply 999-z route revocation; implies --reopen')
    parser.add_argument('--ingress', action='store_true',
                        help='Apply 999-ze to source through 999-zd and test ingress lifecycle')
    args = parser.parse_args()
    if args.ingress and (args.reopen or args.invalidation):
        parser.error('--ingress is independent of --reopen and --invalidation')
    args.reopen |= args.invalidation
    if args.source is None:
        args.source = repo.parent / ('pon-er-consumer-20261127/owner-source-npu-ingress'
                                     if args.ingress else 'pon-ifc-tuple-987-source')
    if args.output is None:
        args.output = tests / 'out' / 'ingress' if args.ingress else tests / 'out'
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    report_path = output / 'report.json'
    if report_path.exists():
        report_path.unlink()
    patch = repo / 'target/linux/airoha/patches-6.18' / (
        '999-ze-net-airoha-connect-pon-npu-ingress-lifecycle.patch' if args.ingress else
        '998-net-airoha-reopen-owned-pon-default-route.patch' if args.reopen else
        '991-net-airoha-own-gdm-default-routes-for-bank1-isolation.patch')
    patch_bytes = patch.read_bytes()
    tree = output / 'kernel'
    driver = tree / DRIVER
    driver.mkdir(parents=True, exist_ok=True)
    originals = {}
    files = FILES + (INGRESS_FILES if args.ingress else ())
    for name in files:
        originals[name] = (args.source.resolve() / DRIVER / name).read_bytes()
        (driver / name).write_bytes(originals[name])
    added = driver / 'airoha_bank1_routes.h'
    if args.reopen or args.ingress:
        originals[added.name] = (args.source.resolve() / DRIVER / added.name).read_bytes()
        added.write_bytes(originals[added.name])
    elif added.exists():
        added.unlink()
    applied_patch = patch
    if args.ingress:
        applied_patch = output / 'ingress-routes.patch'
        applied_patch.write_text(select_patch(patch_bytes, files + (added.name,)))
    patch_output = run(['patch', '--batch', '--forward', '--fuzz=0',
                        '--no-backup-if-mismatch', '-p1', '-i', str(applied_patch)],
                       output, 'apply', cwd=tree)
    if re.search(r'fuzz|offset|FAILED|reversed', patch_output, re.IGNORECASE):
        raise RuntimeError('patch must apply exactly to the input files:\n' + patch_output)
    health_patch = None
    health_bytes = None
    if args.invalidation:
        health_patch = patch.parent / '999-z-net-airoha-monitor-npu-owner-invalidation.patch'
        health_bytes = health_patch.read_bytes()
        marker = '--- a/' + str(DRIVER / added.name) + '\n'
        route_patch = marker + re.split(r'^--- ', health_bytes.decode().split(marker, 1)[1],
                                       maxsplit=1, flags=re.MULTILINE)[0]
        result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1'],
                                input=route_patch, capture_output=True, text=True, cwd=tree)
        (output / 'apply-invalidation.log').write_text(result.stdout + result.stderr)
        if result.returncode or re.search(r'fuzz|offset|FAILED|reversed', result.stdout,
                                          re.IGNORECASE):
            raise RuntimeError('route invalidation must apply exactly: ' + result.stdout + result.stderr)
    modified = {name: (driver / name).read_bytes() for name in files + ('airoha_bank1_routes.h',)}
    header = modified['airoha_eth.h'].decode()
    layout = re.search(r'^struct airoha_bank1_routes \{\n.*?^\};', header, re.MULTILINE | re.DOTALL)
    if not layout or not re.search(r'struct airoha_bank1_routes\s+ct_bank1_routes;', header):
        raise RuntimeError('missing production bank1 route layout or eth field')
    (output / 'route_layout.inc').write_text(layout.group() + '\n')
    eth = modified['airoha_eth.c'].decode()
    if eth.index('#include "airoha_ct_cpu_fallback.h"') > eth.index('#include "airoha_bank1_routes.h"'):
        raise RuntimeError('guard must follow fallback in eth.c')
    extracted = {}
    for filename, names in FUNCTIONS.items():
        for name in names:
            extracted[name] = extract_function(modified[filename].decode(), name)
    if args.reopen or args.ingress:
        extracted['airoha_disable_qos_for_gdm34'] = extract_function(
            modified['airoha_eth.c'].decode(), 'airoha_disable_qos_for_gdm34')
    if args.ingress:
        for name in INGRESS_FUNCTIONS:
            extracted[name] = extract_function(eth, name)
    (output / 'route_functions.inc').write_text('\n'.join(extracted.values()))
    compiler = shutil.which(args.cc)
    if not compiler:
        raise RuntimeError('compiler unavailable: ' + args.cc)
    version = run([compiler, '--version'], output, 'compiler')
    if 'clang' not in version.lower():
        raise RuntimeError('clang is required')
    build = [compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
             '-Wno-sign-compare',
             '-O1', '-g', '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer', '-I', str(output), '-I', str(driver),
             str(tests / 'routes_test.c'), '-o', str(output / 'routes_test')]
    if args.reopen:
        build.insert(1, '-DTEST_PON_REOPEN')
    if args.invalidation:
        build.insert(1, '-DTEST_OWNER_INVALIDATION')
    if args.ingress:
        build.insert(1, '-DTEST_PON_INGRESS')
    run(build, output, 'build')
    environment = dict(os.environ)
    environment['ASAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1'
    environment['UBSAN_OPTIONS'] = 'halt_on_error=1:print_stacktrace=1'
    command = [str(output / 'routes_test')] + ([args.case] if args.case else [])
    result = run(command, output, 'routes_test', environment)
    mutations = {}
    if args.reopen and not args.case:
        targets = {
            'open_wrong_gdm': ('airoha_ct_cpu_fallback.h',
                'id == AIROHA_GDM2_IDX && eth->ct_bank1_routes.pon_open',
                'id == AIROHA_GDM1_IDX && eth->ct_bank1_routes.pon_open'),
            'release_open_owner': ('airoha_bank1_routes.h',
                'routes->pon_open || airoha_fe_rr', 'airoha_fe_rr'),
            'ignore_revoke_latch': ('airoha_bank1_routes.h',
                'routes->owner != owner || !routes->ready || routes->revoked',
                'routes->owner != owner'),
            'ignore_cpu_fallback': ('airoha_bank1_routes.h',
                'eth->ct_cpu_fallback || eth->ct_cpu_route_mask[AIROHA_GDM2_IDX - 1]',
                'false'),
            'forget_open_fallback_mask': ('airoha_ct_cpu_fallback.h',
                'eth->ct_cpu_route_mask[AIROHA_GDM2_IDX - 1] = GENMASK(15, 0);', ''),
            'skip_new_qdma_close': ('route_functions.inc',
                'if (cur_qdma != qdma)', 'if (cur_qdma && cur_qdma != qdma)'),
            'ignore_published_route_error': ('route_functions.inc',
                'err = airoha_ct_gdm_route_locked', 'airoha_ct_gdm_route_locked'),
            'retain_failed_qdma_pointer': ('route_functions.inc',
                'rcu_assign_pointer(dev->qdma, cur_qdma);', ''),
            'wake_previously_stopped_queue': ('route_functions.inc',
                'if (!test_bit(i, tx_stopped))', 'if (true)'),
            'restore_lro_from_netdev_feature': ('route_functions.inc',
                'if (lro_enabled)', 'if (lro_enabled && (netdev->features & NETIF_F_LRO))'),
            'lose_previous_wan_role': ('route_functions.inc',
                'set_bit(AIROHA_DEV_F_WAN, &dev->flags);', ''),
        }
        if args.invalidation:
            targets.update({
                'revoke_foreign_owner': ('airoha_bank1_routes.h',
                    'eth->ct_bank1_routes.owner == owner ?', 'true ?'),
                'skip_atomic_route_revoke': ('airoha_bank1_routes.h',
                    'airoha_bank1_routes_revoke_locked(eth) : -ESTALE', '0 : -ESTALE'),
            })
        for name, (filename, before, after) in targets.items():
            target = (output if filename.endswith('.inc') else driver) / filename
            original = target.read_text()
            if before not in original:
                raise RuntimeError('missing mutation target: ' + name)
            target.write_text(original.replace(before, after))
            run(build, output, name + '-build')
            group = 'invalidation' if name in ('revoke_foreign_owner', 'skip_atomic_route_revoke') else 'reopen'
            attempt = subprocess.run([str(output / 'routes_test'), group],
                capture_output=True, text=True, cwd=output, env=environment)
            (output / (name + '.log')).write_text(attempt.stdout + attempt.stderr)
            target.write_text(original)
            if attempt.returncode == 0 or 'case ' not in attempt.stderr:
                raise RuntimeError('mutation did not hit runtime assertion: ' + name)
            mutations[name] = 'caught'
        run(build, output, 'build-final')
    if args.ingress and not args.case:
        mutations = ingress_mutations(output, driver, build, environment)
        result = run(command, output, 'routes_test-final', environment)
    if args.ingress:
        for name, data in originals.items():
            if (args.source.resolve() / DRIVER / name).read_bytes() != data:
                raise RuntimeError('baseline changed during testing: ' + name)
    if patch.read_bytes() != patch_bytes:
        raise RuntimeError(patch.name + ' changed during testing; rerun against the completed patch')
    if health_patch and health_patch.read_bytes() != health_bytes:
        raise RuntimeError('999-z changed during testing; rerun against the completed patch')
    report = {
        'passed': True, 'case': args.case or 'all', 'source': str(args.source.resolve()),
        'mode': 'ingress' if args.ingress else 'invalidation' if args.invalidation else
                'reopen' if args.reopen else 'default',
        'patch': str(patch),
        'compiler': version.splitlines()[0], 'sanitizers': ['address', 'undefined'],
        'sanitize_recover': False, 'patch_sha256': digest(patch_bytes),
        'invalidation_patch_sha256': digest(health_bytes) if health_bytes else None,
        'base_sha256': {name: digest(data) for name, data in originals.items()},
        'source_sha256': {name: digest(data) for name, data in modified.items()},
        'extracted_sha256': {name: digest(data.encode()) for name, data in extracted.items()},
        'test_sha256': {name: digest((tests / name).read_bytes())
                        for name in ('verify.py', 'routes_test.c', 'reopen_test.inc',
                                     'invalidation_test.inc') +
                                    (('ingress_test.inc',) if args.ingress else ())},
        'result': result, 'mutations': mutations,
    }
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    print(result)
    print('report: ' + str(report_path))


if __name__ == '__main__':
    main()
