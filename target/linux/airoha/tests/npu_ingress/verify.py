#!/usr/bin/env python3
"""Validate the PON NPU ingress row transaction and stock action encoding."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shutil
import subprocess
import sys

from source_binding import SourceBinding


DRIVER = Path('drivers/net/ethernet/airoha')
HEADER = 'airoha_npu_ingress.h'
PATCH = '999-zd-net-airoha-prepare-authorized-pon-npu-ingress.patch'
DEPENDENCIES = ('airoha_ct_pon_ifc_owner.h', 'airoha_ct_pon_ifc_words.h')


def digest(data):
    return hashlib.sha256(data).hexdigest()


def execute(command, output, label, environment):
    result = subprocess.run(command, cwd=output, env=environment, capture_output=True,
                            text=True, timeout=120)
    (output / (label + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(label + ' failed:\n' + result.stdout + result.stderr)
    return result.stdout


def stock_check(tests, stock_dir, lines):
    sys.path.insert(0, str(tests.parent / 'pon_offload'))
    from verify_ifc_service import Classifier

    classifier = Classifier(stock_dir / 'ifc.ko')
    if len(lines) != 64:
        raise ValueError('expected 64 encoded rows')
    comparisons = 0
    for index, line in enumerate(lines):
        protocol = 0x0800 if index < 32 else 0x86dd
        short_lut = index % 32
        classifier.field(56, 'LUT1_hit', 0, 0)
        classifier.configure(56, 0, protocol, False)
        classifier.field(56, 'GEM_LLID', 0, 0)
        classifier.field(56, 'LUT1_hit', 0, 1 << short_lut)
        classifier.steer(56, 6, 1, 7)
        expected = [value for page in range(9) for value in classifier.rows[0, 56, page]]
        for page in range(3):
            expected.extend(classifier.rows[2, 56, page])
            expected.extend([0] * (3 - len(classifier.rows[2, 56, page])))
        actual = [int(value, 16) for value in line.split()]
        if actual != expected:
            raise ValueError('stock encoding mismatch: ' + str((protocol, short_lut)))
        for source in range(32):
            for service in (0, 1, 0x2134, 0xa134, 0xffff):
                for encapsulation in (0, 0x10, 0x20, 0x400, 0x430):
                    for hits in (0, 1 << short_lut, 1 << ((short_lut + 1) % 32)):
                        wanted = source == 2 and not encapsulation and not (hits & (1 << short_lut))
                        if classifier.matches(56, service, protocol, source, encapsulation, hits) != wanted:
                            raise ValueError('source/encapsulation/LUT predicate mismatch')
                        comparisons += 1
        if short_lut == 31:
            for service in range(65536):
                if not classifier.matches(56, service, protocol):
                    raise ValueError('service must reach firmware authorization: ' + str(service))
                comparisons += 1
        for other_protocol in (0, 0x806, 0x8864, 0x88a8, 0x8100,
                               0x86dd if protocol == 0x0800 else 0x0800):
            if classifier.matches(56, 0x2134, other_protocol):
                raise ValueError('incorrect EtherType admitted')
            comparisons += 1
    return {'stock_sha256': classifier.sha256, 'encoded_rows': 64,
            'compared_words': 64 * 27, 'packet_predicates': comparisons,
            'destination': 'PSE6 channel7', 'sif_model': 'SPORT-indexed key/mask bit'}


def main():
    tests = Path(__file__).resolve().parent
    repository = tests.parents[4]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    parser.add_argument('--through-patch', help='last production patch in the generated tree')
    args = parser.parse_args()
    if not __debug__:
        parser.error('omit Python -O')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    patch = repository / 'target/linux/airoha/patches-6.18' / PATCH
    patch_data = patch.read_bytes()
    if patch_data.decode().splitlines()[0] != 'From: Enceka <enceka@yeah.net>':
        raise ValueError('incorrect patch author')
    if re.findall(r'^\+\+\+ b/(.*)$', patch_data.decode(), re.M) != [str(DRIVER / HEADER)]:
        raise ValueError('unexpected patch scope')
    tree = output / 'kernel'
    driver = tree / DRIVER
    driver.mkdir(parents=True)
    binding = SourceBinding(patch.parent, output, args.through_patch)
    original = binding.bind(args.source.resolve() / DRIVER, (HEADER, *DEPENDENCIES))
    for name, data in original.items():
        (driver / name).write_bytes(data)
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    production = (driver / HEADER).read_text()
    compiler = shutil.which(args.cc)
    if not compiler:
        raise ValueError('compiler unavailable')
    version = execute([compiler, '--version'], output, 'compiler', environment).splitlines()[0]
    build = [compiler, '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-O1', '-g',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-fno-omit-frame-pointer', '-I', str(driver), str(tests / 'ingress_test.c'),
             '-o', str(output / 'ingress_test')]
    execute(build, output, 'build', environment)
    result = json.loads(execute([str(output / 'ingress_test')], output, 'test', environment))
    lines = execute([str(output / 'ingress_test'), 'words'], output, 'words', environment).splitlines()
    stock = stock_check(tests, args.stock_dir.resolve(), lines)
    mutants = {
        'partial_source_mask': ('[0] = { BIT(2), U32_MAX }', '[0] = { BIT(2), BIT(2) }'),
        'bypass_authorization': ('[0] = { 6 << 8, 0, 0 }', '[0] = { 8 << 8, 0, 0 }'),
        'wrong_channel': ('7 << 10', '6 << 10'),
        'skip_short_guard': ('[4] = { 0, BIT(short_lut) }', '[4] = { 0, 0 }'),
        'overlap_lut_leases': ('short_lut[0] == short_lut[1]', 'false'),
        'skip_tcam_audit': ('actual[1] != expected[index].tcam[page][1] ||\n'
                            '\t\t\t    ((actual[0] ^ expected[index].tcam[page][0]) & actual[1])', 'false'),
        'strict_tcam_memcmp': ('actual[1] != expected[index].tcam[page][1] ||\n'
                               '\t\t\t    ((actual[0] ^ expected[index].tcam[page][0]) & actual[1])',
                               'memcmp(actual, expected[index].tcam[page], 2 * sizeof(u32))'),
        'ignore_tcam_mask': ('actual[1] != expected[index].tcam[page][1] ||', 'false ||'),
        'ignore_tcam_key': ('((actual[0] ^ expected[index].tcam[page][0]) & actual[1])', '0'),
        'skip_action_audit': ('memcmp(actual, expected[index].action[page], count * sizeof(u32))', '0'),
        'skip_cover_audit': ('index < 4', 'index < 2'),
        'skip_cover_publish': ('airoha_ct_pon_ifc_publish(owner, io, 1, &rows[2])', '0'),
        'reverse_publish_order': ('airoha_ct_pon_ifc_publish(owner, io, 1, &rows[2]);\n'
                                  '\tif (!error)\n\t\terror = airoha_ct_pon_ifc_publish(owner, io, 0, rows);',
                                  'airoha_ct_pon_ifc_publish(owner, io, 0, rows);\n'
                                  '\tif (!error)\n\t\terror = airoha_ct_pon_ifc_publish(owner, io, 1, &rows[2]);'),
        'wrong_cover_ring': ('airoha_ct_pon_ifc_cover_encode(&rows[2], 4, 0)',
                             'airoha_ct_pon_ifc_cover_encode(&rows[2], 2, 0)'),
        'wrong_cover_type': ('airoha_ct_pon_ifc_cover_encode(&rows[3], 4, 1)',
                             'airoha_ct_pon_ifc_cover_encode(&rows[3], 4, 0)'),
        'leave_cover_on_restore': ('return airoha_ct_pon_ifc_restore(owner, io);',
                                   'return airoha_ct_pon_ifc_withdraw(owner, io, 0);'),
        'lose_audit_pending': ('owner->pending = true;', 'owner->pending = false;'),
        'ignore_publish_error': ('if (error)\n\t\treturn error;\n\treturn airoha_npu_ingress_check',
                                 'if (error)\n\t\treturn 0;\n\treturn airoha_npu_ingress_check'),
        'skip_final_audit': ('return airoha_npu_ingress_check(owner, io, short_lut);', 'return 0;'),
        'allow_foreign_rows': ('if ((owner->dirty | owner->active) & ~15)', 'if (false)'),
    }
    caught = {}
    for name, (before, after) in mutants.items():
        if before not in production:
            raise ValueError('missing mutation target: ' + name)
        (driver / HEADER).write_text(production.replace(before, after))
        try:
            execute(build, output, name + '-build', environment)
            if name in ('partial_source_mask', 'bypass_authorization', 'wrong_channel', 'skip_short_guard'):
                changed = execute([str(output / 'ingress_test'), 'words'], output,
                                  name + '-words', environment).splitlines()
                if changed == lines:
                    raise RuntimeError('encoding mutation survived: ' + name)
                caught[name] = 'encoded words differ from executed stock setters'
            else:
                attempt = subprocess.run([str(output / 'ingress_test')], cwd=output,
                                         env=environment, capture_output=True, text=True, timeout=120)
                (output / (name + '.log')).write_text(attempt.stdout + attempt.stderr)
                if not attempt.returncode or 'CHECK failed:' not in attempt.stderr:
                    raise RuntimeError('runtime mutation survived: ' + name + '\n' + attempt.stderr)
                caught[name] = 'runtime assertion'
        finally:
            (driver / HEADER).write_text(production)
    execute(build, output, 'build-final', environment)
    binding.verify_unchanged()
    if patch.read_bytes() != patch_data:
        raise RuntimeError('patch changed during verification')
    for name, data in original.items():
        if (args.source.resolve() / DRIVER / name).read_bytes() != data:
            raise RuntimeError('baseline changed during verification')
    report = dict(result, compiler=version, sanitizers=['address', 'undefined'],
                  stock=stock, mutations=caught, source=str(args.source.resolve()),
                  patch_sha256=digest(patch_data), header_sha256=digest(production.encode()),
                  production_binding=binding.report(),
                  dependency_sha256={name: digest(data) for name, data in original.items()},
                  test_sha256={name: digest((tests / name).read_bytes())
                               for name in ('verify.py', 'ingress_test.c', 'kernel_test.c', 'Makefile',
                                            'source_binding.py', 'source_binding_test.py', 'README.md')})
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
