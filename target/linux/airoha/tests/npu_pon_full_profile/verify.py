#!/usr/bin/env python3
"""Compile profile/loader/startup tests against the unmodified repository chain."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import resource
import subprocess
import sys
import urllib.request

from source_binding import BASE_URL, DRIVER, NAMES, OFFLOAD, OFFLOAD_URL, rebuild


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def function(source, name):
    match = re.search(r'^(?:static )?[^;{}\n]+(?:\n)?\b' + name +
                      r'\([^;{}]*\)\n\{', source, re.M)
    if not match:
        raise ValueError('missing function: ' + name)
    opening = source.index('{', match.start())
    depth, cursor = 1, opening + 1
    while depth:
        depth += (source[cursor] == '{') - (source[cursor] == '}')
        cursor += 1
    return source[match.start():cursor] + '\n'


def run(command, output, name):
    result = subprocess.run(command, text=True, capture_output=True, timeout=60)
    (output / (name + '.log')).write_text(result.stdout + result.stderr)
    if result.returncode:
        raise RuntimeError(name + ': ' + result.stdout + result.stderr)
    return result.stdout.strip()


def generate(driver, output):
    source = (driver / 'airoha_npu.c').read_text()
    startup = (driver / 'airoha_npu_start.h').read_text()
    profile_enum = re.search(r'enum airoha_npu_profile \{.*?\};', source, re.S)[0] + '\n'
    profile = profile_enum + function(source, 'airoha_npu_profile')
    deferred = function(source, 'airoha_npu_deferred_profile')
    (output / 'loader.inc').write_text(
        function(source, 'airoha_npu_is_connac2_ct') + profile + deferred +
        ''.join(function(source, name) for name in (
            'airoha_npu_native_profile', 'airoha_npu_transaction_profile',
            'airoha_npu_load_firmware', 'airoha_npu_load_firmware_from_dts',
            'airoha_npu_run_firmware')))
    for filename, name in [('ready.inc', 'airoha_npu_wlan_short_guard_ready'),
                           ('native.inc', 'airoha_npu_ct_pair_cmd'),
                           ('put.inc', 'airoha_npu_put')]:
        (output / filename).write_text(function(source, name))
    (output / 'startup.inc').write_text(
        function(source, 'airoha_npu_wlan_short_guard_clear') +
        ''.join(function(startup, name) for name in (
            'airoha_npu_boot', 'airoha_npu_prepare_firmware', 'airoha_npu_start_bound')))
    (output / 'fixed.inc').write_text(
        function(startup, 'airoha_npu_fixed_node') +
        function(startup, 'airoha_npu_resident_device'))
    (output / 'start.inc').write_text(function(startup, 'airoha_npu_start_bound'))
    getter = function(source, 'airoha_npu_get')
    (output / 'get.inc').write_text(profile + deferred + getter)
    assert getter.index('airoha_npu_profile(np)') < getter.index('of_find_device_by_node(np)')
    assert getter.index('airoha_npu_resident_acquire(') < getter.index('airoha_npu_start_bound(')
    assert 'resident = airoha_npu_deferred_profile(np);' in getter
    probe = function(source, 'airoha_npu_probe')
    assert probe.index('airoha_npu_profile(dev->of_node)') < probe.index('devm_platform_ioremap_resource(')
    assert 'instance->deferred_start = airoha_npu_deferred_profile(dev->of_node);' in probe
    assert probe.index('instance->deferred_start =') < probe.index('airoha_npu_prepare_firmware(')
    assert 'REG_CR_BOOT_TRIGGER' not in probe and 'airoha_npu_boot(' not in probe
    admission = probe[probe.index('\terr = airoha_npu_profile('):
                      probe.index('\tbase = devm_platform_ioremap_resource(')]
    (output / 'probe.inc').write_text(
        'static int probe_admission(struct device *dev)\n{\n\tint err;\n' +
        admission + '\treturn 0;\n}\n')


def resident_fixture(tests, output):
    path = tests.parent / 'npu_resident_runtime/runtime_test.c'
    fixture = path.read_text()
    old = function(fixture, 'of_property_read_bool')
    new = '''static bool of_property_read_bool(struct device_node *node, const char *name)
{
    if (!strcmp(name, "airoha,connac2-ordinary-full-test"))
        return false;
    if (!strcmp(name, "airoha,connac2-pon-full"))
        return PROFILE_PON_FULL && node && node->rebuilt;
    CHECK(!strcmp(name, "airoha,connac2-rebuilt-ram-lab"));
    return !PROFILE_PON_FULL && node && node->rebuilt;
}
'''
    assert fixture.count(old) == 1
    (output / 'resident_test.c').write_text(fixture.replace(old, new))
    return {'path': str(path), 'sha256': digest(path)}


def mutations(output, driver, build, arguments):
    loader = output / 'loader.inc'
    checks = {
        'mixed_profiles': (loader, 'ram + ordinary + pon > 1', 'ram + ordinary + pon > 3'),
        'pon_name': (loader, 'npu_pon_full_rv32.bin', 'npu_full_test_rv32.bin'),
        'pon_digest': (loader, '0x3a, 0x42, 0xa0, 0x68', '0x3b, 0x42, 0xa0, 0x68'),
        'data_name': (loader, 'npu_pon_full_data.bin', 'npu_rebuilt_data.bin'),
        'data_digest': (loader, '0xdf, 0x3f, 0x61, 0x98', '0xde, 0x3f, 0x61, 0x98'),
        'pon_deferred': (loader, ' || profile == AIROHA_NPU_PROFILE_PON_FULL', ''),
        'ordinary_transactions': (loader,
            'airoha_npu_is_connac2_ct(dev) && airoha_npu_deferred_profile(dev->of_node)',
            'airoha_npu_native_profile(dev)'),
        'ready': (output / 'ready.inc',
            'READ_ONCE(npu->wlan_short_guard_verified)', 'true'),
        'er_admission': (driver / 'airoha_npu_transaction.inc',
            '\tif (!airoha_npu_wlan_short_guard_ready(npu) ||\n'
            '\t    !airoha_npu_transaction_profile(npu->dev))\n\t\treturn -EOPNOTSUPP;\n', ''),
    }
    caught = {}
    for name, (path, before, after) in checks.items():
        original = path.read_text()
        assert original.count(before) == 1, name
        try:
            path.write_text(original.replace(before, after))
            binary = output / name
            run(build + ['-o', str(binary)], output, name + '-build')
            result = subprocess.run([str(binary)] + arguments, text=True,
                                    capture_output=True, timeout=30)
            (output / (name + '.log')).write_text(result.stdout + result.stderr)
            assert result.returncode and re.search('assertion|Assertion', result.stderr), name
            caught[name] = result.returncode
        finally:
            path.write_text(original)
    return caught


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base', type=Path)
    parser.add_argument('--offload-base', type=Path)
    parser.add_argument('--fetch-base', action='store_true')
    parser.add_argument('--payload-dir', type=Path, required=True)
    parser.add_argument('--sdk-source', type=Path,
                        help='Require exact loader/header equality with a rebuilt SDK source')
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.fetch_base == bool(args.base or args.offload_base):
        parser.error('use --fetch-base or both --base and --offload-base')
    if not args.fetch_base and not (args.base and args.offload_base):
        parser.error('offline input requires --base and --offload-base')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    tests = Path(__file__).resolve().parent
    output = args.output.resolve()
    repo = tests.parents[4]
    if output.is_relative_to(repo) or output.exists():
        parser.error('output must be a new directory outside ponwrt')
    output.mkdir(parents=True, exist_ok=False)
    def read(path, url):
        if path:
            return path.read_bytes()
        with urllib.request.urlopen(url, timeout=30) as response:
            return response.read()
    base = read(args.base, BASE_URL)
    offload = read(args.offload_base, OFFLOAD_URL)
    (output / 'upstream.c').write_bytes(base)
    (output / 'upstream-offload.h').write_bytes(offload)
    patches = tests.parents[1] / 'patches-6.18'
    driver, chain = rebuild(base, patches, output / 'kernel', offload=offload)
    (output / 'binding.json').write_text(json.dumps(chain, indent=2) + '\n')
    sdk_binding = {}
    if args.sdk_source:
        for name in NAMES:
            path = args.sdk_source.resolve() / DRIVER / name
            if path.read_bytes() != (driver / name).read_bytes():
                raise ValueError('SDK source differs from repository chain: ' + str(path))
            sdk_binding[str(path)] = digest(path)
    zy = next(item for item in chain if item['patch'].startswith('999-zy-'))
    assert 'offset' not in zy['application']
    generate(driver, output)
    header = (output / 'kernel' / OFFLOAD).read_text()
    pair = '\n'.join(re.findall(r'^#define AIROHA_CT_PAIR_.*$', header, re.M)) + '\n'
    pair += re.search(r'struct airoha_ct_pair_msg \{.*?\};', header, re.S)[0] + '\n'
    (output / 'pair.inc').write_text(pair)
    (output / 'linux').mkdir()
    (output / 'linux/mutex.h').write_text(
        'struct mutex { int unused; };\n'
        'static void mutex_lock(struct mutex *lock) { (void)lock; }\n'
        'static void mutex_unlock(struct mutex *lock) { (void)lock; }\n')
    fixture = resident_fixture(tests, output)
    flags = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
             '-Wno-unused-function', '-Wno-sign-compare', '-Wno-deprecated-declarations',
             '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
             '-I', str(driver), '-I', str(output)]
    build = flags + [str(tests / 'profile_test.c')]
    if sys.platform != 'darwin':
        build += ['-lcrypto']
    binary = output / 'profile-test'
    run(build + ['-o', str(binary)], output, 'build')
    payloads = [args.payload_dir.resolve() / ('ram-npu_' + part + '.bin')
                for part in ('rv32', 'data')]
    arguments = list(map(str, payloads))
    result = run([str(binary)] + arguments, output, 'profile')
    residents = {}
    for profile, value in [('ram', '0'), ('pon-full', '1')]:
        resident = output / ('resident-' + profile)
        run(flags + ['-pthread', '-DPROFILE_PON_FULL=' + value,
                     str(output / 'resident_test.c'), '-o', str(resident)],
            output, 'resident-' + profile + '-build')
        residents[profile] = json.loads(run([str(resident)], output, 'resident-' + profile))
    caught = mutations(output, driver, build, arguments)
    report = {'passed': True, 'profile': result, 'resident': residents,
              'caught_mutations': caught, 'patches_applied': len(chain),
              'resident_fixture': fixture,
              'sdk_source_sha256': sdk_binding,
              'payload_sha256': {str(path): digest(path) for path in payloads},
              'source_sha256': {path.name: digest(path) for path in driver.iterdir() if path.is_file()},
              'tests_sha256': {path.name: digest(path) for path in tests.iterdir() if path.is_file()}}
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
