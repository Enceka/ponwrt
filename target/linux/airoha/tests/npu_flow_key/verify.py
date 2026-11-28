#!/usr/bin/env python3
"""Verify the ZX IPv4 encoder against the real firmware parser and AUTH table."""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import subprocess
import sys

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
REPOSITORY = HERE.parents[4]
sys.path.insert(0, str(HERE.parent / 'npu_ingress'))
from source_binding import SourceBinding, exact_hunks

DRIVER = Path('drivers/net/ethernet/airoha')
HEADER = 'airoha_npu_flow_key.h'
PUBLISH = 'airoha_npu_auth_publish.h'
ABI = 'npu_auth_mailbox_abi.h'
PATCH = '999-zx-net-airoha-encode-pon-ingress-authorization.patch'


def digest(data):
    return hashlib.sha256(data).hexdigest()


def mutants():
    simple = {
        'bank1-metadata': ('epoch, token, 0, row, 4, 2', 'epoch, token, 1, row, 4, 2'),
        'wrong-domain': ('epoch, token, 0, row, 4, 2', 'epoch, token, 0, row, 1, 2'),
        'wrong-producer': ('epoch, token, 0, row, 4, 2', 'epoch, token, 0, row, 4, 24'),
        'lose-token': ('epoch, token, 0, row', 'epoch, (token ^ 1u), 0, row'),
        'lose-row': ('epoch, token, 0, row', 'epoch, token, 0, (row ^ 1u)'),
        'source-port-overflow': ('identity->source_port > 0xffffu ||', '0 ||'),
        'destination-port-overflow': ('identity->destination_port > 0xffffu ||', '0 ||'),
        'swap-ports': ('identity->source_port << 16 | identity->destination_port',
                       'identity->destination_port << 16 | identity->source_port'),
        'swap-addresses': ('encoded.raw[11] = identity->source_ip;',
                           'encoded.raw[11] = identity->destination_ip;'),
        'lose-destination-ip': ('encoded.raw[15] = identity->destination_ip;',
                                'encoded.raw[15] = 0;'),
        'wrong-family': ('encoded.raw[9] = 4;', 'encoded.raw[9] = 6;'),
        'lose-generation': ('encoded.raw[8] = generation;', 'encoded.raw[8] = generation ^ 1u;'),
        'drop-outer-vlan': ('encoded.raw[21] = identity->vlan[0];', 'encoded.raw[21] = 0;'),
        'drop-inner-vlan': ('encoded.raw[22] = identity->vlan[1];', 'encoded.raw[22] = 0;'),
        'truncate-vlan-tci': ('encoded.raw[21] = identity->vlan[0];',
                             'encoded.raw[21] = identity->vlan[0] & 0xffff0fffu;'),
        'wrong-ppp-protocol': ('identity->pppoe_session ? 0x21u : 0', 'identity->pppoe_session ? 0x57u : 0'),
        'ppp-protocol-without-session': ('identity->pppoe_session ? 0x21u : 0', '0x21u'),
        'swap-mac-halves': ('(auth_u32)identity->destination_mac[4] << 24',
                            '(auth_u32)identity->source_mac[4] << 24'),
        'drop-source-mac-byte': ('identity->source_mac[5];', '0;'),
        'dirty-reserved-word': ('encoded.raw[9] = 4;', 'encoded.raw[9] = 4; encoded.raw[31] = 1;'),
        'skip-validator': ('error = airoha_npu_auth_rules_validate(epoch, generation, &encoded, 1);',
                           'error = 0; (void)generation;'),
        'output-before-validation': ('error = airoha_npu_auth_rules_validate(epoch, generation, &encoded, 1);',
                                     '*rule = encoded;\n\terror = airoha_npu_auth_rules_validate(epoch, generation, &encoded, 1);'),
        'ignore-validator-error': ('if (error)\n\t\treturn error;', 'if (error)\n\t\treturn 0;'),
    }
    for name, edit in simple.items():
        yield name, (edit,)
    yield 'truncate-service-before-validation', (
        ('identity->service > 0xffffu ||', '0 ||'),
        ('encoded.raw[7] = identity->service;', 'encoded.raw[7] = identity->service & 0xffffu;'),
    )
    yield 'truncate-session-before-validation', (
        ('identity->pppoe_session > 0xffffu', '0'),
        ('encoded.raw[23] = identity->pppoe_session;', 'encoded.raw[23] = identity->pppoe_session & 0xffffu;'),
    )
    yield 'truncate-protocol-before-validation', (
        ('(identity->protocol != 6u && identity->protocol != 17u)', '0'),
        ('encoded.raw[10] = identity->protocol;', 'encoded.raw[10] = identity->protocol & 0xffu;'),
    )
    yield 'discard-unused-vlan-data', (
        ('encoded.raw[21] = identity->vlan[0];', 'encoded.raw[21] = identity->vlan_count ? identity->vlan[0] : 0;'),
        ('encoded.raw[22] = identity->vlan[1];', 'encoded.raw[22] = identity->vlan_count == 2 ? identity->vlan[1] : 0;'),
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', '--source-snapshot', dest='source', type=Path,
                        default=REPOSITORY.parent / 'pon-npu-diag-20261127/auth-bank-metadata/source')
    parser.add_argument('--firmware', type=Path,
                        default=REPOSITORY.parent.parent / 'an7581-npu-firmware')
    parser.add_argument('--output', type=Path,
                        default=REPOSITORY.parent / 'pon-npu-diag-20261127/flow-key' /
                        datetime.now().strftime('%Y%m%d-%H%M%S'))
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    source, firmware, output = args.source.resolve(), args.firmware.resolve(), args.output.resolve()
    if (output.is_relative_to(REPOSITORY) or any(
            output == root or output.is_relative_to(root) or root.is_relative_to(output)
            for root in (source, firmware))):
        parser.error('output must be new, outside ponwrt, and separate from source and firmware')
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    inputs = {path: path.read_bytes() for path in (
        source / DRIVER / PUBLISH, source / DRIVER / ABI,
        firmware / 'include' / ABI, firmware / 'include/npu_ingress_auth.h',
        firmware / 'src/ingress_auth.c',
    )}
    test_inputs = {path: path.read_bytes() for path in HERE.iterdir() if path.is_file()}
    helper = HERE.parent / 'npu_ingress/source_binding.py'
    helper_bytes = helper.read_bytes()
    output.mkdir(parents=True, exist_ok=False)
    temporary = output / 'tmp'
    temporary.mkdir()
    environment = dict(os.environ, TMPDIR=str(temporary),
                       ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    commands = []

    def run(command, log, required=True, cwd=None):
        command = [str(argument) for argument in command]
        commands.append(command)
        result = subprocess.run(command, cwd=cwd, env=environment, text=True,
                                capture_output=True, timeout=120)
        log.write_text(result.stdout + result.stderr)
        if required and result.returncode:
            raise RuntimeError(str(log) + ':\n' + result.stdout + result.stderr)
        return result

    binding = SourceBinding(REPOSITORY / 'target/linux/airoha/patches-6.18', output, PATCH)
    patch_data = binding.snapshot[PATCH]
    assert patch_data.splitlines()[0] == b'From: Enceka <enceka@yeah.net>'
    assert re.findall(rb'^\+\+\+ ([^\n]+)$', patch_data, re.M) == [b'b/' + str(DRIVER / HEADER).encode()]
    sections = list(binding.sections(patch_data, (HEADER,)))
    assert len(sections) == 1 and sections[0][1], 'ZX must only add the encoder header'
    exact_hunks(b'', sections[0][2])
    staged = output / 'applied-source'
    driver = staged / DRIVER
    driver.mkdir(parents=True)
    for name in (PUBLISH, ABI):
        (driver / name).write_bytes(inputs[source / DRIVER / name])
    source_header = source / DRIVER / HEADER
    already_applied = source_header.exists()
    if already_applied:
        inputs[source_header] = source_header.read_bytes()
        (driver / HEADER).write_bytes(inputs[source_header])
    else:
        patch_file = output / PATCH
        patch_file.write_bytes(patch_data)
        applied = run(['patch', '--batch', '--forward', '--fuzz=0', '-p1', '-i', patch_file],
                      output / 'apply-zx.log', cwd=staged)
        assert not re.search(r'fuzz|offset|FAILED|reversed', applied.stdout + applied.stderr, re.I)
    binding.bind(driver, (PUBLISH, HEADER))
    assert inputs[source / DRIVER / ABI] == inputs[firmware / 'include' / ABI], 'mailbox ABI differs'
    print('PASS exact SourceBinding through ' + PATCH, flush=True)
    original = (driver / HEADER).read_text()
    compiler = shlex.split(args.cc)
    flags = ['-std=c11', '-O1', '-g', '-Wall', '-Wextra', '-Werror', '-Wshadow',
             '-Wstrict-prototypes', '-fno-omit-frame-pointer', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-DNPU_CT_FE_PON_AUTH=1']
    version = run(compiler + ['--version'], output / 'compiler.log').stdout
    firmware_object = output / 'ingress_auth.o'
    run(compiler + flags + ['-I', firmware / 'include', '-c', firmware / 'src/ingress_auth.c',
                            '-o', firmware_object], output / 'firmware-build.log')

    def build_run(name, text):
        directory = output / name
        directory.mkdir()
        (directory / HEADER).write_text(text)
        binary = directory / 'flow-key-test'
        run(compiler + flags + ['-I', directory, '-I', driver, '-I', firmware / 'include',
                                HERE / 'flow_key_test.c', firmware_object, '-o', binary],
            directory / 'build.log')
        return run([binary], directory / 'run.log', required=False)

    baseline = build_run('baseline', original)
    if baseline.returncode:
        raise RuntimeError('baseline failed:\n' + baseline.stdout + baseline.stderr)
    summary = json.loads(baseline.stdout)
    assert summary['passed']
    print('PASS baseline ' + baseline.stdout.strip(), flush=True)
    caught = []
    for name, edits in mutants():
        text = original
        for before, after in edits:
            assert text.count(before) == 1, name
            text = text.replace(before, after, 1)
        result = build_run(name, text)
        assert (result.returncode == 1 and 'CHECK failed [' in result.stderr and
                'Sanitizer' not in result.stderr and 'runtime error:' not in result.stderr), (
                    name, result.stdout, result.stderr)
        caught.append({'name': name, 'exit_code': result.returncode, 'assertion': result.stderr.strip()})
        print('PASS runtime mutant ' + name, flush=True)
    binding.verify_unchanged()
    assert binding.read_patches()[PATCH] == patch_data, 'ZX changed during tests'
    assert source_header.exists() == already_applied, 'source snapshot changed during tests'
    for path, data in {**inputs, **test_inputs, helper: helper_bytes}.items():
        assert path.read_bytes() == data, 'input changed during tests: ' + str(path)
    report = {
        'passed': True, 'baseline': summary, 'source_binding': binding.report(),
        'encoder_from_snapshot': already_applied, 'sanitizers': ['address', 'undefined'],
        'negative_controls': caught, 'compiler': version, 'commands': commands,
        'inputs_sha256': {str(path): digest(data) for path, data in inputs.items()},
        'tests_sha256': {path.name: digest(data) for path, data in test_inputs.items()},
        'source_binding_helper_sha256': digest(helper_bytes),
        'scope': 'Pure IPv4 encoder and public validator; real firmware parser, ADD/ARM, domain decode, take and lease completion. No owner publication, hardware row installation or RX/cookie association.',
    }
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print('PASS ' + str(len(caught)) + ' mutants; report: ' + str(output / 'report.json'), flush=True)


if __name__ == '__main__':
    main()
