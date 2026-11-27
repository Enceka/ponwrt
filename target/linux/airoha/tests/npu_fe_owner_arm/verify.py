import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import shlex
import shutil
import subprocess
import tempfile


DRIVER = Path('drivers/net/ethernet/airoha')
HEADER = 'airoha_ct_fe_native.h'
PATCH = '997-net-airoha-arm-fe-through-npu-owner.patch'


def function(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for ending in range(opening, len(source)):
        depth += (source[ending] == '{') - (source[ending] == '}')
        if not depth:
            return source[start:ending + 1] + '\n'
    raise ValueError('unterminated function: ' + signature)


def execute(command, directory, environment):
    result = subprocess.run(command, cwd=directory, env=environment, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            timeout=120)
    if result.returncode:
        raise RuntimeError(shlex.join(map(str, command)) + '\n' + result.stdout)
    return result.stdout


def main():
    tests = Path(__file__).resolve().parent
    repository = tests.parents[4]
    root = repository.parent / 'pon-er-consumer-20261127'
    parser = argparse.ArgumentParser(description='Test applied FE owner ARM against real FE mailbox code.')
    parser.add_argument('--source', type=Path, default=root / 'owner-source-996-final')
    parser.add_argument('--abi-source', type=Path, default=root / 'owner-source-993')
    parser.add_argument('--firmware', type=Path,
                        default=repository.parent.parent / 'an7581-npu-firmware')
    parser.add_argument('--output', type=Path)
    parser.add_argument('--cc', default=os.environ.get('CC', 'clang'))
    args = parser.parse_args()
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    patch = repository / 'target/linux/airoha/patches-6.18' / PATCH
    patch_data = patch.read_bytes()
    patch_text = patch_data.decode()
    if patch_text.splitlines()[0] != 'From: Enceka <enceka@yeah.net>':
        raise ValueError('incorrect patch author')
    if re.findall(r'^\+\+\+ b/(.*)$', patch_text, re.M) != [str(DRIVER / HEADER)]:
        raise ValueError('997 must modify only the FE native header')
    baseline = {name: (args.source / DRIVER / name).read_bytes() for name in
                (HEADER, 'airoha_eth.h', 'airoha_ct_native_pair.h',
                 'airoha_npu.c', 'airoha_ct_ifc_command.h')}
    abi_path = args.abi_source / 'include/linux/soc/airoha/airoha_offload.h'
    abi_data = abi_path.read_bytes()
    abi = abi_data.decode()
    abi = abi[abi.index('#define AIROHA_CT_PAIR_MAGIC'):abi.index('struct airoha_npu {')]
    firmware_path = args.firmware / 'include/npu_native_pairs.h'
    firmware_data = firmware_path.read_bytes()
    firmware = firmware_data.decode()
    firmware = firmware[:firmware.index('/* Called under pair lock once per consumed descriptor.')]
    firmware += '\n#endif\n#endif\n'
    layout = re.search(r'\tstruct \{\n\t\tconst void \*owner;.*?\n\t\} ct_fe;',
                       baseline['airoha_eth.h'].decode(), re.S)
    if not layout:
        raise ValueError('missing production FE layout')
    native = baseline['airoha_ct_native_pair.h'].decode()
    sender = '#define CT_PAIR_RETRY_US 100000\n'
    for name in ('airoha_ct_pair_exchange_counted', 'airoha_ct_pair_send_from'):
        sender += function(native, 'static int ' + name + '(')
    transport = function(baseline['airoha_npu.c'].decode(),
                         'static int airoha_npu_ct_pair_cmd(')
    environment = dict(os.environ, ASAN_OPTIONS='halt_on_error=1:abort_on_error=1',
                       UBSAN_OPTIONS='halt_on_error=1:print_stacktrace=1')
    compiler = shlex.split(args.cc)
    flags = ['-std=gnu11', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-Wno-unused-parameter', '-O1', '-g', '-fsanitize=address,undefined',
             '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
    print(execute(compiler + ['--version'], tests, environment).splitlines()[0], flush=True)
    with tempfile.TemporaryDirectory(prefix='npu-fe-owner-arm-') as directory:
        temporary = Path(directory)
        driver = temporary / DRIVER
        driver.mkdir(parents=True)
        (driver / HEADER).write_bytes(baseline[HEADER])
        applied = execute(['patch', '--batch', '--forward', '--fuzz=0',
                           '--no-backup-if-mismatch', '-p1', '-i', str(patch)],
                          temporary, environment)
        if re.search(r'fuzz|offset|FAILED|reversed', applied, re.I):
            raise ValueError('inexact patch application:\n' + applied)
        print(applied.strip(), flush=True)
        original = (driver / HEADER).read_text()
        (driver / 'airoha_ct_ifc_command.h').write_bytes(baseline['airoha_ct_ifc_command.h'])
        generated = {'fe_layout.inc': layout.group() + '\n', 'pair_abi.inc': abi,
                     'native_mailbox.inc': firmware, 'pair_sender.inc': sender,
                     'pair_transport.inc': transport}
        for name, content in generated.items():
            (temporary / name).write_text(content)
        executable = temporary / 'arm_test'
        command = compiler + flags + ['-I' + str(temporary), '-I' + str(driver),
                                      '-I' + str(args.firmware / 'include'),
                                      str(tests / 'arm_test.c'), '-o', str(executable)]
        execute(command, temporary, environment)
        result = execute([str(executable)], temporary, environment)
        print(result.strip(), flush=True)
        arm = function(original, 'static int __maybe_unused airoha_ct_fe_owner_arm(')
        mutants = {
            'ignore-owner': ('ppe->ct_fe.owner != owner', 'false'),
            'truncate-generation': ('ppe->ct_fe.generation != generation',
                                    '(u32)ppe->ct_fe.generation != (u32)generation'),
            'ignore-epoch': ('ppe->ct_fe.epoch != epoch', 'false'),
            'skip-quiesce-ack': ('(!ppe->ct_fe.owner_quiesced && !ppe->ct_fe.arm_pending && !ppe->ct_fe.armed)', 'false'),
            'allow-pending-close': ('ppe->ct_fe.pending ||', 'false ||'),
            'ignore-fallback': ('READ_ONCE(ppe->eth->ct_cpu_fallback)', 'false'),
            'lose-arm-pending': ('ppe->ct_fe.arm_pending = true;', 'ppe->ct_fe.arm_pending = false;'),
            'retain-quiet-after-arm': ('ppe->ct_fe.owner_quiesced = false;', ''),
            'forget-armed-ack': ('ppe->ct_fe.armed = true;', 'ppe->ct_fe.armed = false;'),
            'use-last-epoch': ('if (epoch == U32_MAX)', 'if (false)'),
            'program-lan-rows': ('ppe->ct_fe.arm_pending = true;',
                                 'ppe->ct_fe.arm_pending = true;\n\tairoha_ct_fe_restore(ppe);\n\tairoha_ct_fe_snapshot(ppe);'),
            'cache-success': ('ppe->ct_fe.owner_quiesced = false;',
                              'if (ppe->ct_fe.armed)\n\t\treturn 0;\n\tppe->ct_fe.owner_quiesced = false;'),
        }
        mutation_results = {}
        for name, (before, after) in mutants.items():
            if arm.count(before) != 1:
                raise ValueError('nonunique mutation: ' + name)
            (driver / HEADER).write_text(original.replace(arm, arm.replace(before, after, 1), 1))
            execute(command, temporary, environment)
            mutated = subprocess.run([str(executable)], cwd=temporary, env=environment,
                                     capture_output=True, text=True, timeout=120)
            if mutated.returncode == 0 or 'CHECK failed:' not in mutated.stderr:
                raise RuntimeError('runtime mutation survived: ' + name + '\n' + mutated.stderr)
            mutation_results[name] = 'caught'
            print('KILLED ' + name, flush=True)
        extra_mutants = {
            'pin-same-epoch-close': ('\t\tif ((ppe->ct_fe.arm_pending || ppe->ct_fe.armed) && epoch == ppe->ct_fe.epoch)\n\t\t\treturn -ESTALE;\n', ''),
            'native-control-bypass': ('\tif (ppe->ct_fe.owner != owner)\n\t\treturn -EBUSY;', ''),
        }
        for name, (before, after) in extra_mutants.items():
            if original.count(before) != 1:
                raise ValueError('nonunique mutation: ' + name)
            (driver / HEADER).write_text(original.replace(before, after, 1))
            execute(command, temporary, environment)
            mutated = subprocess.run([str(executable)], cwd=temporary, env=environment,
                                     capture_output=True, text=True, timeout=120)
            if mutated.returncode == 0 or 'CHECK failed:' not in mutated.stderr:
                raise RuntimeError('runtime mutation survived: ' + name + '\n' + mutated.stderr)
            mutation_results[name] = 'caught'
            print('KILLED ' + name, flush=True)
        (driver / HEADER).write_text(original)
        execute(command, temporary, environment)
        execute([str(executable)], temporary, environment)
        for name, data in baseline.items():
            if (args.source / DRIVER / name).read_bytes() != data:
                raise RuntimeError('baseline changed during testing: ' + name)
        if patch.read_bytes() != patch_data or firmware_path.read_bytes() != firmware_data:
            raise RuntimeError('production input changed during testing')
        digest = lambda data: hashlib.sha256(data).hexdigest()
        report = {'passed': True, 'sanitizers': ['address', 'undefined'],
                  'result': result.strip(), 'mutations': mutation_results,
                  'patch_sha256': digest(patch_data),
                  'applied_header_sha256': digest(original.encode()),
                  'baseline_sha256': {name: digest(data) for name, data in baseline.items()},
                  'firmware_sha256': digest(firmware_data), 'abi_sha256': digest(abi_data),
                  'test_sha256': {name: digest((tests / name).read_bytes())
                                  for name in ('verify.py', 'arm_test.c', 'stubs.inc')}}
        if args.output:
            args.output.mkdir(parents=True, exist_ok=True)
            (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
            shutil.copyfile(driver / HEADER, args.output / HEADER)
    print('PASS: real FE mailbox, host sender and transport; '
          + str(len(mutation_results)) + ' runtime mutants; ASan/UBSan', flush=True)


if __name__ == '__main__':
    main()
