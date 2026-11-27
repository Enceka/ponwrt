#!/usr/bin/env python3
"""Exercise the shared command transport through both production callers."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess


def extract(source, signature):
    start = source.index(signature)
    opening = source.index('{', start)
    depth = 0
    for ending in range(opening, len(source)):
        depth += (source[ending] == '{') - (source[ending] == '}')
        if not depth:
            return source[start:ending + 1]
    raise ValueError(signature)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    headers = args.source.resolve() / 'drivers/net/ethernet/airoha'
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    names = ('airoha_ct_ifc_command.h', 'airoha_ct_ifc.h', 'airoha_ct_fe_native.h')
    sources = {name: (headers / name).read_text() for name in names}
    callers = extract(sources[names[1]], 'static int ct_ifc_access(') + '\n'
    callers += extract(sources[names[2]], 'static int airoha_ct_fe_table(') + '\n'
    mutations = {
        'baseline': sources[names[0]],
        'skip_pending_drain': sources[names[0]].replace('if (eth->ct_ifc_command_pending)', 'if (false)'),
        'forget_timeout': sources[names[0]].replace('eth->ct_ifc_command_pending = true;', 'eth->ct_ifc_command_pending = false;'),
        'ignore_drain_timeout': sources[names[0]].replace('if (err)\n\t\t\treturn err;', 'if (err)\n\t\t\terr = 0;'),
    }
    report = {'passed': True, 'mutations': [], 'sources': {
        name: hashlib.sha256(text.encode()).hexdigest() for name, text in sources.items()}}
    for name, header in mutations.items():
        directory = output / name
        directory.mkdir()
        (directory / names[0]).write_text(header)
        (directory / 'ifc_callers.inc').write_text(callers)
        shutil.copyfile(Path(__file__).with_name('ifc_command_test.c'), directory / 'test.c')
        command = ['clang', '-std=gnu11', '-Wall', '-Wextra', '-Werror', '-g',
                   '-fsanitize=address,undefined', str(directory / 'test.c'), '-o', str(directory / 'test')]
        compiled = subprocess.run(command, text=True, capture_output=True)
        (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        result = subprocess.run([str(directory / 'test')], capture_output=True, text=True)
        (directory / 'stdout.txt').write_text(result.stdout)
        (directory / 'stderr.txt').write_text(result.stderr)
        (directory / 'status.json').write_text(json.dumps({'returncode': result.returncode}) + '\n')
        if name == 'baseline':
            result.check_returncode()
            report.update(json.loads(result.stdout))
            assert report['cases'] == 32 and report['blocked_retries'] == 96
        else:
            assert header != sources[names[0]] and result.returncode < 0, name
            assert 'Assertion' in result.stderr or 'assertion' in result.stderr, result.stderr
            report['mutations'].append(name)
    report['sanitizers'] = ['address', 'undefined']
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
