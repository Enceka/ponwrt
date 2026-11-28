#!/usr/bin/env python3
"""Rebuild the complete loader from Linux 6.18.60 and repository patches."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.request


DRIVER = Path('drivers/net/ethernet/airoha')
BASE_URL = ('https://raw.githubusercontent.com/gregkh/linux/v6.18.60/'
            'drivers/net/ethernet/airoha/airoha_npu.c')
BASE_SHA256 = 'd68252c18d195c66d25ac376917db0fa6e00ad1f36df2aa0ae91e1b329fa3356'
OFFLOAD = Path('include/linux/soc/airoha/airoha_offload.h')
OFFLOAD_URL = 'https://raw.githubusercontent.com/gregkh/linux/v6.18.60/' + str(OFFLOAD)
OFFLOAD_SHA256 = '9c1ca951322c80c37315fddbed579a7505a3f6c99dc3de87660a2b46fb7bd436'
NAMES = ('airoha_npu.c', 'airoha_npu_transaction.inc', 'airoha_npu_start.h',
         'airoha_npu_resident.h', 'airoha_npu_er_provider.h',
         'airoha_npu_transaction.h', 'npu_auth_mailbox_abi.h',
         'npu_eth_return_abi.h', 'npu_bank1_gate_abi.h')
SECTION = re.compile(r'^--- ([^\n\t]+)(?:\t[^\n]*)?\n'
                     r'\+\+\+ ([^\n\t]+)(?:\t[^\n]*)?\n'
                     r'.*?(?=^--- |^diff --git |\Z)', re.M | re.S)


def rebuild(base, patches, tree, through=None, offload=None):
    if hashlib.sha256(base).hexdigest() != BASE_SHA256:
        raise ValueError('expected unmodified Linux 6.18.60 airoha_npu.c')
    driver = tree / DRIVER
    driver.mkdir(parents=True)
    (driver / 'airoha_npu.c').write_bytes(base)
    targets = {'b/' + str(DRIVER / name) for name in NAMES}
    if offload is not None:
        if hashlib.sha256(offload).hexdigest() != OFFLOAD_SHA256:
            raise ValueError('expected unmodified Linux 6.18.60 airoha_offload.h')
        (tree / OFFLOAD).parent.mkdir(parents=True)
        (tree / OFFLOAD).write_bytes(offload)
        targets.add('b/' + str(OFFLOAD))
    paths = sorted(patches.glob('*.patch'))
    if through:
        names = [path.name for path in paths]
        if through not in names:
            raise ValueError('unknown final patch: ' + through)
        paths = paths[:names.index(through) + 1]
    chain = []
    for path in paths:
        data = path.read_bytes()
        text = data.decode()
        selected = []
        for section in SECTION.finditer(text):
            if section[2] not in targets:
                continue
            if section[1] not in ('/dev/null', 'a/' + section[2][2:]):
                raise ValueError('unexpected source path in ' + path.name)
            selected.append(section[0])
        if not selected:
            continue
        result = subprocess.run(
            ['patch', '--batch', '--forward', '--fuzz=0',
             '--no-backup-if-mismatch', '-p1'],
            input=''.join(selected), cwd=tree, text=True,
            capture_output=True, timeout=30)
        log = result.stdout + result.stderr
        if result.returncode or re.search(r'fuzz|FAILED|reversed', log, re.I):
            for reject in sorted(driver.glob('*.rej')):
                headings = re.findall(r'^@@.*$', reject.read_text(), re.M)
                log += reject.name + ': ' + '; '.join(headings) + '\n'
            raise RuntimeError(path.name + ':\n' + log)
        chain.append({'patch': path.name,
                      'sha256': hashlib.sha256(data).hexdigest(),
                      'applied_sha256': hashlib.sha256(''.join(selected).encode()).hexdigest(),
                      'application': log.strip()})
    return driver, chain


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument('--base', type=Path,
                        help='Unmodified Linux 6.18.60 airoha_npu.c; offline input')
    source.add_argument('--fetch-base', action='store_true',
                        help='Fetch the SHA256-pinned upstream base')
    parser.add_argument('--through', help='Last repository patch to apply')
    parser.add_argument('--output', type=Path, help='New output directory outside ponwrt')
    args = parser.parse_args()
    tests = Path(__file__).resolve().parent
    patches = tests.parents[1] / 'patches-6.18'
    try:
        if args.base:
            base = args.base.read_bytes()
        else:
            with urllib.request.urlopen(BASE_URL, timeout=30) as response:
                base = response.read()
        def build(output):
            driver, chain = rebuild(base, patches, output / 'kernel', args.through)
            (output / 'upstream.c').write_bytes(base)
            (output / 'binding.json').write_text(json.dumps(chain, indent=2) + '\n')
            print('Applied ' + str(len(chain)) + ' loader patches without fuzz')
            for name in NAMES:
                path = driver / name
                if path.exists():
                    print(hashlib.sha256(path.read_bytes()).hexdigest() + '  ' + name)
        if args.output:
            output = args.output.resolve()
            if output.is_relative_to(tests.parents[4]) or output.exists():
                parser.error('output must be a new directory outside ponwrt')
            output.mkdir(parents=True, exist_ok=False)
            build(output)
        else:
            with tempfile.TemporaryDirectory(prefix='source-binding-') as temporary:
                build(Path(temporary))
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, str(error) + '\n')


if __name__ == '__main__':
    main()
