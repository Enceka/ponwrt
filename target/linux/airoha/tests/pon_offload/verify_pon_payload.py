#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import re


PACKAGE = Path(__file__).resolve().parents[5] / 'package/firmware/hg5585f-ct-npu-firmware'
INSTALLED_NAMES = {'code': 'npu_pon_full_rv32.bin', 'data': 'npu_pon_full_data.bin'}
SOURCE_NAMES = {'elf': 'lab.elf', 'code': 'ram-npu_rv32.bin', 'data': 'ram-npu_data.bin'}


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def sha256(content):
    return hashlib.sha256(content).hexdigest()


def unique_object(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, 'duplicate JSON key: ' + name)
        result[name] = value
    return result


def read_json(path):
    return json.loads(path.read_text(), object_pairs_hook=unique_object)


def match_fields(actual, expected, path='manifest'):
    require(type(actual) is type(expected), path + ': type mismatch')
    if isinstance(expected, dict):
        for name, value in expected.items():
            require(name in actual, path + ': missing ' + name)
            match_fields(actual[name], value, path + '.' + name)
    else:
        require(actual == expected, path + ': identity mismatch')


def load_identity(package=PACKAGE):
    identity = read_json(package / 'pon-full.json')
    require(identity['schema'] == 1 and identity['profile'] == 'hg5585f-ct-pon-full',
            'unsupported PON payload identity')
    require(identity['installed_names'] == INSTALLED_NAMES, 'unexpected installed names')
    manifest = identity['manifest']
    pins = {}
    for line in (package / 'SHA256SUMS.pon-full').read_text().splitlines():
        match = re.fullmatch(r'([0-9a-f]{64})  (\S+)', line)
        require(match is not None, 'invalid SHA256SUMS.pon-full entry')
        digest, name = match.groups()
        require(name not in pins, 'duplicate SHA256SUMS.pon-full entry')
        pins[name] = digest
    require(pins == {name: manifest[section]['sha256']
                     for section, name in INSTALLED_NAMES.items()},
            'package digest pins disagree with identity')
    for section, name in SOURCE_NAMES.items():
        description = manifest[section]
        require(description['name'] == name, 'unexpected source name: ' + section)
        require(type(description['bytes']) is int and description['bytes'] > 0,
                'invalid size: ' + section)
        require(re.fullmatch(r'[0-9a-f]{64}', description['sha256']) is not None,
                'invalid digest: ' + section)
    require(manifest['code']['bytes'] <= 0x18000 and manifest['data']['bytes'] == 4,
            'payload exceeds loader bounds')
    return identity


def verify(directory, installed=False, package=PACKAGE):
    identity = load_identity(package)
    manifest = identity['manifest']
    if not installed:
        match_fields(read_json(directory / 'ram-payload.json'), manifest)
    names = INSTALLED_NAMES if installed else SOURCE_NAMES
    checked = {}
    for section, name in names.items():
        path = directory / name
        require(path.is_file() and not path.is_symlink(), 'expected regular payload: ' + name)
        expected = manifest[section]
        require(path.stat().st_size == expected['bytes'], 'size mismatch: ' + name)
        content = path.read_bytes()
        require(len(content) == expected['bytes'], 'size changed: ' + name)
        require(sha256(content) == expected['sha256'], 'digest mismatch: ' + name)
        if section == 'data':
            require(content == bytes(4), 'data must be four zero bytes')
        checked[name] = {'bytes': len(content), 'sha256': expected['sha256']}
    return {'passed': True, 'profile': identity['profile'],
            'mode': 'installed' if installed else 'source',
            'source_revision': identity['source_revision'], 'files': checked}


def main():
    parser = argparse.ArgumentParser(description='Verify the pinned HG5585F PON full-image payload offline')
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--payload-dir', type=Path, help='Original build directory with ELF and ram-payload.json')
    mode.add_argument('--installed-dir', type=Path, help='Package input directory with npu_pon_full_*.bin')
    args = parser.parse_args()
    try:
        result = verify(args.installed_dir or args.payload_dir, args.installed_dir is not None)
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(1, f'PON payload verification failed: {error}\n')
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
