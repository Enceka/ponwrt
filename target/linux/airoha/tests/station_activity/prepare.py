#!/usr/bin/env python3
"""Reconstruct patched wireless sources from repository-pinned source archives."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--downloads', type=Path, required=True,
                    help='OpenWrt dl directory containing the two pinned source archives')
parser.add_argument('--output', type=Path, required=True, help='New output directory')
args = parser.parse_args()
repo = Path(__file__).resolve().parents[5]
output = args.output.resolve()
downloads = args.downloads.resolve()
patch_command = os.environ.get('PATCH', 'patch')
version = subprocess.run([patch_command, '--version'], capture_output=True, text=True, check=True)
if 'GNU patch' not in version.stdout:
    parser.error('source reconstruction requires GNU patch (set PATCH=gpatch on macOS)')
output.mkdir(parents=True, exist_ok=False)
report = {'passed': False, 'archives': {}, 'patches': []}

def variable(makefile, name):
    match = re.search(r'^' + re.escape(name) + r':=(.+)$', makefile, re.M)
    if not match:
        raise ValueError('missing source identity: ' + name)
    return match[1].strip()

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

for package in ('mac80211', 'mt76'):
    package_dir = repo / 'package/kernel' / package
    makefile = (package_dir / 'Makefile').read_text()
    if package == 'mac80211':
        archive_name = 'backports-' + variable(makefile, 'PKG_SOURCE_VERSION') + '.tar.zst'
        expected = variable(makefile, 'PKG_HASH')
        patch_groups = re.findall(r'\$\(call PatchDir,\$\(PKG_BUILD_DIR\),\$\(PATCH_DIR\)/([^,]+),', makefile)
        patch_dirs = [package_dir / 'patches' / group for group in patch_groups]
    else:
        archive_name = 'mt76-' + variable(makefile, 'PKG_SOURCE_DATE').replace('-', '.') + '~' + variable(makefile, 'PKG_SOURCE_VERSION')[:8] + '.tar.zst'
        expected = variable(makefile, 'PKG_MIRROR_HASH')
        patch_dirs = [package_dir / 'patches', package_dir / 'ct-wed/patches']
    archive = downloads / archive_name
    actual = digest(archive)
    if actual != expected:
        raise ValueError('source archive digest mismatch: ' + str(archive))
    report['archives'][package] = {'file': archive_name, 'sha256': actual}
    tree = output / package
    tree.mkdir()
    subprocess.run(['tar', '-xf', str(archive), '-C', str(tree), '--strip-components=1'], check=True)
    for directory in patch_dirs:
        if not directory.is_dir():
            continue
        for patch in sorted(directory.glob('*.patch')):
            # Match OpenWrt's historical patch tolerance; new activity patches
            # must apply with every context line intact.
            fuzz = 0 if patch.name.startswith(('602-mac80211-', '142-mt7915-')) else 2
            process = subprocess.run([patch_command, '--batch', '--forward', '--fuzz=' + str(fuzz), '-p1'],
                                     cwd=tree, input=patch.read_bytes(), capture_output=True)
            entry = {'path': str(patch.relative_to(repo)), 'sha256': digest(patch),
                     'returncode': process.returncode,
                     'output': (process.stdout + process.stderr).decode()}
            report['patches'].append(entry)
            if process.returncode:
                (output / 'prepare-report.json').write_text(json.dumps(report, indent=2) + '\n')
                raise RuntimeError(entry)
    if package == 'mt76':
        target = tree / 'mt7915/ct-wed'
        target.mkdir(exist_ok=True)
        for path in (package_dir / 'ct-wed').iterdir():
            if path.suffix in ('.c', '.h'):
                shutil.copyfile(path, target / path.name)
report['passed'] = True
(output / 'prepare-report.json').write_text(json.dumps(report, indent=2) + '\n')
print('PASS verified source archives and applied %d repository patches; %s' %
      (len(report['patches']), output / 'prepare-report.json'))
