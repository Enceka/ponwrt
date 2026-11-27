"""Reconstruct test inputs from ordered production patches without fuzz."""
import hashlib
from pathlib import Path
import re
import subprocess


DRIVER = Path('drivers/net/ethernet/airoha')
SECTION = re.compile(r'^--- ([^\n\t]+)(?:\t[^\n]*)?\n'
                     r'\+\+\+ ([^\n\t]+)(?:\t[^\n]*)?\n'
                     r'.*?(?=^--- |^diff --git |\Z)', re.M | re.S)
HUNK = re.compile(r'^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@[^\n]*\n', re.M)


def exact_hunks(original, section):
    lines = original.decode().splitlines(True)
    hunks = list(HUNK.finditer(section))
    if not hunks:
        raise ValueError('missing patch hunks')
    previous_end = delta = 0
    for index, hunk in enumerate(hunks):
        old_count, new_count = int(hunk[2] or 1), int(hunk[4] or 1)
        old_start = int(hunk[1]) - bool(old_count)
        new_start = int(hunk[3]) - bool(new_count)
        if old_start < previous_end or old_start > len(lines) or new_start != old_start + delta:
            raise ValueError('patch hunk position mismatch')
        end = hunks[index + 1].start() if index + 1 < len(hunks) else len(section)
        body = section[hunk.end():end].splitlines(True)
        old_lines, new_lines = [], []
        for line in body:
            if len(old_lines) == old_count and len(new_lines) == new_count:
                if line.strip():
                    raise ValueError('unexpected trailing hunk data')
                continue
            if line[:1] not in (' ', '-', '+'):
                raise ValueError('malformed patch hunk')
            if line[0] != '+':
                old_lines.append(line[1:])
            if line[0] != '-':
                new_lines.append(line[1:])
        if len(old_lines) != old_count or len(new_lines) != new_count:
            raise ValueError('patch hunk length mismatch')
        if lines[old_start:old_start + old_count] != old_lines:
            raise ValueError('patch hunk context or position mismatch')
        previous_end = old_start + old_count
        delta += new_count - old_count


class SourceBinding:
    def __init__(self, patches, output, through=None):
        self.patches = patches
        self.output = output
        self.through = through
        self.snapshot = self.read_patches()
        self.originals = {}
        self.chains = {}

    def read_patches(self):
        paths = sorted(self.patches.glob('*.patch'))
        if self.through:
            names = [path.name for path in paths]
            if self.through not in names:
                raise ValueError('unknown final patch: ' + self.through)
            paths = paths[:names.index(self.through) + 1]
        return {path.name: path.read_bytes() for path in paths}

    def sections(self, data, names):
        targets = {'b/' + str(DRIVER / name): name for name in names}
        for match in SECTION.finditer(data.decode()):
            if match[2] in targets:
                name = targets[match[2]]
                if match[1] not in ('/dev/null', 'a/' + str(DRIVER / name)):
                    raise ValueError('unexpected source path for ' + name)
                yield name, match[1] == '/dev/null', match[0]

    def bind(self, source, names):
        tree = self.output / 'bound-source'
        (tree / DRIVER).mkdir(parents=True, exist_ok=False)
        applied = self.output / 'bound-patches'
        applied.mkdir()
        self.originals = {name: (source / name).read_bytes() for name in names}
        self.chains = {name: [] for name in names}
        for patch_name, data in self.snapshot.items():
            selected = list(self.sections(data, names))
            if not selected:
                continue
            for name, added, section in selected:
                if added == bool(self.chains[name]):
                    raise ValueError('missing or duplicate creation: ' + name)
                exact_hunks(b'' if added else (tree / DRIVER / name).read_bytes(), section)
                self.chains[name].append(patch_name)
            patch_file = applied / patch_name
            patch_file.write_text(''.join(section for name, added, section in selected))
            result = subprocess.run(['patch', '--batch', '--forward', '--fuzz=0', '-p1',
                                     '-i', str(patch_file.resolve())], cwd=tree,
                                    capture_output=True, text=True, timeout=30)
            log = result.stdout + result.stderr
            (applied / (patch_name + '.log')).write_text(log)
            if result.returncode or re.search(r'fuzz|offset|FAILED|reversed', log, re.I):
                raise ValueError('patch does not apply exactly: ' + patch_name + '\n' + log)
        for name, data in self.originals.items():
            if not self.chains[name]:
                raise ValueError('no production patch creates ' + name)
            if (tree / DRIVER / name).read_bytes() != data:
                raise ValueError('generated source differs from patch chain: ' + name)
        self.source = source
        return dict(self.originals)

    def verify_unchanged(self):
        current = self.read_patches()
        for name, data in self.originals.items():
            if (self.source / name).read_bytes() != data:
                raise RuntimeError('source changed during run: ' + name)
            expected = [(patch, self.snapshot[patch]) for patch in self.chains[name]]
            actual = [(patch, data) for patch, data in current.items()
                      if list(self.sections(data, [name]))]
            if actual != expected:
                raise RuntimeError('production patch chain changed during run: ' + name)

    def report(self):
        used = {patch for chain in self.chains.values() for patch in chain}
        return {'through_patch': self.through, 'chains': self.chains,
                'patch_sha256': {name: hashlib.sha256(data).hexdigest()
                                 for name, data in self.snapshot.items() if name in used},
                'source_sha256': {name: hashlib.sha256(data).hexdigest()
                                  for name, data in self.originals.items()}}
