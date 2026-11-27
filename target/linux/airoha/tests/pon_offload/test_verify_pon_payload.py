#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

import verify_pon_payload as subject


class PayloadTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.package = self.root / 'package'
        self.payload = self.root / 'build'
        self.installed = self.root / 'installed'
        for directory in (self.package, self.payload, self.installed):
            directory.mkdir()
        self.identity = subject.load_identity()
        self.blobs = {'elf': b'ELF fixture', 'code': b'RV32 fixture', 'data': bytes(4)}
        for section, blob in self.blobs.items():
            self.identity['manifest'][section].update(bytes=len(blob), sha256=subject.sha256(blob))
            (self.payload / subject.SOURCE_NAMES[section]).write_bytes(blob)
            if section in subject.INSTALLED_NAMES:
                (self.installed / subject.INSTALLED_NAMES[section]).write_bytes(blob)
        self.manifest = copy.deepcopy(self.identity['manifest'])
        self.write_identity()
        self.write_manifest()

    def write_identity(self):
        (self.package / 'pon-full.json').write_text(json.dumps(self.identity))
        (self.package / 'SHA256SUMS.pon-full').write_text(''.join(
            f"{self.identity['manifest'][section]['sha256']}  {name}\n"
            for section, name in subject.INSTALLED_NAMES.items()))

    def write_manifest(self):
        (self.payload / 'ram-payload.json').write_text(json.dumps(self.manifest))

    def verify(self, installed=False):
        return subject.verify(self.installed if installed else self.payload,
                              installed=installed, package=self.package)

    def test_committed_identity_and_package_pins(self):
        identity = subject.load_identity()
        self.assertEqual(identity['profile'], 'hg5585f-ct-pon-full')
        self.assertEqual(identity['manifest']['code']['bytes'], 39084)
        self.assertEqual(identity['manifest']['local_sram']['remaining_bytes'], 4)

    def test_source_and_installed_modes(self):
        self.manifest['ct_fe_generic']['layout'] = {'diagnostic': {'address': '0x3e903530'}}
        self.write_manifest()
        source = self.verify()
        installed = self.verify(installed=True)
        self.assertTrue(source['passed'] and installed['passed'])
        self.assertEqual(set(source['files']), set(subject.SOURCE_NAMES.values()))
        self.assertEqual(set(installed['files']), set(subject.INSTALLED_NAMES.values()))
        self.assertEqual(source['mode'], 'source')
        self.assertEqual(installed['mode'], 'installed')

    def test_digest_changes_with_same_size(self):
        for installed in (False, True):
            names = subject.INSTALLED_NAMES if installed else subject.SOURCE_NAMES
            directory = self.installed if installed else self.payload
            for section, name in names.items():
                with self.subTest(installed=installed, section=section):
                    blob = self.blobs[section]
                    (directory / name).write_bytes(bytes([blob[0] ^ 1]) + blob[1:])
                    with self.assertRaisesRegex(ValueError, 'digest mismatch'):
                        self.verify(installed)
                    (directory / name).write_bytes(blob)

    def test_truncated_empty_and_oversize_payloads(self):
        for installed in (False, True):
            names = subject.INSTALLED_NAMES if installed else subject.SOURCE_NAMES
            directory = self.installed if installed else self.payload
            for section, name in names.items():
                blob = self.blobs[section]
                for changed in (blob[:-1], b'', blob + b'\0', bytes(0x18001)):
                    with self.subTest(installed=installed, section=section, size=len(changed)):
                        (directory / name).write_bytes(changed)
                        with self.assertRaisesRegex(ValueError, 'size mismatch'):
                            self.verify(installed)
                (directory / name).write_bytes(blob)

    def test_rewritten_manifest_cannot_replace_pinned_code(self):
        changed = b'different firmware'
        (self.payload / 'ram-npu_rv32.bin').write_bytes(changed)
        self.manifest['code'].update(bytes=len(changed), sha256=subject.sha256(changed))
        self.write_manifest()
        with self.assertRaisesRegex(ValueError, 'manifest.code'):
            self.verify()

    def test_every_feature_and_missing_feature(self):
        original = copy.deepcopy(self.manifest)
        for name, value in original['features'].items():
            for changed in (not value, int(value), None):
                with self.subTest(feature=name, value=changed):
                    self.manifest = copy.deepcopy(original)
                    self.manifest['features'][name] = changed
                    self.write_manifest()
                    with self.assertRaisesRegex(ValueError, 'manifest.features.' + name):
                        self.verify()
            self.manifest = copy.deepcopy(original)
            del self.manifest['features'][name]
            self.write_manifest()
            with self.assertRaisesRegex(ValueError, 'missing ' + name):
                self.verify()

    def test_profile_fields(self):
        original = copy.deepcopy(self.manifest)
        for name in ('native_abi', 'native_caps', 'ct_bridge_guard', 'ct_bridge_guard_profile',
                     'ct_short_pad', 'ct_tdma_bank_profile', 'ct_native_pairs', 'ct_fe_native'):
            with self.subTest(field=name):
                self.manifest = copy.deepcopy(original)
                self.manifest[name] = 0
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, 'manifest.' + name):
                    self.verify()

    def test_addresses_sram_size_and_names(self):
        original = copy.deepcopy(self.manifest)
        changes = [('code', 'npu_address', '0x84000004'), ('data', 'host_address', '0x1e900004'),
                   ('data', 'npu_address', '0x3e900004'), ('code', 'bytes', 0x18001),
                   ('data', 'bytes', 8), ('elf', 'sha256', '0' * 64),
                   ('code', 'name', '../outside'), ('local_sram', 'bss_end', '0x3e9037cc'),
                   ('local_sram', 'remaining_bytes', 8), ('ct_fe_generic', 'source_port', 2),
                   ('ct_fe_generic', 'output_pse', 4), ('ct_fe_generic', 'channel', 6)]
        for section, field, value in changes:
            with self.subTest(section=section, field=field):
                self.manifest = copy.deepcopy(original)
                self.manifest[section][field] = value
                self.write_manifest()
                with self.assertRaisesRegex(ValueError, 'manifest.' + section):
                    self.verify()

    def test_package_pin_drift_duplicates_and_missing_entry(self):
        path = self.package / 'SHA256SUMS.pon-full'
        original = path.read_text()
        for changed in (original.replace(original[:64], '0' * 64), original + original,
                        original.splitlines()[0] + '\n', original + 'malformed\n'):
            with self.subTest(pins=changed):
                path.write_text(changed)
                with self.assertRaisesRegex(ValueError, 'digest pins|SHA256SUMS'):
                    self.verify()

    def test_missing_file_and_symlink(self):
        path = self.installed / subject.INSTALLED_NAMES['code']
        path.unlink()
        with self.assertRaisesRegex(ValueError, 'regular payload'):
            self.verify(installed=True)
        path.symlink_to(self.payload / subject.SOURCE_NAMES['code'])
        with self.assertRaisesRegex(ValueError, 'regular payload'):
            self.verify(installed=True)

    def test_duplicate_json_keys(self):
        path = self.payload / 'ram-payload.json'
        path.write_text('{"native_abi": 2, "native_abi": 3}')
        with self.assertRaisesRegex(ValueError, 'duplicate JSON key'):
            self.verify()

    def test_cli_rejects_unpinned_input_even_with_optimization(self):
        for mode, directory in (('--payload-dir', self.payload), ('--installed-dir', self.installed)):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-B', '-O', subject.__file__,
                                         mode, str(directory)], text=True, capture_output=True)
                self.assertEqual(result.returncode, 1)
                self.assertIn('PON payload verification failed:', result.stderr)
                self.assertNotIn('Traceback', result.stderr)
                self.assertEqual(result.stdout, '')

    def test_install_rejects_conflicting_profiles_before_files(self):
        makefile = (subject.PACKAGE / 'Makefile').read_text()
        block = re.search(r'(?ms)^define Package/hg5585f-ct-npu-pon-full-firmware/install\n'
                          r'(.*?)^endef$', makefile)
        self.assertIsNotNone(block)
        harness = f'CURDIR := {self.package}\nTOPDIR := {subject.PACKAGE.parents[2]}\n'
        harness += 'stage:\n' + block[1]
        for package in ('rebuilt', 'full-test'):
            for selection in ('y', 'm'):
                with self.subTest(package=package, selection=selection):
                    result = subprocess.run(
                        ['make', '-f', '-', 'stage',
                         f'CONFIG_PACKAGE_hg5585f-ct-npu-{package}-firmware={selection}'],
                        input=harness, cwd=self.root, text=True, capture_output=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn('PON full firmware conflicts', result.stderr)
                    self.assertNotIn('PON payload verification failed', result.stderr)


if __name__ == '__main__':
    unittest.main()
