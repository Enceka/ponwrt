#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile
import unittest

import prepare_npu_ram as subject
from pack_npu_ram import verified_kernel


class PreparationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.payload = Path(self.directory.name)
        self.manifest = dict(native_abi=3, native_caps=63, ct_bridge_guard_profile=2,
                             ct_tdma_bank_profile=2, ct_short_pad=True, ct_native_pairs=True,
                             ct_fe_native=True, features={name: True for name in subject.FEATURES},
                             local_sram=dict(bss_end='0x3e9037c4', remaining_bytes=4))
        self.manifest['features']['eth_return_dma'] = False
        for section, name, blob in [('elf', 'lab.elf', b'ELF fixture'),
                                    ('code', 'ram-npu_rv32.bin', b'new RV32'),
                                    ('data', 'ram-npu_data.bin', bytes(4))]:
            (self.payload / name).write_bytes(blob)
            self.manifest[section] = dict(name=name, bytes=len(blob), sha256=subject.sha256(blob))
        self.manifest['code']['npu_address'] = '0x84000000'
        self.manifest['data'].update(npu_address='0x3e900000', host_address='0x1e900000')
        self.acceptance = dict(passed=True, elf_sha256=self.manifest['elf']['sha256'])
        fields = [10, 0o100644, 0, 0, 1, 123456, 0, 0, 0, 0, 0, 0, 0]
        self.entries = [(subject.FIRMWARE + subject.NAMES[0], fields, b'old RV32'),
                        (subject.FIRMWARE + subject.NAMES[1], fields, bytes(4)),
                        ('etc/config/network', fields, b'preserved network')]
        self.trailer = [0] * 13
        self.archive = subject.encode_archive(self.entries, self.trailer)
        rows = ['{ ' + ', '.join('0x' + subject.sha256(blob)[index:index + 2]
                for index in range(0, 64, 2)) + ' },' for blob in (b'old RV32', bytes(4))]
        self.loader = ('static const u8 lab_sha256[][SHA256_DIGEST_SIZE] = {\n' +
                       '\n'.join(rows) + '\n\t};\n' +
                       '0x18000, lab_sha256[0], false)\n4, lab_sha256[1], false)\n')

    def prepare(self):
        (self.payload / 'ram-payload.json').write_text(json.dumps(self.manifest))
        return subject.prepare(self.payload, self.acceptance, self.archive, self.loader)

    def test_payload_and_metadata(self):
        loader, archive, report = self.prepare()
        entries, _ = subject.archive_entries(archive)
        self.assertEqual(entries[2][2], b'preserved network')
        self.assertEqual(entries[2][1][:6], self.entries[2][1][:6])
        self.assertEqual(entries[0][2], b'new RV32')
        self.assertEqual(report['changed_entries'], [subject.FIRMWARE + subject.NAMES[0]])
        self.assertNotEqual(loader, self.loader)
        self.assertEqual(len(archive) % 512, 0)
        self.loader, self.archive = loader, archive
        self.assertEqual(self.prepare()[2]['changed_entries'], [])

    def test_kernel_transfer_truncation(self):
        original = b'kernel-with-complete-initramfs' + bytes(59400)
        expected = subject.sha256(original)
        kernel = self.payload / 'Image'
        kernel.write_bytes(original)
        self.assertEqual(verified_kernel(kernel, expected), original)
        kernel.write_bytes(original[:-59400])
        with self.assertRaisesRegex(ValueError, 'transfer identity'):
            verified_kernel(kernel, expected)

    def test_mismatched_acceptance(self):
        for field, value in [('passed', False), ('elf_sha256', '0' * 64)]:
            with self.subTest(field=field):
                original = self.acceptance.copy()
                self.acceptance[field] = value
                with self.assertRaises(ValueError):
                    self.prepare()
                self.acceptance = original

    def test_corrupt_payloads(self):
        for name in ('lab.elf', 'ram-npu_rv32.bin', 'ram-npu_data.bin'):
            with self.subTest(name=name):
                path = self.payload / name
                original = path.read_bytes()
                path.write_bytes(original + b'bad')
                with self.assertRaises(ValueError):
                    self.prepare()
                path.write_bytes(original)

    def test_profile_and_bounds(self):
        for section, field, value in [('features', 'fe_pon_auth', False),
                                      ('features', 'eth_return_dma', True),
                                      ('local_sram', 'bss_end', '0x3e9037cc'),
                                      ('local_sram', 'remaining_bytes', 8),
                                      ('code', 'name', '../outside'),
                                      ('data', 'host_address', '0x1e900004')]:
            with self.subTest(field=field):
                original = copy.deepcopy(self.manifest)
                self.manifest[section][field] = value
                with self.assertRaises(ValueError):
                    self.prepare()
                self.manifest = original

    def test_loader_identity(self):
        original = self.loader
        for invalid in (original + original, original.replace('0x18000', '0x20000'),
                        original.replace('0x', '0xff, 0x', 1)):
            with self.subTest(loader=invalid[:60]):
                self.loader = invalid
                with self.assertRaises(ValueError):
                    self.prepare()

    def test_bad_archive(self):
        variants = [self.archive[:115], self.archive + b'x',
                    subject.encode_archive(self.entries + [self.entries[0]], self.trailer),
                    subject.encode_archive([('../outside', self.entries[0][1], b'')], self.trailer)]
        for archive in variants:
            with self.subTest(length=len(archive)), self.assertRaises(ValueError):
                subject.archive_entries(archive)

    def test_linked_or_missing_firmware(self):
        original = copy.deepcopy(self.entries)
        for mode, links in [(0o120777, 1), (0o100644, 2)]:
            entries = copy.deepcopy(original)
            entries[0][1][1], entries[0][1][4] = mode, links
            self.archive = subject.encode_archive(entries, self.trailer)
            with self.assertRaises(ValueError):
                self.prepare()
        self.archive = subject.encode_archive(original[1:], self.trailer)
        with self.assertRaises(ValueError):
            self.prepare()


if __name__ == '__main__':
    unittest.main()
