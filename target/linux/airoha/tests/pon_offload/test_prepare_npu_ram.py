#!/usr/bin/env python3
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import prepare_npu_ram as subject
from pack_npu_ram import select_profile, verified_kernel


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

    def production_source(self):
        digest = ', '.join('0x' + subject.sha256(b'new RV32')[index:index + 2]
                           for index in range(0, 64, 2))
        return (self.loader.replace('0x18000, lab_sha256[0]', '0x18000, pon ? pon_sha256 : lab_sha256[0]') +
                'static const u8 pon_sha256[SHA256_DIGEST_SIZE] = {\n' + digest + '\n\t};\n' +
                '\n'.join('airoha/hg5585f-ct/' + name for name in subject.INSTALLED_NAMES.values()))

    def test_production_archive_and_unchanged_loader(self):
        (self.payload / 'ram-payload.json').write_text(json.dumps(self.manifest))
        source = self.production_source()
        with patch.object(subject, 'verify_pon_payload') as verify:
            loader, archive, report = subject.prepare(self.payload, self.acceptance,
                                                      self.archive, source, 'production-session')
            verify.assert_called_once_with(self.payload)
        entries, _ = subject.archive_entries(archive)
        self.assertEqual(loader, source)
        self.assertEqual([entry[0] for entry in entries[:2]],
                         [subject.FIRMWARE + name for name in subject.INSTALLED_NAMES.values()])
        self.assertEqual(entries[0][2], b'new RV32')
        self.assertEqual(entries[2], subject.archive_entries(self.archive)[0][2])
        self.assertEqual(report['profile'], 'production-session')
        with patch.object(subject, 'verify_pon_payload', side_effect=ValueError('package pin')):
            with self.assertRaisesRegex(ValueError, 'package pin'):
                subject.prepare(self.payload, self.acceptance, self.archive, source, 'production-session')

    def test_production_loader_rejects_wrong_digest_or_missing_profile(self):
        source = self.production_source()
        for invalid in (source + source, source.replace('pon_sha256', 'wrong_sha256'),
                        source.replace('npu_pon_full_data.bin', 'wrong.bin'),
                        source.replace('0x18000', '0x20000')):
            with self.subTest(source=invalid[-80:]), self.assertRaises(ValueError):
                subject.production_loader(invalid, [b'new RV32', bytes(4)])
        with self.assertRaisesRegex(ValueError, 'digest mismatch'):
            subject.production_loader(source, [b'other RV32', bytes(4)])

    def test_production_archive_rejects_destination_collision(self):
        (self.payload / 'ram-payload.json').write_text(json.dumps(self.manifest))
        entries = self.entries + [(subject.FIRMWARE + subject.INSTALLED_NAMES['code'],
                                   self.entries[0][1], b'existing')]
        with patch.object(subject, 'verify_pon_payload'), self.assertRaisesRegex(ValueError, 'already contains'):
            subject.prepare(self.payload, self.acceptance, subject.encode_archive(entries, self.trailer),
                            self.production_source(), 'production-session')

    def test_module_replacement_checks_architecture_and_release(self):
        directory = self.payload / 'modules'
        directory.mkdir()
        name = 'lib/modules/6.18.60/nf_flow_table.ko'
        original = b'\x7fELF\x02\x01' + bytes(12) + b'\xb7\0' + b'vermagic=6.18.60 SMP\0'
        path = directory / 'nf_flow_table.ko'
        entries = [(name, self.entries[0][1], b'old module')]
        path.write_bytes(original)
        self.assertEqual(subject.module_replacements(directory, entries), {name: original})
        for invalid in (original.replace(b'6.18.60', b'6.18.59'), original.replace(b'\xb7\0', b'\x3e\0'),
                        b'not ELF'):
            path.write_bytes(invalid)
            with self.assertRaises(ValueError):
                subject.module_replacements(directory, entries)
        path.write_bytes(original)
        with self.assertRaises(ValueError):
            subject.module_replacements(directory, [])
        with self.assertRaises(ValueError):
            subject.module_replacements(directory, entries + entries)


class ProfileTests(unittest.TestCase):
    def test_production_profile_removes_lab_and_diagnostic(self):
        for diagnostic in (False, True):
            npu = {'airoha,connac2-rebuilt-ram-lab': b'', 'untouched': b'NPU'}
            eth = {'airoha,connac2-ram-native-pairs': b'', 'untouched': b'ETH'}
            if diagnostic:
                eth['airoha,connac2-pon-er-diagnostic'] = b''
            select_profile(npu, eth, 'production-session')
            self.assertEqual(npu, {'airoha,connac2-pon-full': b'', 'untouched': b'NPU'})
            self.assertEqual(eth, {'airoha,connac2-pon-full': b'', 'untouched': b'ETH'})

    def test_reject_mixed_profile(self):
        for target in ('npu', 'eth'):
            for marker in ('airoha,connac2-ordinary-full-test', 'airoha,connac2-pon-full'):
                npu = {'airoha,connac2-rebuilt-ram-lab': b''}
                eth = {'airoha,connac2-ram-native-pairs': b''}
                (npu if target == 'npu' else eth)[marker] = b''
                with self.subTest(target=target, marker=marker), self.assertRaises(ValueError):
                    select_profile(npu, eth, 'production-session')

    def test_diagnostic_default_and_repeat_rejection(self):
        npu = {'airoha,connac2-rebuilt-ram-lab': b''}
        eth = {'airoha,connac2-ram-native-pairs': b''}
        select_profile(npu, eth, 'diagnostic')
        self.assertIn('airoha,connac2-rebuilt-ram-lab', npu)
        self.assertIn('airoha,connac2-ram-native-pairs', eth)
        self.assertIn('airoha,connac2-pon-er-diagnostic', eth)
        with self.assertRaises(ValueError):
            select_profile(npu, eth, 'diagnostic')


if __name__ == '__main__':
    unittest.main()
