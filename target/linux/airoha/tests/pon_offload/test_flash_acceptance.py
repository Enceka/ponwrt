"""Synthetic offline fixtures only; no release evidence is produced."""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from flash_acceptance import FW_DIR, MODES, check_acceptance


def digest(data):
    return hashlib.sha256(data).hexdigest()


def window(service, hits, received, cpu):
    return dict(service=service, tuple=['192.0.2.1', '192.0.2.2', 'udp', 1234, 5678],
                ingress={'qdma_msg1': (2 << 21) | 24} if cpu else {'fe_word6': 0x62},
                sent=3, foe_hits=hits, receiver_rx=received, wan_cpu_rx=cpu)


class GateTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.recovery = self.root / 'recovery'
        self.recovery.write_bytes(b'synthetic recovery fixture')
        self.fit = self.root / 'fit'
        self.fit.write_bytes(b'synthetic sysupgrade fixture')
        self.candidate = digest(self.fit.read_bytes())
        self.pair_path = self.root / 'verified-pair.json'
        self.record_path = self.root / 'run.json'
        fw = {f'npu_full_test_{part}.bin': digest(part.encode()) for part in ('rv32', 'data')}
        self.run_data = dict(board='fiberhome,hg5585f-ct', mode=MODES[0],
                             boot_id='11111111-1111-4111-a111-111111111111',
                             sources={'source_commit': 'a' * 40}, firmware=fw,
                             boot_fit_sha256=digest(self.recovery.read_bytes()), sysupgrade_sha256=self.candidate,
                             services=[1, 257, 513], foe_row=10, ppe_bank=1,
                             bound=dict(ppe_bank=1, bound_rows=[10], windows=[window(1, 3, [3, 0], 0),
                                        window(257, 0, [0, 3], 3), window(513, 0, [0, 0], 3)]),
                             withdraw_a=dict(ppe_bank=1, bound_rows=[], windows=[window(1, 0, [3, 0], 3),
                                        window(257, 0, [0, 3], 3), window(513, 0, [0, 0], 3)]))
        pair = dict(recovery_sha256=self.run_data['boot_fit_sha256'], sysupgrade_sha256=self.candidate,
                    sources=self.run_data['sources'], firmware={FW_DIR + key: val for key, val in fw.items()})
        self.pair_path.write_text(json.dumps(pair))

    def check(self, record):
        self.record_path.write_text(json.dumps(record))
        return check_acceptance(self.pair_path, self.record_path, self.recovery, self.candidate)

    def test_both_bench_paths(self):
        for mode in MODES:
            self.assertEqual(self.check(dict(self.run_data, mode=mode)), mode)

    def test_insufficient_evidence(self):
        for record in [{'passed': True}, dict(self.run_data, mode='lan1'),
                       dict(self.run_data, services=[1, 257, 1]), dict(self.run_data, services=[0, 257, 513]),
                       dict(self.run_data, sources={}), dict(self.run_data, firmware={}),
                       dict(self.run_data, boot_fit_sha256='b' * 64), dict(self.run_data, sysupgrade_sha256='b' * 64)]:
            with self.subTest(keys=list(record)), self.assertRaises(ValueError):
                self.check(record)

    def test_wrong_measurements(self):
        for phase, index, key, bad in [
                ('bound', 1, 'tuple', ['192.0.2.1', '192.0.2.2', 'udp', 1234, 9999]),
                ('bound', 1, 'service', 1), ('bound', 1, 'sent', 0),
                ('bound', 0, 'foe_hits', 0), ('bound', 1, 'foe_hits', 3), ('bound', 1, 'wan_cpu_rx', 0),
                ('bound', 0, 'receiver_rx', [3, 1]), ('bound', 1, 'receiver_rx', [0, 0]),
                ('bound', 2, 'foe_hits', 1), ('bound', 2, 'receiver_rx', [1, 0]),
                ('withdraw_a', 2, 'wan_cpu_rx', 0), ('withdraw_a', 2, 'receiver_rx', [0, 1]),
                ('withdraw_a', 0, 'foe_hits', 1), ('withdraw_a', 0, 'wan_cpu_rx', 0),
                ('withdraw_a', 0, 'receiver_rx', [0, 0]), ('withdraw_a', 1, 'foe_hits', 3)]:
            with self.subTest(phase=phase, field=key, value=bad):
                with patch.dict(self.run_data[phase]['windows'][index], {key: bad}), self.assertRaises(ValueError):
                    self.check(self.run_data)

    def test_exclusive_bank_and_control(self):
        for row, bank in ((0, 0), (8192, 1), (-1, 1), (0, True)):
            with self.subTest(row=row, bank=bank), self.assertRaisesRegex(ValueError, 'bank-local'):
                self.check(dict(self.run_data, foe_row=row, ppe_bank=bank))
        for phase, fields in [('bound', {'bound_rows': [10, 11]}), ('withdraw_a', {'bound_rows': [10]}),
                              ('withdraw_a', {'ppe_bank': 0}),
                              ('bound', {'windows': self.run_data['bound']['windows'][:2]})]:
            with self.subTest(phase=phase, fields=fields):
                with patch.dict(self.run_data[phase], fields), self.assertRaises(ValueError):
                    self.check(self.run_data)

    def test_measured_sport(self):
        for phase in ('bound', 'withdraw_a'):
            for sample in self.run_data[phase]['windows']:
                for invalid in ({}, {'sport': 2}, {'fe_word6': 24}, {'qdma_msg1': (24 << 21) | 2},
                                {'fe_word6': (1 << 32) | 2}):
                    with self.subTest(phase=phase, service=sample['service'], descriptor=invalid):
                        with patch.dict(sample, ingress=invalid), self.assertRaisesRegex(ValueError, 'descriptor|SPORT'):
                            self.check(self.run_data)

    def test_artifact_drift(self):
        name = 'npu_full_test_rv32.bin'
        with patch.dict(self.run_data['firmware'], {name: 'b' * 64}), self.assertRaises(ValueError):
            self.check(self.run_data)
        with patch.dict(self.run_data['sources'], source_commit='b' * 40), self.assertRaises(ValueError):
            self.check(self.run_data)
        self.recovery.write_bytes(b'different recovery')
        with self.assertRaisesRegex(ValueError, 'tested recovery'):
            self.check(self.run_data)

    @unittest.skipUnless(os.environ.get('FLASH_TRANSACTION'), 'set FLASH_TRANSACTION to test the private CLI')
    def test_cli_rejects_before_device(self):
        spec = importlib.util.spec_from_file_location('transaction_under_test', os.environ['FLASH_TRANSACTION'])
        tx = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(tx)
        with patch.dict(self.run_data['bound']['windows'][0], ingress={'fe_word6': 24}):
            self.record_path.write_text(json.dumps(self.run_data))
        base = ['--fit', str(self.fit), '--sha256', self.candidate, '--backup', str(self.root),
                '--recovery', str(self.recovery), '--pon-record', str(self.record_path)]
        for mode in ('plan', 'install'):
            args = base if mode == 'plan' else base + ['--pin', str(self.fit), '--journal', str(self.root/'journal')]
            with self.subTest(mode=mode), contextlib.ExitStack() as stack:
                def mock(*args, **kwargs):
                    return stack.enter_context(patch.object(*args, **kwargs))
                mock(sys, 'argv', ['flash_transaction.py', mode] + args)
                mock(tx, 'D', self.root)
                stack.enter_context(patch('ct243_verify_full.verify', return_value={
                    'sha256': self.candidate, 'bytes': self.fit.stat().st_size}))
                backup = mock(tx, 'read_backup')
                config = mock(tx, 'config')
                device = mock(tx.live, 'Device')
                stderr = stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
                with self.assertRaises(SystemExit) as exit_status:
                    tx.main()
                self.assertEqual(exit_status.exception.code, 2)
                self.assertIn('expected GDM2 SPORT 2', stderr.getvalue())
                backup.assert_not_called()
                config.assert_not_called()
                device.assert_not_called()


if __name__ == '__main__':
    unittest.main()
