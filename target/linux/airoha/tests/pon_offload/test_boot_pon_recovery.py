import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

import boot_pon_recovery as boot


class RecoveryPreflightTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.fit = self.root / 'recovery.itb'
        self.fit.write_bytes(b'recovery fixture')
        self.evidence = self.root / 'verified-pair.json'
        self.report = dict(passed=True, profile='pon-full', recovery=dict(
            sha256=hashlib.sha256(self.fit.read_bytes()).hexdigest(),
            bytes=self.fit.stat().st_size, resident_checks=[dict(ok=True)]))
        self.write_report()
        self.key = self.root / 'key'
        self.pin = self.root / 'known-hosts'
        for path in (self.key, self.pin, self.root / 'live.py'):
            path.touch()
        self.args = SimpleNamespace(
            board_ip='192.168.1.1', host_ip='192.168.1.120', interface='en6',
            transfer_board_ip='192.168.6.221', transfer_host_ip='192.168.6.231',
            transfer_interface='en4', previous_boot='62ec95be-2dab-4038-8757-1e2f19af5fe6',
            key=self.key, pin=self.pin, serial=Path('/dev/cu.test'), tftp_port=1069,
            toolkit=self.root, output=self.root / 'output')

    def write_report(self):
        self.evidence.write_text(json.dumps(self.report))

    def test_verified_image_and_config(self):
        data, digest = boot.preflight(self.fit, self.evidence)
        self.assertEqual(data, self.fit.read_bytes())
        self.assertEqual(digest, self.report['recovery']['sha256'])
        control, transfer = boot.config(self.args)
        self.assertEqual(control['host'], '192.168.1.1')
        self.assertEqual(transfer['host'], '192.168.6.221')
        self.assertFalse(self.args.output.exists())

    def test_changed_image(self):
        self.fit.write_bytes(b'changed image')
        with self.assertRaisesRegex(ValueError, 'differs'):
            boot.preflight(self.fit, self.evidence)

    def test_rejected_evidence(self):
        for field, value in (('passed', False), ('profile', 'ordinary-full')):
            with self.subTest(field=field):
                original = self.report[field]
                self.report[field] = value
                self.write_report()
                with self.assertRaisesRegex(ValueError, 'passing PON'):
                    boot.preflight(self.fit, self.evidence)
                self.report[field] = original
        for checks in ([], [dict(ok=False)], [dict(ok=True), dict(ok=False)]):
            with self.subTest(checks=checks):
                self.report['recovery']['resident_checks'] = checks
                self.write_report()
                with self.assertRaisesRegex(ValueError, 'incomplete'):
                    boot.preflight(self.fit, self.evidence)

    def test_unsafe_filename(self):
        for name in ('recovery;reset.itb', '-recovery.itb', 'recovery.bin'):
            with self.subTest(name=name):
                path = self.root / name
                path.write_bytes(self.fit.read_bytes())
                with self.assertRaisesRegex(ValueError, 'filename'):
                    boot.preflight(path, self.evidence)

    def test_invalid_config(self):
        for field, value in (
            ('board_ip', '::1'), ('interface', 'en6;reboot'),
            ('previous_boot', 'invalid'), ('key', self.root / 'missing'),
            ('serial', Path('/tmp/serial')), ('tftp_port', 69),
            ('transfer_board_ip', '192.168.6.231'),
            ('transfer_board_ip', '192.168.7.221'),
            ('output', self.root),
            ('output', Path(boot.__file__).resolve().parent / 'uncreated'),
            ('toolkit', self.root / 'missing-toolkit'),
        ):
            with self.subTest(field=field, value=value):
                original = getattr(self.args, field)
                setattr(self.args, field, value)
                with self.assertRaises(ValueError):
                    boot.config(self.args)
                setattr(self.args, field, original)

    def test_symlink_output_inside_repository(self):
        link = self.root / 'repository'
        link.symlink_to(Path(boot.__file__).resolve().parent)
        self.args.output = link / 'uncreated'
        with self.assertRaisesRegex(ValueError, 'outside ponwrt'):
            boot.config(self.args)


class SSHReadinessTests(unittest.TestCase):
    def test_bounded_retry(self):
        live = SimpleNamespace(LiveError=RuntimeError)
        device = mock.Mock()
        device.run.side_effect = [RuntimeError('starting'),
                                  subprocess.TimeoutExpired('ssh', 5), b'PON_SSH_READY']
        with mock.patch.object(boot.time, 'sleep') as sleep:
            boot.wait_ssh(device, live)
        self.assertEqual(device.run.call_count, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_expired_retry(self):
        device = mock.Mock()
        device.run.side_effect = RuntimeError('unreachable')
        with mock.patch.object(boot.time, 'monotonic', side_effect=[0, 31]), \
                mock.patch.object(boot.time, 'sleep') as sleep:
            with self.assertRaisesRegex(RuntimeError, 'unreachable'):
                boot.wait_ssh(device, SimpleNamespace(LiveError=RuntimeError))
        sleep.assert_not_called()

    def test_wrong_reply_is_not_retried(self):
        device = mock.Mock()
        device.run.return_value = b'wrong board'
        with self.assertRaisesRegex(ValueError, 'unexpected SSH'):
            boot.wait_ssh(device, SimpleNamespace(LiveError=RuntimeError))
        device.run.assert_called_once()


if __name__ == '__main__':
    unittest.main()
