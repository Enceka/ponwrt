import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


HERE = Path(__file__).resolve().parent
PROFILES = ((), ('--connac2',), ('--connac2', '--connac2-rx'))


class RamGdm2Test(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.factory = Path(temp.name) / 'factory'
        self.dtb = Path(temp.name) / 'trial.dtb'
        self.data = bytearray(1 << 20)
        self.data[0x1000:0x1002] = bytes.fromhex('1679')
        self.data[0x2000:0x2006] = bytes.fromhex('0011223344ff')

    def generate(self, *options):
        self.factory.write_bytes(self.data)
        return subprocess.check_output([sys.executable, HERE / 'ram-dts.py', self.factory,
                                        hashlib.sha256(self.data).hexdigest(), *options])

    def compile(self, *options, phandles=()):
        source = subprocess.check_output([os.environ.get('CPP', 'cpp'),
                                          '-nostdinc', '-undef', '-P', '-x', 'assembler-with-cpp',
                                          '-I', HERE.parent / 'dts', '-I', os.environ['LINUX_INCLUDE'], '-'],
                                         input=self.generate(*options))
        source += b''.join(f'&{{{node}}} {{ phandle = <0x{value}>; }};\n'.encode()
                           for node, value in phandles)
        subprocess.run([os.environ.get('DTC', 'dtc'), '-q', '-@', '-I', 'dts', '-O', 'dtb',
                        '-o', self.dtb, '-'], input=source, check=True)

    def get(self, *args):
        return subprocess.check_output([os.environ.get('FDTGET', 'fdtget'),
                                        *args[:1], self.dtb, *args[1:]], text=True).strip()

    def node(self, label):
        return self.get('-ts', '/__symbols__', label)

    def snapshot(self, node='/'):
        properties = {name: self.get('-tx', node, name)
                      for name in self.get('-p', node).splitlines()}
        nodes = {node: properties}
        for child in self.get('-l', node).splitlines():
            nodes.update(self.snapshot(node.rstrip('/') + '/' + child))
        return nodes

    def test_default_output(self):
        digests = (
            '93ab678db680fc0da9a5b766257f4fa2419c71bdbe2be1ec13f83788c4ecc731',
            '1502dac7a09c5f88d5621c703ccd2245142d6bf386b27c638ab0e4f701aeb762',
            'efc0266ede00323ff6bd88249107bfa3f285feb563f7657bf967aef1bb352766',
        )
        for options, digest in zip(PROFILES, digests):
            with self.subTest(options=options):
                self.assertEqual(hashlib.sha256(self.generate(*options)).hexdigest(), digest)
                self.compile(*options)
                for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'pon_pcs', 'hg5585f_bosa', 'gdm2'):
                    self.assertEqual(self.get('-ts', self.node(label), 'status'), 'disabled', label)
                self.assertNotIn('ram-tx-disable-hog',
                                 self.get('-l', self.node('en7581_pinctrl')).splitlines())

    def test_enum(self):
        for options in PROFILES:
            with self.subTest(options=options):
                self.compile('--gdm2-enum', *options)
                for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'pon_pcs', 'hg5585f_bosa'):
                    self.assertEqual(self.get('-ts', self.node(label), 'status'), 'disabled', label)
                self.assertNotIn('bootargs-append', self.get('-p', '/chosen').splitlines())
                gdm2 = self.node('gdm2')
                self.assertEqual(self.get('-ts', gdm2, 'status'), 'okay')
                props = self.get('-p', gdm2).splitlines()
                self.assertIn('airoha,pon-data-path', props)
                self.assertEqual(self.get('-tu', gdm2, 'reg'), '2')
                self.assertFalse({'nvmem-cells', 'nvmem-cell-names'} & set(props))
                pinctrl = self.node('en7581_pinctrl')
                hog = pinctrl + '/ram-tx-disable-hog'
                bosa_gate = self.get('-tu', self.node('hg5585f_bosa'), 'tx-disable-gpios').split()
                self.assertEqual(bosa_gate, [self.get('-tu', pinctrl, 'phandle'), '38', '0'])
                self.assertEqual(self.get('-tu', hog, 'gpios').split(), bosa_gate[1:])
                props = set(self.get('-p', hog).splitlines())
                self.assertTrue({'gpio-hog', 'output-high'} <= props)
                self.assertFalse({'input', 'output-low'} & props)
                self.assertEqual(self.get('-ts', hog, 'line-name'), 'ram-pon-tx-disable')

    def test_enum_mac_addresses(self):
        for base in ('0011223344ff', '02112233447f', '020000000080',
                     '02fffffffffe', 'fefffffffffe', '000000000001'):
            with self.subTest(base=base):
                self.data[0x2000:0x2006] = bytes.fromhex(base)
                self.compile('--gdm2-enum')
                addresses = [bytes(map(int, self.get('-tbu', self.node(label), 'local-mac-address').split()))
                             for label in ('gdm4', 'gdm1', 'gdm2')]
                self.assertEqual(addresses[0], bytes.fromhex(base))
                self.assertEqual(int.from_bytes(addresses[1], 'big'), int(base, 16) + 1)
                self.assertEqual(len(addresses[2]), 6)
                self.assertEqual(addresses[2][0] & 3, 2)
                self.assertEqual(len(set(addresses)), 3)

    def test_enum_dtb_changes_only_gdm2_and_tx_disable(self):
        for options in PROFILES:
            with self.subTest(options=options):
                self.compile(*options)
                baseline = self.snapshot()
                gdm2 = self.node('gdm2')
                hog = self.node('en7581_pinctrl') + '/ram-tx-disable-hog'
                phandles = [(node, props['phandle']) for node, props in baseline.items()
                            if 'phandle' in props]
                self.compile('--gdm2-enum', *options, phandles=phandles)
                enumerated = self.snapshot()
                self.assertEqual(set(enumerated) - set(baseline), {hog})
                self.assertEqual(set(baseline) - set(enumerated), set())
                enumerated.pop(hog)
                baseline_gdm2 = baseline.pop(gdm2)
                enumerated_gdm2 = enumerated.pop(gdm2)
                self.assertEqual(baseline, enumerated)
                for name in ('status', 'nvmem-cells', 'nvmem-cell-names'):
                    baseline_gdm2.pop(name)
                for name in ('status', 'local-mac-address'):
                    enumerated_gdm2.pop(name)
                self.assertEqual(baseline_gdm2, enumerated_gdm2)

    def test_enum_preserves_input_guards(self):
        for fault in ('digest', 'size', 'eeprom', 'zero-mac', 'multicast',
                      'native-without-wed', 'rx-without-connac2', 'ppe-without-rx'):
            with self.subTest(fault=fault):
                self.data[0x1000] = 0 if fault == 'eeprom' else 0x16
                self.data[0x2000:0x2006] = bytes(6) if fault == 'zero-mac' else bytes.fromhex('0011223344ff')
                self.data[0x2000] = 1 if fault == 'multicast' else 0
                payload = self.data[:-1] if fault == 'size' else self.data
                self.factory.write_bytes(payload)
                digest = '0' * 64 if fault == 'digest' else hashlib.sha256(payload).hexdigest()
                options = {
                    'native-without-wed': ['--native-pairs'],
                    'rx-without-connac2': ['--connac2-rx'],
                    'ppe-without-rx': ['--connac2-host-ppe'],
                }.get(fault, [])
                result = subprocess.run([sys.executable, HERE / 'ram-dts.py', self.factory, digest,
                                         '--gdm2-enum', *options], capture_output=True)
                self.assertEqual(result.returncode, 2)
                self.assertEqual(result.stdout, b'')
                self.assertIn(b'error:', result.stderr)


if __name__ == '__main__':
    unittest.main()
