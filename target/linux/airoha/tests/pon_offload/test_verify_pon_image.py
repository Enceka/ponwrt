#!/usr/bin/env python3
import copy
import gzip
import json
import lzma
from pathlib import Path
import stat
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from prepare_npu_ram import encode_archive
import verify_pon_image as subject


RESIDENT = subject.module('pon_image_test_resident',
                          Path(__file__).resolve().parent.parent / 'npu_resident_config/verify.py')
FIRMWARE = 'lib/firmware/airoha/hg5585f-ct/'
NETWORK = 'etc/board.d/02_network'
METADATA = 'etc/hg5585f-ct-build.json'


def cells(*values):
    return struct.pack('>' + 'I' * len(values), *values)


def strings(*values):
    return b''.join(value.encode() + b'\0' for value in values)


class Node:
    def __init__(self, name, properties=None, children=()):
        self.name = name
        self.properties = properties or {}
        self.children = list(children)

    def child(self, name):
        for child in self.children:
            if child.name == name:
                return child
        raise ValueError('missing FIT/DT node: ' + name)


def flatten(root):
    names = bytearray()
    structure = bytearray()

    def write(node):
        structure.extend(cells(1) + node.name.encode() + b'\0')
        structure.extend(bytes(-len(structure) % 4))
        for name, value in node.properties.items():
            offset = len(names)
            names.extend(name.encode() + b'\0')
            structure.extend(cells(3, len(value), offset) + value)
            structure.extend(bytes(-len(structure) % 4))
        for child in node.children:
            write(child)
        structure.extend(cells(2))

    write(root)
    structure.extend(cells(9))
    header = cells(0xd00dfeed, 56 + len(structure) + len(names), 56,
                   56 + len(structure), 40, 17, 16, 0, len(names), len(structure))
    return header + bytes(16) + structure + names


def device_tree():
    root = Node('', {'compatible': strings('fiberhome,hg5585f-ct', 'airoha,an7581', 'airoha,en7581'),
                     '#address-cells': cells(2), '#size-cells': cells(2), 'variant': strings('pon-full')})
    soc = Node('soc', {'compatible': strings('simple-bus'), '#address-cells': cells(2),
                       '#size-cells': cells(2), 'ranges': b''})
    reserved = Node('reserved-memory', {'#address-cells': cells(2), '#size-cells': cells(2), 'ranges': b''})
    root.children.extend([soc, reserved])
    devices = {}
    for label, path in (('eth', RESIDENT.ETH), ('npu', RESIDENT.NPU),
                        ('scu', RESIDENT.SCU), ('chip', RESIDENT.CHIP_SCU)):
        compatible, registers = RESIDENT.DEVICES[path]
        devices[label] = Node(path.rsplit('/', 1)[-1],
                              {'compatible': strings(*compatible), 'reg': cells(*registers),
                               'phandle': cells(len(devices) + 1)})
        soc.children.append(devices[label])
    devices['eth'].properties.update({'airoha,npu': cells(2), 'airoha,connac2-pon-full': b'',
                                     'resets': cells(3, 0, 3, 1, 3, 2),
                                     'reset-names': strings('fe', 'pdma', 'qdma')})
    devices['scu'].properties.update({'#clock-cells': cells(1), '#reset-cells': cells(1),
                                     'airoha,chip-scu': cells(4)})
    devices['npu'].properties.update({'airoha,connac2-pon-full': b'', 'memory-region': cells(10, 11, 12, 13),
                                     'memory-region-names': strings('binary', 'ba', 'connac2-pkt', 'connac2-host-rx')})
    for index, (address, size) in enumerate(((0x84000000, 0xa00000), (0x92980000, 0x80000),
                                           (0x92a00000, 0x600000), (0x93000000, 0x380000))):
        reserved.children.append(Node('pool@' + hex(address)[2:],
                                      {'reg': struct.pack('>QQ', address, size), 'no-map': b'',
                                       'phandle': cells(10 + index)}))
    for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'hg5585f_bosa', 'gdm2', 'pon_pcs'):
        devices[label] = Node(label, {'status': strings('okay')})
        soc.children.append(devices[label])
    devices['gdm2'].properties['phandle'] = cells(20)
    devices['xpon_mac'].properties.update({'data-path': cells(20), 'nvmem-cells': cells(30)})
    devices['hg5585f_bosa'].properties['nvmem-cells'] = cells(30)
    root.children.append(Node('__symbols__', {label: strings('/soc/' + node.name)
                                              for label, node in devices.items()}))
    root.children.extend([Node('bl2', {'label': strings('bl2'), 'reg': cells(0, 131072)}),
                          Node('ubi', {'label': strings('ubi'), 'reg': cells(131072, 0)}),
                          Node('fit-volume', {'volname': strings('fit')}),
                          Node('factory-volume', {'volname': strings('factory')})])
    return root, devices


class ImageTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='pon-image-tests-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.package = self.root / 'repo/package/firmware/hg5585f-ct-npu-firmware'
        self.package.mkdir(parents=True)
        board = self.package.parents[2] / 'target/linux/airoha/an7581/base-files' / NETWORK
        board.parent.mkdir(parents=True)
        board.write_bytes(b'board network generator\n')
        self.blobs = {name: ('fixture:' + name).encode() for name in
                      ('npu_rv32.bin', 'npu_data.bin', 'npu_pon_full_rv32.bin', 'npu_pon_full_data.bin')}
        for manifest, names in [('SHA256SUMS', ('npu_rv32.bin', 'npu_data.bin')),
                                ('SHA256SUMS.pon-full', ('npu_pon_full_rv32.bin', 'npu_pon_full_data.bin'))]:
            (self.package / manifest).write_text(''.join(subject.sha256(self.blobs[name]) + '  ' + name + '\n'
                                                        for name in names))
        self.identity = {'manifest': {kind: {'sha256': subject.sha256(self.blobs[name])}
                                     for kind, name in [('code', 'npu_pon_full_rv32.bin'),
                                                        ('data', 'npu_pon_full_data.bin')]}}
        self.provenance = {'schema': 1, 'profile': 'hg5585f-ct-pon-full',
                           'board': 'fiberhome,hg5585f-ct', 'pon_production_admission': False,
                           'firmware': self.identity['manifest']['code']['sha256'],
                           'sources': {'ponwrt': {'commit': 'fixture-revision', 'tracked_dirty': False}}}
        self.files = {FIRMWARE + name: blob for name, blob in self.blobs.items()}
        self.files.update({NETWORK: board.read_bytes(), METADATA: json.dumps(self.provenance).encode(),
                           'etc/config/network': b'', 'etc/config/wireless': b'wireless fixture',
                           'etc/dropbear/authorized_keys': b'fixture key',
                           'etc/modules.d/19-mt7916-ct-wed-prepare': b'prepare',
                           'etc/modules.d/mt7915e': b'mt7915e'})
        for name in ('airoha-xpon', 'mt7915e', 'ct_wed_platform', 'ct_wed_guard_v2', 'nf_flow_table'):
            self.files['lib/modules/6.18.60/' + name + '.ko'] = ('module ' + name).encode()
        self.modes = {}
        self.extra_entries = []
        self.rootfs_changes = {}
        self.rootfs_symlinks = {}
        self.archive_count = 1
        self.bad_archive = None
        self.omit_digests = set()
        self.hash_failure = False
        self.hash_checks = 0
        self.unsquashfs_failure = False
        self.dt, self.devices = device_tree()
        self.config = (Path(__file__).resolve().parent.parent /
                       'npu_resident_config/fixtures/resident.config').read_text()
        self.args = SimpleNamespace(**{name: self.root / name for name in
                                      ('recovery', 'sysupgrade', 'initramfs_archive', 'config',
                                       'source_manifest', 'image_helper', 'output')}, unsquashfs='fake-unsquashfs')
        self.args.source_manifest.write_text(json.dumps(self.provenance))
        self.args.image_helper.write_bytes(b'fake FIT parser fixture')
        self.fit_nodes = {}
        for kind in ('recovery', 'sysupgrade'):
            kernel = Node('kernel-1', {'compression': strings('lzma'),
                                      'load': cells(0x8a000000), 'entry': cells(0x8a000000)})
            fdt = Node('fdt-1')
            images = Node('images', children=[kernel, fdt])
            configuration = Node('conf-1', {'kernel': strings('kernel-1'), 'fdt': strings('fdt-1')})
            if kind == 'sysupgrade':
                images.children.append(Node('rootfs-1', {'type': strings('filesystem')}))
                configuration.properties['loadables'] = strings('rootfs-1')
            configurations = Node('configurations', {'default': strings('conf-1')}, [configuration])
            self.fit_nodes[kind] = Node('', children=[images, configurations])
            getattr(self.args, kind).write_bytes(kind.encode())
        self.raw_changes = {}
        self.other_dt = None
        self.squashfs = b'hsqs fixture'
        self.registry = {}
        self.image = SimpleNamespace(Fit=lambda content: self.registry[content],
                                     text=lambda value: value.removesuffix(b'\0').decode(),
                                     integer=lambda value: int.from_bytes(value, 'big'),
                                     verify_fit_hashes=self.check_hashes)
        self.addCleanup(patch.stopall)
        patch.object(subject, 'PACKAGE', self.package).start()
        patch.object(subject, 'load_identity', return_value=self.identity).start()
        patch.object(subject, 'module', side_effect=lambda name, path:
                     self.image if name == 'pon_image_helper' else RESIDENT).start()
        patch.object(subject.subprocess, 'run', side_effect=self.extract).start()

    def check_hashes(self, fit):
        self.hash_checks += 1
        subject.require(not self.hash_failure, 'FIT hash mismatch')

    def entry(self, name, payload):
        fields = [0] * 13
        fields[1] = self.modes.get(name, stat.S_IFREG | 0o644)
        fields[4] = 1
        return name, fields, payload

    def prepare(self):
        archive = self.bad_archive if self.bad_archive is not None else encode_archive(
            [self.entry(name, payload) for name, payload in self.files.items()] + self.extra_entries, [0] * 13)
        self.args.initramfs_archive.write_bytes(archive)
        self.args.config.write_text(self.config)
        dtb = flatten(self.dt)
        self.registry[dtb] = SimpleNamespace(root=self.dt)
        if self.other_dt:
            self.registry[flatten(self.other_dt)] = SimpleNamespace(root=self.other_dt)
        for kind, root in self.fit_nodes.items():
            header = bytearray(64)
            header[56:60] = b'ARMd'
            struct.pack_into('<Q', header, 16, 0x200000)
            raw = bytes(header) + b''.join(bytes.fromhex(self.identity['manifest'][part]['sha256'])
                                          for part in ('code', 'data') if (kind, part) not in self.omit_digests)
            if kind == 'recovery':
                raw += archive * self.archive_count
            if kind in self.raw_changes:
                raw = self.raw_changes[kind](raw)
            images = root.child('images')
            compression = images.child('kernel-1').properties['compression']
            images.child('kernel-1').payload = gzip.compress(raw) if compression == strings('gzip') else lzma.compress(raw)
            images.child('fdt-1').payload = flatten(self.other_dt) if kind == 'sysupgrade' and self.other_dt else dtb
            for node in images.children:
                if node.properties.get('type') == strings('filesystem'):
                    node.payload = self.squashfs
            self.registry[kind.encode()] = SimpleNamespace(root=root, image_data=lambda node: (node.payload, None))

    def extract(self, command, **kwargs):
        if self.unsquashfs_failure:
            return SimpleNamespace(returncode=1, stderr='fixture extraction error')
        destination = Path(command[command.index('-d') + 1])
        requested = command[command.index('-d') + 3:]
        files = dict(self.files)
        files.update(self.rootfs_changes)
        for name, payload in files.items():
            if not any(name == request or name.startswith(request.rstrip('/') + '/') for request in requested):
                continue
            if payload is None:
                continue
            path = destination / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if name in self.rootfs_symlinks:
                path.symlink_to(self.rootfs_symlinks[name])
            else:
                path.write_bytes(payload)
        return SimpleNamespace(returncode=0, stderr='')

    def verify(self):
        self.prepare()
        return subject.verify(self.args)

    def reject(self, reason):
        with self.assertRaisesRegex(ValueError, reason):
            self.verify()

    def selection(self, kind='sysupgrade'):
        return self.fit_nodes[kind].child('configurations').child('conf-1').properties

    def test_valid_pair_and_loadables(self):
        result = self.verify()
        self.assertTrue(result['passed'])
        self.assertFalse(result['board_tested'])
        self.assertEqual(result['profile'], 'pon-full')
        self.assertEqual(self.hash_checks, 2)
        self.assertEqual(result['modules'], 5)
        self.assertEqual(result['source_manifest_sha256'], subject.sha256(self.args.source_manifest.read_bytes()))
        self.assertEqual(len(result['recovery']['resident_checks']), 19)

    def test_sysupgrade_without_loadables(self):
        del self.selection()['loadables']
        self.assertTrue(self.verify()['passed'])

    def test_gzip_kernel(self):
        for root in self.fit_nodes.values():
            root.child('images').child('kernel-1').properties['compression'] = strings('gzip')
        self.assertTrue(self.verify()['passed'])

    def test_auxiliary_target_rejections(self):
        for kind in self.fit_nodes:
            original = dict(self.selection(kind))
            for prop, value in [('firmware', strings('rootfs-1')), ('ramdisk', strings('rootfs-1')),
                                ('loadables', strings('kernel-1')), ('loadables', strings('fdt-1')),
                                ('loadables', strings('rootfs-1', 'kernel-1')),
                                ('loadables', strings('rootfs-1', 'rootfs-1')),
                                ('loadables', strings('missing-rootfs')),
                                ('loadables', b'rootfs-1'), ('loadables', b''),
                                ('loadables', strings(''))]:
                with self.subTest(kind=kind, property=prop, value=value):
                    self.selection(kind).clear()
                    self.selection(kind).update(original)
                    self.selection(kind)[prop] = value
                    self.reject('auxiliary|missing FIT/DT node')
            self.selection(kind).clear()
            self.selection(kind).update(original)
        self.selection('recovery')['loadables'] = strings('rootfs-1')
        self.reject('auxiliary')

    def test_filesystem_load_and_entry_rejected(self):
        properties = self.fit_nodes['sysupgrade'].child('images').child('rootfs-1').properties
        for field in ('load', 'entry'):
            with self.subTest(field=field):
                properties[field] = cells(0)
                self.reject('filesystem must not have load/entry')
                del properties[field]

    def test_filesystem_count_and_type(self):
        images = self.fit_nodes['sysupgrade'].child('images')
        filesystem = images.child('rootfs-1')
        filesystem.properties['type'] = strings('firmware')
        self.reject('filesystem count')
        filesystem.properties['type'] = strings('filesystem')
        images.children.append(Node('rootfs-2', {'type': strings('filesystem')}))
        self.reject('filesystem count')
        images.children.pop()
        self.fit_nodes['recovery'].child('images').children.append(filesystem)
        self.reject('filesystem count')

    def test_hash_failure(self):
        self.hash_failure = True
        self.reject('FIT hash mismatch')

    def test_kernel_header_load_compression(self):
        kernel = self.fit_nodes['sysupgrade'].child('images').child('kernel-1')
        for field in ('load', 'entry'):
            original = kernel.properties[field]
            kernel.properties[field] = cells(0x8a000004)
            self.reject('kernel load/entry')
            kernel.properties[field] = original
        kernel.properties['compression'] = strings('none')
        self.reject('compression')
        kernel.properties['compression'] = strings('lzma')
        self.raw_changes['sysupgrade'] = lambda raw: raw[:56] + b'bad!' + raw[60:]
        self.reject('ARM64')

    def test_profile_and_resident_config(self):
        for label in ('eth', 'npu'):
            properties = self.devices[label].properties
            del properties['airoha,connac2-pon-full']
            self.reject('resident preflight')
            properties['airoha,connac2-pon-full'] = b''
            properties['airoha,connac2-ordinary-full-test'] = b''
            self.reject('resident preflight')
            del properties['airoha,connac2-ordinary-full-test']
        self.config = self.config.replace('CONFIG_NET_AIROHA_NPU=y', 'CONFIG_NET_AIROHA_NPU=m')
        self.reject('resident preflight')

    def test_network_variant_and_diagnostic(self):
        self.dt.properties['variant'] = strings('ordinary')
        self.reject('network variant')
        self.dt.properties['variant'] = strings('pon-full')
        self.devices['eth'].properties['airoha,connac2-pon-er-diagnostic'] = b''
        self.reject('diagnostic mode')

    def test_persistent_devices_and_calibration(self):
        for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'hg5585f_bosa', 'gdm2', 'pon_pcs'):
            with self.subTest(device=label):
                self.devices[label].properties['status'] = strings('disabled')
                self.reject('disabled persistent device: ' + label)
                self.devices[label].properties['status'] = strings('okay')
        for label in ('xpon_mac', 'hg5585f_bosa'):
            value = self.devices[label].properties.pop('nvmem-cells')
            self.reject('factory calibration')
            self.devices[label].properties['nvmem-cells'] = value
        self.devices['xpon_mac'].properties['data-path'] = cells(21)
        self.reject('PON data path')

    def test_inline_radio_calibration(self):
        self.dt.children.append(Node('wifi', {'mediatek,eeprom-data': b'calibration'}))
        self.reject('inline radio calibration')

    def test_flash_layout_and_duplicate_partitions(self):
        self.dt.child('bl2').properties['reg'] = cells(0, 65536)
        self.reject('flash partition layout')
        self.dt.child('bl2').properties['reg'] = cells(0, 131072)
        self.dt.children.append(Node('duplicate', dict(self.dt.child('bl2').properties)))
        self.reject('duplicate or missing flash partition')

    def test_ubi_volumes(self):
        for name in ('fit-volume', 'factory-volume'):
            volume = self.dt.child(name)
            original = volume.properties['volname']
            volume.properties['volname'] = strings('wrong')
            self.reject('UBI volume')
            volume.properties['volname'] = original

    def test_ram_bounds_overlaps_and_kernel_extent(self):
        region = self.dt.child('reserved-memory').children[-1]
        original = region.properties['reg']
        for address, size in ((0x7ffff000, 0x1000), (0x9ffff000, 0x2000),
                              (0x93000000, 0), (0x8a000000, 0x1000),
                              (0x90000000, 0x1000), (0x92a00000, 0x1000)):
            with self.subTest(address=address, size=size):
                region.properties['reg'] = struct.pack('>QQ', address, size)
                self.reject('RAM overlap|resident preflight')
        region.properties['reg'] = original
        self.raw_changes['sysupgrade'] = lambda raw: raw[:16] + struct.pack('<Q', 0x7000000) + raw[24:]
        self.reject('RAM overlap')

    def test_dtb_pair_mismatch(self):
        self.other_dt = copy.deepcopy(self.dt)
        self.other_dt.properties['model'] = strings('different metadata')
        self.reject('DTB mismatch')

    def test_squashfs_magic(self):
        self.squashfs = b'not squashfs'
        self.reject('expected squashfs')

    def test_raw_cpio_must_be_embedded_once(self):
        for count in (0, 2):
            with self.subTest(count=count):
                self.archive_count = count
                self.reject('supplied initramfs')

    def test_raw_cpio_is_parsed(self):
        self.bad_archive = b'not cpio'
        self.reject('newc header')

    def test_duplicate_normalized_paths(self):
        for name in ('./etc/config/network', '././etc/config/network', 'etc//config/network'):
            with self.subTest(name=name):
                self.extra_entries = [self.entry(name, b'')]
                self.reject('duplicate normalized initramfs names')

    def test_nonregular_selected_cpio_files(self):
        for name in ('etc/config/network', NETWORK, METADATA, FIRMWARE + 'npu_pon_full_rv32.bin'):
            with self.subTest(name=name):
                self.modes[name] = stat.S_IFLNK | 0o777
                self.reject('non-regular initramfs file')
                del self.modes[name]

    def test_firmware_digest_missing_and_corrupt(self):
        for name in self.blobs:
            path = FIRMWARE + name
            original = self.files[path]
            for value in (None, original[:-1], original + b'changed'):
                with self.subTest(name=name, value=value):
                    if value is None:
                        self.files.pop(path, None)
                    else:
                        self.files[path] = value
                    self.reject('firmware pin mismatch')
            self.files[path] = original

    def test_loader_digest_in_each_kernel(self):
        for kind in ('recovery', 'sysupgrade'):
            for part in ('code', 'data'):
                with self.subTest(kind=kind, part=part):
                    self.omit_digests = {(kind, part)}
                    self.reject('production loader digest: ' + part)

    def test_conflicting_firmware_packages(self):
        for prefix in ('npu_rebuilt_', 'npu_full_test_'):
            name = FIRMWARE + prefix + 'rv32.bin'
            self.files[name] = b'conflict'
            self.reject('conflicting firmware package')
            del self.files[name]

    def test_required_modules(self):
        for name in list(self.files):
            if name.endswith('.ko'):
                original = self.files.pop(name)
                self.reject('missing module')
                self.files[name] = original

    def test_network_seed_and_generator(self):
        self.files['etc/config/network'] = b'config interface stale'
        self.reject('nonempty seed')
        self.files['etc/config/network'] = b''
        self.files[NETWORK] += b'changed'
        self.reject('wrong network generator')

    def test_provenance_mismatch_and_json_failure(self):
        for field, changed in [('profile', 'ordinary'), ('pon_production_admission', True),
                               ('firmware', '0' * 64), ('sources', {}), ('schema', 2)]:
            with self.subTest(field=field):
                self.files[METADATA] = json.dumps({**self.provenance, field: changed}).encode()
                self.reject('stale build provenance')
        self.files[METADATA] = b'{bad'
        self.reject('Expecting property name')

    def test_provenance_json_formatting_is_irrelevant(self):
        self.files[METADATA] = json.dumps(self.provenance, indent=4, sort_keys=True).encode()
        self.assertTrue(self.verify()['passed'])

    def test_selected_cross_rootfs_bytes(self):
        for name in self.files:
            with self.subTest(name=name):
                self.rootfs_changes = {name: self.files[name] + b'drift'}
                self.reject('rootfs mismatch: ' + name)

    def test_extra_sysupgrade_firmware_and_modules(self):
        for name in (FIRMWARE + 'npu_rebuilt_rv32.bin', FIRMWARE + 'npu_full_test_data.bin',
                     FIRMWARE + 'extra.bin', 'lib/modules/6.18.60/extra.ko'):
            with self.subTest(name=name):
                self.rootfs_changes = {name: b'extra'}
                self.reject('rootfs .* inventory mismatch')

    def test_missing_sysupgrade_files(self):
        for name in (FIRMWARE + 'npu_pon_full_rv32.bin', 'lib/modules/6.18.60/airoha-xpon.ko', METADATA):
            with self.subTest(name=name):
                self.rootfs_changes = {name: None}
                self.reject('inventory mismatch|missing or non-regular rootfs file')

    def test_sysupgrade_symlink_is_not_compared_as_regular_file(self):
        self.rootfs_symlinks[NETWORK] = self.package.parents[2] / 'target/linux/airoha/an7581/base-files' / NETWORK
        self.reject('non-regular rootfs file')

    def test_extractor_failure(self):
        self.unsquashfs_failure = True
        self.reject('unsquashfs failed: fixture extraction error')

    def test_cli_rejects_repository_and_existing_output(self):
        arguments = ['verify_pon_image.py', '--unsquashfs', 'fake-unsquashfs']
        for name in ('recovery', 'sysupgrade', 'initramfs_archive', 'config', 'source_manifest', 'image_helper'):
            arguments.extend(['--' + name.replace('_', '-'), str(getattr(self.args, name))])
        for output, reason in ((self.package.parents[2] / 'report.json', 'outside ponwrt'),
                               (self.args.source_manifest, 'output must be new')):
            with self.subTest(output=output), patch.object(sys, 'argv', arguments + ['--output', str(output)]), \
                    patch.object(subject, 'verify') as verifier:
                before = output.read_bytes() if output.exists() else None
                with self.assertRaisesRegex(ValueError, reason):
                    subject.main()
                verifier.assert_not_called()
                self.assertEqual(output.read_bytes() if output.exists() else None, before)


if __name__ == '__main__':
    unittest.main()
