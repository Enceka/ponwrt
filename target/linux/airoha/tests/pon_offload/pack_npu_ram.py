#!/usr/bin/env python3
import argparse
import hashlib
import importlib.util
import json
import lzma
from pathlib import Path
import struct
import subprocess
import sys
import zlib

from prepare_npu_ram import require, sha256


def verified_kernel(path, expected):
    raw = path.read_bytes()
    require(sha256(raw) == expected, 'kernel transfer identity mismatch')
    return raw


def main():
    parser = argparse.ArgumentParser(description='Pack a prepared PON diagnostic kernel into a pinned RAM FIT')
    for name in ('baseline', 'base-archive', 'prepared', 'kernel', 'config', 'image-helper', 'output'):
        parser.add_argument('--' + name, type=Path, required=True)
    parser.add_argument('--baseline-sha256', required=True)
    parser.add_argument('--kernel-sha256', required=True,
                        help='SHA256 computed in the kernel build environment before transfer')
    args = parser.parse_args()
    baseline = args.baseline.read_bytes()
    require(sha256(baseline) == args.baseline_sha256, 'rollback FIT identity mismatch')
    spec = importlib.util.spec_from_file_location('pon_ram_image', args.image_helper)
    image = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = image
    spec.loader.exec_module(image)
    fit = image.Fit(baseline)
    image.verify_fit_hashes(fit)
    images = fit.root.child('images')
    require({node.name for node in images.children} == {'kernel-1', 'fdt-1'}, 'unexpected FIT images')
    configs = fit.root.child('configurations')
    config = configs.child(image.text(configs.properties['default'])).properties
    require(config['kernel'] == b'kernel-1\0' and config['fdt'] == b'fdt-1\0' and
            not {'ramdisk', 'loadables', 'firmware'} & config.keys(), 'unexpected FIT configuration')
    kernel = images.child('kernel-1')
    require(kernel.properties['compression'] == b'lzma\0' and
            image.integer(kernel.properties['load']) == image.integer(kernel.properties['entry']) == 0x8a000000,
            'kernel load address or compression mismatch')
    old_payload = fit.image_data(kernel)[0]
    old_kernel = lzma.decompress(old_payload)
    prepared = json.loads((args.prepared / 'prepared.json').read_text())
    old_archive = args.base_archive.read_bytes()
    archive = (args.prepared / 'pon-npu.cpio').read_bytes()
    require(sha256(old_archive) == prepared['baseline_initramfs_sha256'] and
            old_kernel.count(old_archive) == 1, 'baseline initramfs mismatch')
    require(sha256(archive) == prepared['initramfs_sha256'], 'prepared initramfs changed')
    raw = verified_kernel(args.kernel, args.kernel_sha256)
    require(raw[56:60] == b'ARMd' and raw.count(archive) == 1, 'kernel does not embed prepared initramfs')
    require(b'starting bound rebuilt Connac2 firmware' in raw and
            b'pon_npu_diag' in raw, 'missing startup or PON diagnostic code')
    require(all(bytes.fromhex(digest) in raw for digest in prepared['firmware_sha256'].values()),
            'kernel is missing a prepared loader digest')
    fdt = images.child('fdt-1')
    old_dtb = fit.image_data(fdt)[0]
    tree = image.Fit(old_dtb)
    require(tree.root.properties['compatible'].split(b'\0')[0] == b'fiberhome,hg5585f-ct', 'wrong board')
    symbols = tree.root.child('__symbols__').properties

    def node(label):
        found = tree.root
        for part in image.text(symbols[label]).strip('/').split('/'):
            found = found.child(part)
        return found

    for label in ('pnand', 'pnand_ecc', 'xpon_mac', 'pon_pcs', 'hg5585f_bosa'):
        require(node(label).properties.get('status') == b'disabled\0', 'enabled flash or optical node: ' + label)
    require('airoha,connac2-rebuilt-ram-lab' in node('npu').properties and
            'airoha,connac2-ram-native-pairs' in node('eth').properties and
            'airoha,connac2-ordinary-full-test' not in node('eth').properties, 'wrong firmware profile')
    require('airoha,connac2-pon-er-diagnostic' not in node('eth').properties, 'baseline already has diagnostic marker')
    node('eth').properties['airoha,connac2-pon-er-diagnostic'] = b''
    dtb = tree.encode()
    del node('eth').properties['airoha,connac2-pon-er-diagnostic']
    require(tree.encode() == image.Fit(old_dtb).encode(), 'unrelated DT mutation')
    properties = old_payload[0]
    payload = lzma.compress(raw, format=lzma.FORMAT_ALONE, filters=[dict(
        id=lzma.FILTER_LZMA1, dict_size=int.from_bytes(old_payload[1:5], 'little'),
        lc=properties % 9, lp=(properties // 9) % 5, pb=properties // 45)])
    for target, data in ((kernel, payload), (fdt, dtb)):
        require('data' in target.properties, 'external FIT image data unsupported')
        target.properties['data'] = data
        require(target.children, 'missing FIT hashes')
        for child in target.children:
            algorithm = image.text(child.properties['algo'])
            require(algorithm in ('crc32', 'sha1', 'sha256'), 'unexpected FIT hash algorithm')
            child.properties['value'] = (struct.pack('>I', zlib.crc32(data)) if algorithm == 'crc32'
                                         else hashlib.new(algorithm, data).digest())
    packed = fit.encode()
    packed += bytes(-len(packed) % 65536)
    check = image.Fit(packed)
    image.verify_fit_hashes(check)
    require(lzma.decompress(check.image_data(check.root.child('images').child('kernel-1'))[0]) == raw and
            check.image_data(check.root.child('images').child('fdt-1'))[0] == dtb, 'FIT roundtrip mismatch')
    ranges = [(0x8a000000, 0x8a000000 + max(len(raw), struct.unpack_from('<Q', raw, 16)[0])),
              (0x90000000, 0x90000000 + len(packed))]
    for region in tree.root.child('reserved-memory').children:
        address, size = struct.unpack('>QQ', region.properties['reg'])
        ranges.append((address, address + size))
    ranges.sort()
    require(all(0x80000000 <= start < end <= 0xa0000000 for start, end in ranges) and
            all(left[1] <= right[0] for left, right in zip(ranges, ranges[1:])), 'RAM regions overlap')
    output = args.output.resolve()
    require(not output.is_relative_to(Path(__file__).resolve().parents[5]), 'output must be outside ponwrt')
    output.mkdir(parents=True, exist_ok=False)
    (output / 'final.dtb').write_bytes(dtb)
    (output / 'final.config').write_bytes(args.config.read_bytes())
    verifier = Path(__file__).resolve().parent.parent / 'npu_resident_config/verify.py'
    subprocess.run([sys.executable, '-B', str(verifier), '--config', str(output / 'final.config'),
                    '--dt', str(output / 'final.dtb'), '--report', str(output / 'resident.json')], check=True)
    report = dict(prepared, fit_sha256=sha256(packed), bytes=len(packed),
                  kernel_sha256=sha256(raw), config_sha256=sha256(args.config.read_bytes()),
                  dtb_sha256=sha256(dtb), baseline_fit_sha256=sha256(baseline),
                  image_helper_sha256=sha256(args.image_helper.read_bytes()),
                  board_tested=False, pon_ppe_qualified=False)
    (output / 'pon-npu-diag-ram.itb').write_bytes(packed)
    (output / 'sealed.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
