#!/usr/bin/env python3
"""Compare production optical CPU row words with the stock named setters."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from verify_ifc_service import Classifier


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    header = args.source / 'drivers/net/ethernet/airoha/airoha_ct_pon_ifc_words.h'
    shutil.copyfile(header, output / header.name)
    binary = output / 'ifc-cpu-words'
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
                    '-fsanitize=address,undefined', '-I', str(output),
                    str(Path(__file__).with_name('ifc_cpu_words_test.c')),
                    '-o', str(binary)], check=True)
    cases = [(service, protocol, ring, short_lut)
             for service in (0, 1, 0x2134, 0xa134, 0xffff)
             for protocol in (0x0800, 0x86dd)
             for ring in (2, 4)
             for short_lut in range(32)]
    result = subprocess.run([str(binary)], input=''.join('%u %u %u %u\n' % case for case in cases),
                            capture_output=True, text=True, check=True)
    rows = result.stdout.splitlines()
    assert len(rows) == len(cases)
    classifier = Classifier(args.stock_dir / 'ifc.ko')
    packet_checks = 0
    for case, words in zip(cases, rows):
        service, protocol, ring, short_lut = case
        classifier.field(56, 'LUT1_hit', 0, 0)
        classifier.configure(56, service, protocol, False)
        classifier.field(56, 'LUT1_hit', 0, 1 << short_lut)
        classifier.force_cpu(56, 1, ring)
        expected = [value for page in range(9) for value in classifier.rows[0, 56, page]]
        for page in range(3):
            expected.extend(classifier.rows[2, 56, page])
            expected.extend([0] * (3 - len(classifier.rows[2, 56, page])))
        actual = [int(word, 16) for word in words.split()]
        assert actual == expected, case
        for hit in (0, 1 << short_lut, 1 << ((short_lut + 1) % 32)):
            for candidate in (service, service ^ 0x8000):
                accepted = candidate == service and not hit & (1 << short_lut)
                assert classifier.matches(56, candidate, protocol, lut_hits=hit) == accepted
                packet_checks += 1
        assert not classifier.matches(56, service, protocol, source=24)
        assert not classifier.matches(56, service, protocol, encap=0x400)
        packet_checks += 2
    report = dict(passed=True, word_comparisons=len(cases), packet_checks=packet_checks,
                  stock_sha256=classifier.sha256,
                  production_header_sha256=hashlib.sha256(header.read_bytes()).hexdigest(),
                  sanitizers=['address', 'undefined'], destination='WAN CPU rings 2/4')
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
