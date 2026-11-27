#!/usr/bin/env python3
"""Compare exact tuple words to SHA-pinned stock setters and single LUT predicates."""
import argparse
import hashlib
import json
from pathlib import Path
import random
import shutil
import signal
import subprocess

from stock_oracle import Module, R
from verify_ifc_service import Classifier


class LutSetter(Module):
    def __init__(self, path):
        super().__init__(path)
        assert self.names['ifc_set_lut1_rules'] - self.text == 0x1261c
        assert self.names['ifc_lut1_rule_parser'] - self.text == 0x1da84
        self.local_stubs[self.names['write_all_ifc_rule_to_hw']] = (
            'publication_skipped', lambda module: module.cpu.reg_write(R.UC_ARM64_REG_W0, 0))
        self.local_stubs[self.names['ifc_get_value_by_field']] = ('field_value_input', self.field_value)
        self.put(self.names['gpIfcPriv'], '<Q', self.DATA + 0x4000)
        self.field, self.value, self.valid = 0, 0, True

    def field_value(self, module):
        assert module.cpu.reg_read(R.UC_ARM64_REG_W3) == self.field
        module.cpu.reg_write(R.UC_ARM64_REG_X0, 0 if self.valid else 0xffffffff)
        module.cpu.reg_write(R.UC_ARM64_REG_X1, self.value)

    def encode(self, index, field, value, width):
        self.cpu.mem_write(self.names['IFC_LUT1_Rule'], bytes(32 * 8))
        prefix = 0 if width == 32 else (1 << width) - 1
        result = self.call('ifc_set_lut1_rules', index, 1, 1, field, 0, prefix, 0, value)
        assert result == index + 1
        control, data = self.get(self.names['IFC_LUT1_Rule'] + index * 8, '<II')
        return data, control

    def predicate(self, index, field, value, valid=True):
        self.field, self.value, self.valid = field, value, valid
        result = self.call('ifc_lut1_rule_parser', self.DATA, self.DATA, self.DATA,
                           index, self.DATA + 0x3000)
        assert self.get(self.DATA + 0x3000, '<I')[0] == index + 1
        assert result in (0, -1)
        return result == 0


def make_cases():
    generator = random.Random(980)
    cases = []
    for family in (4, 6):
        for protocol in (6, 17):
            for first in range(32):
                for sample in range(2):
                    indices = [index for index in range(32) if index != first]
                    generator.shuffle(indices)
                    indices.insert(0, first)
                    count = 1 if family == 4 else 4
                    src = [generator.getrandbits(32) for _ in range(count)] + [0] * (4 - count)
                    dst = [generator.getrandbits(32) for _ in range(count)] + [0] * (4 - count)
                    if sample == 0:
                        src[:count] = [0] * count
                        dst[:count] = [0xffffffff] * count
                    cases.append(dict(family=family, protocol=protocol,
                                      sport=0 if sample == 0 else generator.randrange(65536),
                                      dport=65535 if sample == 0 else generator.randrange(65536),
                                      indices=indices[:11], src=src, dst=dst))
    return cases


def input_line(case):
    return ' '.join([str(case[key]) for key in ('family', 'protocol', 'sport', 'dport')] +
                    [f'{word:x}' for word in case['src'] + case['dst']]) + '\n'


def fields(case):
    if case['family'] == 4:
        addresses = [(3, case['dst'][0], 32), (4, case['src'][0], 32)]
    else:
        addresses = [(5 + index, value, 32) for index, value in enumerate(reversed(case['dst']))]
        addresses += [(9 + index, value, 32) for index, value in enumerate(reversed(case['src']))]
    return addresses + [(24 if case['family'] == 4 else 25, case['protocol'], 8),
                        (28, case['dport'], 16), (29, case['sport'], 16)]


def check_type_layouts(path):
    stock = Classifier(path)
    row = 56
    shadows = [stock.names[name] + row * 0x74 for name in ('ifc_rule_key', 'ifc_rule_mask')]
    records = []
    for row_type in (0, 1):
        for protocol_valid in (0, 1):
            for port_valid in (0, 1):
                for address in shadows:
                    stock.cpu.mem_write(address, bytes(0x74))
                for name, value in (('L4PrtcoVLD', protocol_valid), ('L4PortVLD', port_valid)):
                    stock.cpu.mem_write(stock.DATA, bytes(64))
                    stock.put(stock.DATA + 16, '<B', row_type)
                    stock.put(stock.DATA + 20, '<I', row)
                    stock.put(stock.DATA + 28, '<II', value, 1)
                    stock.call('ifc_set_field_' + name, stock.DATA)
                page7 = stock.rows[0, row, 7]
                assert page7 == ((protocol_valid << 8) | (port_valid << 9), 0x300)
                assert stock.rows[0, row, 8] == (row_type << 6, 0xc0)
                for address in shadows:
                    stock.cpu.mem_write(address, bytes(0x74))
                offset = 8 if row_type == 0 else 0x2c
                stock.call('ifc_read_rule', row, shadows[0] + offset, shadows[1] + offset)
                decoded = {}
                for name in ('dmac_type', 'L4PrtcoVLD', 'L4PortVLD'):
                    stock.call('ifc_get_field_' + name, stock.DATA)
                    decoded[name] = stock.get(stock.DATA + 28, '<II')
                if row_type == 0:
                    assert decoded == dict(dmac_type=(protocol_valid | (port_valid << 1), 3),
                                           L4PrtcoVLD=(0, 0), L4PortVLD=(0, 0))
                else:
                    assert decoded == dict(dmac_type=(0, 0),
                                           L4PrtcoVLD=(protocol_valid, 1), L4PortVLD=(port_valid, 1))
                records.append(dict(row_type=row_type, page7=page7, decoded=decoded))
    stock.cpu.mem_write(stock.DATA, bytes(64))
    stock.put(stock.DATA + 24, '<I', 31)
    assert stock.call('ifc_get_rule_type', stock.DATA) == 1
    assert stock.get(stock.DATA + 16, '<B') == (0,)
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    if not __debug__:
        parser.error('Run without -O; validation requires assertions.')
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    headers = args.source / 'drivers/net/ethernet/airoha'
    header_names = ['airoha_ct_ifc_tuple_words.h']
    production = {name: (headers / name).read_text() for name in header_names}
    test = output / 'ifc_tuple_words_test.c'
    shutil.copyfile(Path(__file__).with_name(test.name), test)
    cases = make_cases()
    inputs = ''.join(input_line(case) for case in cases)
    (output / 'cases.json').write_text(json.dumps(cases, indent=2) + '\n')
    (output / 'stdin.txt').write_text(inputs)

    def run(name, sanitized, header):
        directory = output / name
        directory.mkdir(parents=True)
        for filename, contents in production.items():
            (directory / filename).write_text(header if filename == header_names[0] else contents)
        command = ['clang', '-std=gnu11', '-O1', '-g', '-Wall', '-Wextra', '-Werror',
                   '-I', str(directory), str(test), '-o', str(directory / 'test')]
        if sanitized:
            command += ['-fsanitize=address,undefined', '-fno-sanitize-recover=all', '-fno-omit-frame-pointer']
        (directory / 'compile-command.json').write_text(json.dumps(command) + '\n')
        compiled = subprocess.run(command, capture_output=True, text=True)
        (directory / 'compile.log').write_text(compiled.stdout + compiled.stderr)
        compiled.check_returncode()
        tested = subprocess.run([str(directory / 'test')], input=inputs, capture_output=True, text=True)
        (directory / 'stdout.txt').write_text(tested.stdout)
        (directory / 'stderr.txt').write_text(tested.stderr)
        (directory / 'exit-status.json').write_text(json.dumps({'returncode': tested.returncode}) + '\n')
        return tested

    modes = []
    for mode in ('plain', 'sanitized'):
        tested = run(mode, mode == 'sanitized', production[header_names[0]])
        tested.check_returncode()
        modes.append(tested.stdout)
    assert modes[0] == modes[1]
    lines = modes[0].splitlines()
    assert len(lines) == len(cases)
    stock = LutSetter(args.stock_dir / 'ifc.ko')
    layouts = check_type_layouts(args.stock_dir / 'ifc.ko')
    lut_checks = predicate_checks = 0
    for case, line in zip(cases, lines):
        tokens = line.split()
        assert len(tokens) == 23
        count = int(tokens[0])
        lut_words = [int(word, 16) for word in tokens[1:]]
        expected_fields = fields(case)
        assert count == len(expected_fields)
        for position, (field, value, width) in enumerate(expected_fields):
            index = case['indices'][position]
            expected = stock.encode(index, field, value, width)
            actual = tuple(lut_words[position * 2:position * 2 + 2])
            assert actual == expected, (case, field, actual, expected)
            assert stock.predicate(index, field, value)
            assert not stock.predicate(index, field, value, valid=False)
            predicate_checks += 2
            for bit in range(width):
                assert not stock.predicate(index, field, value ^ (1 << bit)), (case, field, bit)
                predicate_checks += 1
            lut_checks += 1
        assert all(word == 0 for word in lut_words[count * 2:])

    mutations = [
        ('missing_end', 'BIT(15) | BIT(14)', 'BIT(15)'),
        ('missing_enable', 'BIT(15) | BIT(14)', 'BIT(14)'),
        ('accept_unsupported_protocol', '(tuple->protocol != 6 && tuple->protocol != 17)', 'false'),
        ('accept_ipv4_tail', 'if (tuple->src[index] || tuple->dst[index])', 'if (false)'),
        ('truncate_ipv6', 'encoded.count = index + 3;', 'encoded.count = 5;'),
    ]
    rejected = []
    for name, old, new in mutations:
        assert old in production[header_names[0]], name
        tested = run('mutations/' + name, True, production[header_names[0]].replace(old, new))
        assert tested.returncode == -signal.SIGABRT, (name, tested.returncode, tested.stderr)
        assert 'assert' in tested.stderr.lower() and 'failed' in tested.stderr.lower(), (name, tested.stderr)
        assert not any(marker in tested.stderr for marker in ('AddressSanitizer', 'UndefinedBehaviorSanitizer', 'runtime error:'))
        rejected.append(dict(name=name, compile_passed=True, caught_runtime=True, assertion=tested.stderr.strip()))
    report = dict(passed=True, tuple_cases=len(cases), lut_word_comparisons=lut_checks,
                  single_predicate_checks=predicate_checks, type_layout_cases=layouts,
                  runtime_mutations=rejected,
                  stock_sha256=stock.sha256, stock_setter='ifc_set_lut1_rules@0x1261c',
                  stock_parser='ifc_lut1_rule_parser@0x1da84',
                  production_sha256={name: hashlib.sha256(text.encode()).hexdigest() for name, text in production.items()},
                  test_sha256=hashlib.sha256(test.read_bytes()).hexdigest(),
                  validation_sha256={name: hashlib.sha256(Path(__file__).with_name(name).read_bytes()).hexdigest()
                                     for name in (Path(__file__).name, 'stock_oracle.py', 'verify_ifc_service.py')},
                  source=str(args.source.resolve()), sanitizers=['address', 'undefined'],
                  stubs=['stock write_all_ifc_rule_to_hw publication skipped for LUT setter',
                         'stock ifc_get_value_by_field receives explicit valid/value for single-predicate checks',
                         'type layout regression uses MMIO emulation from verify_ifc_service'],
                  scope='Pure tuple encoding and individual LUT predicates; no service row or admission API. Stock read/get regression distinguishes type0 DMAC and type1 L4 validity layouts.')
    (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in ('passed', 'tuple_cases', 'lut_word_comparisons',
                     'single_predicate_checks')}, indent=2))


if __name__ == '__main__':
    main()
