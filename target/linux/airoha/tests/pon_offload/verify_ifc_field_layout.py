#!/usr/bin/env python3
"""Audit stock field classification and complete TCAM readback in Unicorn."""
import argparse
import hashlib
import json
from pathlib import Path

from verify_ifc_tuple_packet import PacketOracle


TYPE_FIELDS = {
    0: [23, 15, 31, 16, 17, 18, 19, 20, 21, 30, 22, 1, 2, 14, 56, 57, 58, 59],
    1: [29, 28, 13, 4, 3, 25, 27, 26, 24, 48, 49, 50, 51, 52, 53, 54,
        55, 60, 61, 62, 63, 64, 65, 67],
    2: [12, 11, 10, 9, 8, 7, 6, 5, 66],
}
SYMBOLS = {
    'ifc_get_rule_type': 0xaac,
    'ifc_read_rule': 0xd48,
    'ifc_set_rule': 0x10ec,
    'ifc_set_field_dmac_type': 0x677c,
    'ifc_set_field_L4PrtcoVLD': 0x6a6c,
    'ifc_set_field_L4PortVLD': 0x6d54,
    'ifc_get_field_dmac_type': 0xc964,
    'ifc_get_field_L4PrtcoVLD': 0xca74,
    'ifc_get_field_L4PortVLD': 0xcb74,
}


def field_map(stock):
    reverse = {address: name for name, address in stock.names.items()
               if name.startswith(('ifc_set_field_', 'ifc_get_field_'))}
    records = []
    for row_type, fields in TYPE_FIELDS.items():
        for field in fields:
            slot = field if field < 32 else field - 16
            stock.cpu.mem_write(stock.DATA, bytes(64))
            stock.put(stock.DATA + 16, '<B', 0xff)
            stock.put(stock.DATA + 24, '<I', field)
            assert stock.call('ifc_get_rule_type', stock.DATA) == 1
            assert stock.get(stock.DATA + 16, '<B') == (row_type,)
            record = dict(field=field, natural_type=row_type, dispatch_slot=slot)
            for direction in ('set', 'get'):
                address = stock.get(stock.names[f'ifc_{direction}_field_funcs'] + slot * 8,
                                    '<Q')[0]
                record[direction] = reverse[address]
                record[direction + '_pc'] = hex(address - stock.text)
            records.append(record)
    assert len(records) == 51
    return sorted(records, key=lambda record: record['field'])


def read_case(path, name, fields, expected_type, expected_page8, expected_page7,
              forced=False):
    stock = PacketOracle(path)
    row = 56
    for field, value, mask in fields:
        stock.cpu.mem_write(stock.DATA, bytes(64))
        stock.put(stock.DATA + 17, '<B', int(forced))
        stock.put(stock.DATA + 20, '<4I', row, field, value, mask)
        assert stock.call('ifc_set_rule', stock.DATA) == 0
        assert stock.get(stock.DATA + 16, '<B') == (expected_type,)
    key_buffer = stock.DATA + 0x20000
    mask_buffer = key_buffer + 0x100
    stock.call('ifc_read_rule', row, key_buffer, mask_buffer)
    keys = stock.get(key_buffer, '<9I')
    masks = stock.get(mask_buffer, '<9I')
    pages = [(keys[8 - page], masks[8 - page]) for page in range(9)]
    assert all(words == stock.rows[0, row, page] for page, words in enumerate(pages))
    assert pages[8] == expected_page8
    assert pages[7] == expected_page7
    assert all(words == (0, 0) for words in pages[:7])
    layout_offset = {0: 8, 1: 0x2c}[expected_type]
    for symbol in ('ifc_rule_key', 'ifc_rule_mask'):
        stock.cpu.mem_write(stock.names[symbol] + row * 0x74, bytes(0x74))
    stock.call('ifc_read_rule', row,
               stock.names['ifc_rule_key'] + row * 0x74 + layout_offset,
               stock.names['ifc_rule_mask'] + row * 0x74 + layout_offset)
    decoded = {}
    for getter in ('dmac_type', 'L4PrtcoVLD', 'L4PortVLD',
                   'IPv4VLD', 'IPv6VLD', 'outterIPv4', 'outterIPv6'):
        stock.cpu.mem_write(stock.DATA, bytes(64))
        stock.put(stock.DATA + 20, '<I', row)
        stock.call('ifc_get_field_' + getter, stock.DATA)
        decoded[getter] = stock.get(stock.DATA + 28, '<II')
    expected = {getter: (0, 0) for getter in decoded}
    if expected_type == 0:
        expected['dmac_type'] = (expected_page7[0] >> 8, expected_page7[1] >> 8)
    else:
        field_names = {49: 'L4PrtcoVLD', 51: 'L4PortVLD', 52: 'outterIPv4',
                       53: 'outterIPv6', 54: 'IPv4VLD', 55: 'IPv6VLD'}
        for field, value, mask in fields:
            expected[field_names[field]] = (value, mask)
    assert decoded == expected, (name, decoded, expected)
    return dict(name=name, inputs=fields, forced_type0=forced, row_type=expected_type,
                pages=pages, readback_shadow_offset=layout_offset, decoded=decoded,
                stub_calls=dict(stock.stub_calls))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required; omit -O')
    path = args.stock_dir / 'ifc.ko'
    stock = PacketOracle(path)
    for name, offset in SYMBOLS.items():
        assert stock.names[name] - stock.text == offset
    mapping = field_map(stock)
    cases = [read_case(path, 'dmac_type', [(31, 3, 3)], 0, (0, 0xc0), (0x300, 0x300)),
             read_case(path, 'L4_valid', [(49, 1, 1), (51, 1, 1)], 1,
                       (0x40, 0xc0), (0x300, 0x300))]
    for field, name, bit in ((52, 'outer_IPv4', 8), (53, 'outer_IPv6', 4),
                             (54, 'IPv4_valid', 2), (55, 'IPv6_valid', 1)):
        cases.append(read_case(path, name, [(field, 1, 1)], 1,
                               (0x40 | bit, 0xc0 | bit), (0, 0)))
    for protocol_valid in (0, 1):
        for port_valid in (0, 1):
            cases.append(read_case(path, f'forced_type0_{protocol_valid}_{port_valid}',
                                   [(49, protocol_valid, 1), (51, port_valid, 1)], 0,
                                   (0, 0xc0),
                                   (protocol_valid << 8 | port_valid << 9, 0x300), True))
    result = dict(module_sha256=stock.sha256, field_count=len(mapping),
                  readback_cases=len(cases), symbols={name: hex(pc) for name, pc in SYMBOLS.items()},
                  field_map=mapping, cases=cases, execution='process-local Unicorn',
                  readback_adapter='test selects shadow +8 for type0, +0x2c for type1',
                  priority='TCAM numerical arbitration remains unresolved',
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest())
    args.output.mkdir(parents=True, exist_ok=False)
    (args.output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(dict(module_sha256=stock.sha256, field_count=len(mapping),
                          readback_cases=len(cases), result=str(args.output / 'result.json'))))


if __name__ == '__main__':
    main()
