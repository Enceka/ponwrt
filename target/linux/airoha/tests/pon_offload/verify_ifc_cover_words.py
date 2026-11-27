#!/usr/bin/env python3
"""Compare typed SPORT2 CPU covers with complete stock TCAM/action readback."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

from verify_ifc_tuple_packet import PacketOracle
from verify_ifc_service import U32_MAX, sif_matches


HARNESS = r'''
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint32_t u32;
typedef uint16_t u16;
#define BIT(index) (UINT32_C(1) << (index))
#define U32_MAX UINT32_MAX
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86dd
#include "airoha_ct_pon_ifc_words.h"

int main(void)
{
    struct airoha_ct_pon_ifc_words row, before;
    const unsigned int types[] = {0, 1, 2, 3, UINT_MAX};
    unsigned int ring, type, invalid = 0;

    assert(airoha_ct_pon_ifc_cover_encode(NULL, 2, 0) == -EINVAL);
    invalid++;
    for (unsigned int candidate = 0; candidate < 34; candidate++) {
        ring = candidate == 33 ? UINT_MAX : candidate;
        for (unsigned int index = 0; index < sizeof(types) / sizeof(types[0]); index++) {
            type = types[index];
            if ((ring == 2 || ring == 4) && type <= 1)
                continue;
            memset(&row, 0xa5, sizeof(row));
            before = row;
            assert(airoha_ct_pon_ifc_cover_encode(&row, ring, type) == -EINVAL);
            assert(!memcmp(&row, &before, sizeof(row)));
            invalid++;
        }
    }
    fprintf(stderr, "invalid_checks=%u\n", invalid);
    while (scanf("%u %u", &ring, &type) == 2) {
        memset(&row, 0xa5, sizeof(row));
        assert(!airoha_ct_pon_ifc_cover_encode(&row, ring, type));
        for (unsigned int page = 0; page < 9; page++)
            printf("%08x %08x ", row.tcam[page][0], row.tcam[page][1]);
        for (unsigned int page = 0; page < 3; page++)
            for (unsigned int word = 0; word < 3; word++)
                printf("%08x ", row.action[page][word]);
        puts("");
    }
    return 0;
}
'''
SYMBOLS = {
    'ifc_set_rule': 0x10ec,
    'ifc_set_field_sif': 0x4e94,
    'ifc_get_field_sif': 0xc0c8,
    'ifc_read_rule': 0xd48,
    'ifc_set_action_forceCPU': 0xb1e8,
    'ifc_read_act': 0xed8,
    'ifc_set_field_dipv6_w0': 0x42c0,
}


def set_field(stock, row, row_type, field, value, mask):
    stock.cpu.mem_write(stock.DATA, bytes(64))
    stock.put(stock.DATA + 16, '<BB', row_type, 1)
    stock.put(stock.DATA + 20, '<4I', row, field, value, mask)
    assert stock.call('ifc_set_rule', stock.DATA) == 0


def read_tcam(stock, row):
    key_buffer = stock.DATA + 0x20000
    mask_buffer = key_buffer + 0x100
    stock.call('ifc_read_rule', row, key_buffer, mask_buffer)
    keys = stock.get(key_buffer, '<9I')
    masks = stock.get(mask_buffer, '<9I')
    pages = [(keys[8 - page], masks[8 - page]) for page in range(9)]
    assert all(words == stock.rows[0, row, page] for page, words in enumerate(pages))
    return pages


def read_action(stock, row):
    buffer = stock.DATA + 0x20200
    stock.call('ifc_read_act', row, buffer)
    words = stock.get(buffer, '<6I')
    pages = [(words[5], words[4], 0), (words[3], words[2], words[1]), (words[0], 0, 0)]
    for page, width in enumerate((2, 3, 1)):
        assert pages[page][:width] == stock.rows[2, row, page]
    return pages


def cover_case(path, row, row_type, ring, candidate):
    stock = PacketOracle(path)
    for name, offset in SYMBOLS.items():
        assert stock.names[name] - stock.text == offset
    set_field(stock, row, row_type, 14, 4, U32_MAX)
    tcam = read_tcam(stock, row)
    assert tcam == [(4, U32_MAX)] + [(0, 0)] * 7 + [(row_type << 6, 0xc0)]
    shadows = [stock.names[name] + row * 0x74 for name in ('ifc_rule_key', 'ifc_rule_mask')]
    for address in shadows:
        stock.cpu.mem_write(address, bytes(0x74))
    offset = (8, 0x2c)[row_type]
    stock.call('ifc_read_rule', row, shadows[0] + offset, shadows[1] + offset)
    stock.call('ifc_get_field_sif', stock.DATA)
    assert stock.get(stock.DATA + 28, '<II') == (4, U32_MAX)
    for source in range(32):
        assert sif_matches(*tcam[0], source) == (source == 2)
    stock.force_cpu(row, 1, ring)
    action = read_action(stock, row)
    expected = [word for page in tcam + action for word in page]
    assert len(candidate) == 27 and candidate == expected, (row, row_type, ring)
    stock.force_cpu(row, 0, ring)
    disabled = read_action(stock, row)
    assert disabled == [action[0], action[1], (0x50000000, 0, 0)]
    assert read_tcam(stock, row) == tcam
    return dict(row=row, type=row_type, ring=ring, tcam=tcam, action=action,
                disabled_action=disabled, sif_getter=[4, U32_MAX], candidate=candidate,
                stub_calls=dict(stock.stub_calls))


def type2_cases(path, candidates):
    records = []
    for value in (0, 4, 0x12345678, 0xffffffff):
        stock = PacketOracle(path)
        stock.cpu.mem_write(stock.DATA, bytes(64))
        stock.put(stock.DATA + 20, '<4I', 56, 5, value, 0xffffffff)
        assert stock.call('ifc_set_rule', stock.DATA) == 0
        assert stock.get(stock.DATA + 16, '<B') == (2,)
        pages = read_tcam(stock, 56)
        assert pages == [(value, 0xffffffff)] + [(0, 0)] * 7 + [(0x80, 0xc0)]
        packet = [value] + [0] * 7 + [0x80]
        for candidate in candidates:
            typed = list(zip(candidate[:18:2], candidate[1:18:2]))
            assert any((word ^ key) & mask for word, (key, mask) in zip(packet, typed))
            wildcard = typed[:8] + [(0, 0)]
            wildcard_hit = all(not ((word ^ key) & mask)
                               for word, (key, mask) in zip(packet, wildcard))
            assert wildcard_hit == (value == 4)
            legacy_wildcard = [(4, 4)] + wildcard[1:]
            legacy_hit = all(not ((word ^ key) & mask)
                             for word, (key, mask) in zip(packet, legacy_wildcard))
            assert legacy_hit == bool(value & 4)
        records.append(dict(field=5, natural_type=2, address_low_word=value, pages=pages,
                            typed_cover_match=False, wildcard_type_match=value == 4,
                            legacy_wildcard_type_match=bool(value & 4)))
    stock = PacketOracle(path)
    set_field(stock, 56, 2, 14, 4, U32_MAX)
    assert stock.rows == {}
    return records


def sif_cases(path):
    stock = PacketOracle(path)
    records = []
    for row_type in (0, 1):
        for selected in range(32):
            for name, key, mask in (('only', 1 << selected, U32_MAX),
                                    ('absent', 0, 1 << selected),
                                    ('legacy', 1 << selected, 1 << selected)):
                set_field(stock, 56, row_type, 14, key, mask)
                pages = read_tcam(stock, 56)
                assert pages[0] == (key, mask)
                assert pages[8] == (row_type << 6, 0xc0)
                accepted = [source for source in range(32) if sif_matches(*pages[0], source)]
                expected = [selected] if name == 'only' else (
                    [source for source in range(32) if source != selected]
                    if name == 'absent' else list(range(32)))
                assert accepted == expected
                records.append(dict(type=row_type, selected=selected, profile=name,
                                    page0=pages[0], accepted_sources=accepted))
    return records


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required; omit -O')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    header = args.source / 'drivers/net/ethernet/airoha/airoha_ct_pon_ifc_words.h'
    snapshot = output / header.name
    shutil.copyfile(header, snapshot)
    harness = output / 'cover_words_test.c'
    harness.write_text(HARNESS)
    binary = output / 'cover-words'
    command = ['cc', '-std=c11', '-Wall', '-Wextra', '-Werror',
               '-fsanitize=address,undefined', '-fno-sanitize-recover=all',
               '-I', str(output), str(harness), '-o', str(binary)]
    compiled = subprocess.run(command, text=True, capture_output=True)
    (output / 'compile.log').write_text(compiled.stdout + compiled.stderr)
    compiled.check_returncode()
    cases = [(row, row_type, ring) for row in range(56, 60)
             for row_type in (0, 1) for ring in (2, 4)]
    inputs = ''.join(f'{ring} {row_type}\n' for row, row_type, ring in cases)
    (output / 'input.txt').write_text(inputs)
    executed = subprocess.run([str(binary)], input=inputs, text=True, capture_output=True)
    (output / 'stdout.txt').write_text(executed.stdout)
    (output / 'stderr.txt').write_text(executed.stderr)
    executed.check_returncode()
    assert executed.stderr == 'invalid_checks=167\n', executed.stderr
    candidates = [[int(word, 16) for word in line.split()] for line in executed.stdout.splitlines()]
    assert len(candidates) == len(cases)
    path = args.stock_dir / 'ifc.ko'
    records = [cover_case(path, *case, words) for case, words in zip(cases, candidates)]
    regressions = type2_cases(path, candidates[:4])
    source_vectors = sif_cases(path)
    report = dict(passed=True, cover_vectors=len(records), word_comparisons=27 * len(records),
                  invalid_checks=167, type2_address_vectors=len(regressions), type2_sif_no_write=True,
                  cover_source_checks=len(records) * 32, sif_checks=len(source_vectors) * 32,
                  sif_model='SPORT-indexed key/mask bit', sif_mask=U32_MAX,
                  stock_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                  header_sha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                  script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
                  symbols={name: hex(offset) for name, offset in SYMBOLS.items()},
                  compile_command=command, sanitizers=['address', 'undefined'],
                  execution='process-local Unicorn and native pure encoder',
                  predicate_model='SPORT-indexed SIF for types0/1; ternary address comparison for type2',
                  priority='not modeled', vectors=records, type2=regressions,
                  sif_vectors=source_vectors)
    (output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({key: report[key] for key in
                      ('passed', 'cover_vectors', 'word_comparisons', 'invalid_checks',
                       'type2_address_vectors', 'type2_sif_no_write', 'header_sha256')}))


if __name__ == '__main__':
    main()
