#!/usr/bin/env python3
"""Check how stock EPON software selects and validates an RX data channel."""
import argparse
from collections import Counter
from itertools import product
import json
from pathlib import Path

from stock_oracle import Module


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    m = Module(args.stock_dir / 'xpon_10g.ko')
    msg, skb, flag = [m.DATA + off for off in (0, 0x1000, 0x2000)]
    wan, system = m.DATA + 0x10000, m.DATA + 0x50000
    m.put(m.names['gpWanPriv'], '<Q', wan)
    m.put(m.names['gpPonSysData'], '<Q', system)
    counts = Counter()
    # Vary every bit of the 16-bit field used for GPON service selection.
    tags = [0, 0xffff] + [1 << n for n in range(16)]
    for channel, tag, enabled, drop, mark in product(range(32), tags, range(2), range(2), range(2)):
        row = wan + 0x2c930 + channel * 0xc0
        other = wan + 0x2c930 + (channel ^ 1) * 0xc0
        m.cpu.mem_write(row, bytes(0xc0))
        m.cpu.mem_write(other, bytes(0xc0))
        # A neighbouring channel has the opposite enable state. Distinct
        # LLID values in the table's low 16 bits keep them apart from the tag.
        ctl = enabled << 23 | drop << 20 | mark << 21 | (tag ^ 0xa55a)
        m.put(row + 8, '<Q', ctl)
        m.put(other + 8, '<Q', (1 - enabled) << 23 | (tag ^ 0x5aa5))
        m.put(msg, '<IIII', tag << 14 | channel << 3, 2 << 21, 0, 0)
        m.cpu.mem_write(skb, bytes(0x200))
        m.put(skb + 0xa0, '<I', 0x12345678)
        m.put(skb + 0xba, '<H', 0xace1)
        m.put(skb + 0xc0, '<B', 0xff)
        m.put(flag, '<BB', 0, 0)
        length = 128 + channel
        got = m.call('ewan_process_rx_message', msg, skb, length, flag, flag + 1)
        accepted = bool(enabled and not drop)
        marked = bool(accepted and mark)
        assert got == (3 if accepted else -1), (channel, tag, ctl, got)
        assert m.get(skb + 0xc0, '<B') == (channel if enabled else 0xff,)
        assert m.get(skb + 0xba, '<H') == (0xace1,)
        assert m.get(flag, '<BB') == (int(marked), 0)
        assert m.get(skb + 0xa0, '<I') == (0x12345608 if marked else 0x12345678,)
        for offset, expected in ((0x10, int(accepted)), (0x20, length if accepted else 0),
                                 (0x40, int(enabled and drop))):
            assert m.get(row + offset, '<Q') == (expected,)
            assert m.get(other + offset, '<Q') == (0,)
        counts['accepted' if accepted else 'dropped' if enabled else 'inactive'] += 1
    assert not m.stub_calls, m.stub_calls
    result = dict(function='ewan_process_rx_message', stock_sha256=m.sha256,
                  counts=dict(counts), total=sum(counts.values()), instructions=m.instructions)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
