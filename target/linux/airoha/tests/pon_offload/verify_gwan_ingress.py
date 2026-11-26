#!/usr/bin/env python3
"""Run stock GPON RX service selection and check its skb against stock FOE state."""
import argparse
from collections import Counter
import json
from pathlib import Path
from unicorn import arm64_const as R

from stock_oracle import Module


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--stock-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    m = Module(args.stock_dir / 'xpon_10g.ko')
    h = Module(args.stock_dir / 'hw_nat.ko')
    msg, skb, frame, flag = [m.DATA + off for off in (0, 0x1000, 0x2000, 0x3000)]
    wan, sys, gpon = [m.DATA + off for off in (0x10000, 0x50000, 0x90000)]
    for name, addr in [('gpWanPriv', wan), ('gpPonSysData', sys), ('gpGponPriv', gpon)]:
        m.put(m.names[name], '<Q', addr)
    # isUnknownUnicastPkt follows the WAN netdev to its hardware address.
    netdev, devaddr = m.DATA + 0xa0000, m.DATA + 0xa1000
    unicast = '020000000001'
    m.put(wan + 0x18, '<Q', netdev)
    m.put(netdev + 0x2f8, '<Q', devaddr)
    m.cpu.mem_write(devaddr, bytes.fromhex(unicast))
    ext, entry = h.DATA + 0x10000, 53
    h.put(h.names['foe_ext'], '<Q', ext)
    stored = ext + entry * 0xa8 + 0x5c
    deleted = []
    h.local_stubs[h.names['hwnat_delete_foe_entry']] = (
        'hwnat_delete_foe_entry', lambda module: deleted.append(module.cpu.reg_read(R.UC_ARM64_REG_W0)))
    counts = Counter()

    def run(gem, index, valid, channel, ani, dmac, oam=False, flag_mode=0, vlan=42):
        m.put(msg, '<IIII', (gem << 14) | (0x100 if oam else 0), 2 << 21, 0, 0)
        m.cpu.mem_write(skb, bytes(0x200))
        m.cpu.mem_write(frame, bytes.fromhex(dmac + '0200000000028100' + f'{vlan:04x}0800') + bytes(110))
        m.put(skb + 0x188, '<Q', frame)
        m.put(skb + 0xb8, '<HH', 0x1234, 0xace1)
        m.put(skb + 0x12f, '<H', entry)
        m.put(flag, '<B', 0)
        m.put(wan + 2 * (0x38 + gem), '<H', index)
        row = wan + 0x20070 + 0xc8 * (index & 0xff)
        m.cpu.mem_write(row, bytes(0xc8))
        m.put(row, '<II', gem, ani)
        m.put(row + 8, '<B', channel)
        m.put(row + 9, '<B', flag_mode)
        m.put(row + 12, '<B', valid)
        result = m.call('gwan_process_rx_message', msg, skb, 128, flag)
        assert m.get(skb + 0xc0, '<B') == ((ani & 0xff) if (result >= 0 and not oam) else 0,)
        return (result, *m.get(skb + 0xb8, '<HH'), *m.get(skb + 0xbc, '<I'),
                *m.get(flag, '<B'), *m.get(row + 16, '<Q'), *m.get(row + 32, '<Q'))

    bcast, mcast = 'ffffffffffff', '01005e000001'
    for gem in (0, 1, 0xff, 0x100, 0x1ff, 0xfff, 0x1000, 0x8000, 0xffff):
        for index in (0, 1, 0xff, 0x8001):
            for channel, ani in ((0, 0), (31, 256), (32, 257)):
                for addr, code in ((bcast, 0x13), (mcast, 0x23), (unicast, 3), ('020000000003', 0x33)):
                    got = run(gem, index, 1, channel, ani, addr)
                    assert got == (code, int(channel == 32), gem, 0x400,
                                   0, 1, 128), (gem, index, channel, got)
                    counts['data'] += 1
        for index, valid, channel, ani in ((3, 0, 0, 0), (3, 0, 32, 257),
                                            (256, 1, 0, 0), (0xffff, 1, 32, 0),
                                            (3, 1, 31, 257)):
            got = run(gem, index, valid, channel, ani, bcast)
            assert got == (-1, 0x1234, 0xace1, 0, 0, 0, 0), (gem, index, got)
            counts['unmapped_or_invalid'] += 1
        for channel in (0, 31, 32):
            got = run(gem, 1, 1, channel, 1, bcast, flag_mode=1)
            assert got == (0x13, int(channel == 32), gem, 0x400,
                           int(channel < 32), 1, 128), (gem, channel, got)
            counts['optional_output_flag'] += 1
        # OMCC is disabled in the controller fixture; even a valid data map
        # for the same GEM must not publish data metadata on an OAM packet.
        m.put(gpon + 0x3fa, '<H', 0x3ff)
        got = run(gem, 1, 1, 0, 0, bcast, oam=True)
        assert got == (-1, 0x1234, 0xace1, 0, 0, 0, 0), got
        counts['oam_not_data'] += 1
        # Keep both mappings present; the control path accounts to the
        # configured OMCC row even when the RX message carries another GEM.
        omcc = gem ^ 0x4000
        omcc_row = wan + 0x20070 + 2 * 0xc8
        m.put(gpon + 0x3fa, '<H', omcc)
        m.put(wan + 2 * (0x38 + omcc), '<H', 2)
        m.cpu.mem_write(omcc_row, bytes(0xc8))
        m.put(omcc_row, '<I', omcc)
        m.put(omcc_row + 12, '<B', 1)
        got = run(gem, 1, 1, 0, 0, bcast, oam=True)
        assert got == (1, 0x1234, 0xace1, 0, 0, 0, 0), got
        assert m.get(omcc_row + 16, '<Q') == (1,) and m.get(omcc_row + 32, '<Q') == (128,)
        counts['configured_omci'] += 1

        for channel in (0, 32):
            for vlan in (42, 4094):
                assert run(gem, 1, 1, channel, 0, unicast, vlan=vlan)[0] == 3
                packet = bytes(m.cpu.mem_read(skb, 0x200))
                for mismatch in (False, True):
                    previous = gem ^ (0x0100 if mismatch else 0)
                    h.put(stored, '<I', previous)
                    deleted.clear()
                    h.cpu.mem_write(skb, packet)
                    h.call('PpeGemportCheck', skb)
                    assert h.get(stored, '<I') == ((2**32 - 1) if mismatch else gem,)
                    assert deleted == ([entry] if mismatch else [])
                    counts['foe_delete' if mismatch else 'foe_keep'] += 1
    result = dict(functions=['gwan_process_rx_message', 'PpeGemportCheck'], counts=dict(counts),
                  modules={v.path.name: dict(sha256=v.sha256, instructions=v.instructions,
                                              helper_stubs=dict(v.stub_calls)) for v in (m, h)})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
