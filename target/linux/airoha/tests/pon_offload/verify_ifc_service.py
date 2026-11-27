#!/usr/bin/env python3
"""Exercise two optical service rules in the stock AN7581 classifier writer."""
import argparse
import json
from pathlib import Path

from stock_oracle import Module, R


U32_MAX = (1 << 32) - 1


def sif_matches(key, mask, source):
    assert 0 <= source < 32
    return bool((key >> source) & 1) or not bool((mask >> source) & 1)


class Classifier(Module):
    ctrl, data = 0xbfb50204, 0xbfb50210

    def __init__(self, path):
        self.regs = {}
        self.rows = {}
        super().__init__(path)

    def _hook(self, cpu, pc, size, opaque):
        name, tail = self.calls.get(pc, ('', False))
        if name not in ('get_frame_engine_data', 'set_frame_engine_data'):
            return super()._hook(cpu, pc, size, opaque)
        addr = cpu.reg_read(R.UC_ARM64_REG_W0)
        assert addr in (self.ctrl, self.data, self.data + 4, self.data + 8)
        if name == 'set_frame_engine_data':
            word = cpu.reg_read(R.UC_ARM64_REG_W1)
            self.regs[addr] = word
            if addr == self.ctrl:
                row, page, bank = (word >> 16) & 63, (word >> 8) & 15, (word >> 4) & 7
                assert word & 1 and bank in (0, 2)
                n = 2 if bank == 0 else (2, 3, 1)[page]
                key = bank, row, page
                if word & 2:
                    self.rows[key] = tuple(self.regs[self.data + 4*i] for i in range(n))
                else:
                    for i, value in enumerate(self.rows.get(key, (0,) * n)):
                        self.regs[self.data + 4*i] = value
                self.regs[addr] |= 1 << 31
            result = 0
        else:
            result = self.regs.get(addr, 0)
        cpu.reg_write(R.UC_ARM64_REG_X0, result)
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)

    def field(self, row, name, value, mask):
        self.cpu.mem_write(self.DATA, bytes(64))
        self.put(self.DATA + 20, '<I', row)
        self.put(self.DATA + 28, '<II', value, mask)
        self.call('ifc_set_field_' + name, self.DATA)

    def steer(self, row, port, enabled, queue=7):
        self.cpu.mem_write(self.DATA, bytes(64))
        self.put(self.DATA + 18, '<B', 1)
        self.put(self.DATA + 20, '<7I', row, enabled, 1, 0, 1, port, queue)
        self.call('ifc_set_action_forcePort', self.DATA)
        assert self.rows[2,row,0] == (port << 8, 0)
        assert self.rows[2,row,1] == (0, 1 << 28, queue << 10)
        assert self.rows[2,row,2] == ((enabled << 31) | (1 << 30),)

    def configure(self, row, gem, etype, reverse):
        fields = [('sif', 4, U32_MAX), ('etype', etype, 65535), ('VLan0VLD', 0, 1),
                  ('VLan1VLD', 0, 1), ('isPPPoE', 0, 1), ('GEM_LLID', gem, 65535)]
        for args in (reversed(fields) if reverse else fields):
            self.field(row, *args)
        expected = {0: (4,U32_MAX), 5: (etype,65535), 7: (gem << 16,0xffff0430), 8: (0,0xc0)}
        for i in range(9):
            assert self.rows[0,row,i] == expected.get(i, (0,0)), (row,i,self.rows[0,row,i])

    def force_cpu(self, row, enabled, ring):
        self.cpu.mem_write(self.DATA, bytes(64))
        self.put(self.DATA + 18, '<B', 1)
        self.put(self.DATA + 20, '<7I', row, enabled, 1, 0, 0, 0, ring)
        self.call('ifc_set_action_forceCPU', self.DATA)
        assert self.rows[2,row,0] == (0, 0)
        assert self.rows[2,row,1] == (0, 0, ring << 10)
        assert self.rows[2,row,2] == ((enabled << 31) | (1 << 30) | (1 << 28),)

    def matches(self, row, gem, etype, source=2, encap=0, lut_hits=0):
        if not self.rows[2,row,2][0] & (1 << 31):
            return False
        if not sif_matches(*self.rows[0, row, 0], source):
            return False
        packet = {4: lut_hits, 5: etype, 7: gem << 16 | encap}
        return all(not ((packet.get(i, 0) ^ key) & mask)
                   for i in range(1, 9) for key, mask in [self.rows[0,row,i]])


def check_sif(path):
    stock = Classifier(path)
    stock.configure(56, 0x2134, 0x0800, False)
    stock.force_cpu(56, 1, 2)
    checked = 0
    for selected in range(32):
        for name, key, mask in (('only', 1 << selected, U32_MAX),
                                ('absent', 0, 1 << selected),
                                ('legacy', 1 << selected, 1 << selected)):
            stock.field(56, 'sif', key, mask)
            stock.call('ifc_read_rule', 56, stock.DATA + 0x1000, stock.DATA + 0x1100)
            assert stock.get(stock.DATA + 0x1020, '<I') == (key,)
            assert stock.get(stock.DATA + 0x1120, '<I') == (mask,)
            for source in range(32):
                expected = source == selected if name == 'only' else (
                    source != selected if name == 'absent' else True)
                assert stock.matches(56, 0x2134, 0x0800, source) == expected
                checked += 1
    for key in (0, 0x011f0000, 0x000f0000, U32_MAX):
        stock.field(56, 'sif', key, U32_MAX)
        for source in range(32):
            assert stock.matches(56, 0x2134, 0x0800, source) == bool(key & (1 << source))
            checked += 1
    return checked


def check_cpu_rings(path):
    checked = 0
    for etype in (0x0800, 0x86dd):
        cpu = Classifier(path)
        first, second = 54, 55
        cpu.configure(first, 0x2134, etype, False)
        cpu.configure(second, 0xa134, etype, True)
        cpu.force_cpu(first, 1, 2)
        cpu.force_cpu(second, 1, 4)
        saved = {key: value for key, value in cpu.rows.items() if key[1] == second}

        def destinations(gem, source=2):
            return [cpu.rows[2,row,1][2] >> 10 & 31 for row in (first, second)
                    if cpu.matches(row, gem, etype, source)]

        for gem in range(65536):
            expected = {0x2134: [2], 0xa134: [4]}.get(gem, [])
            assert destinations(gem) == expected
            checked += 1
        assert destinations(0x2134, 24) == destinations(0xa134, 24) == []
        cpu.force_cpu(first, 0, 2)
        assert destinations(0x2134) == [] and destinations(0xa134) == [4]
        cpu.field(first, 'GEM_LLID', 0x2135, 65535)
        cpu.force_cpu(first, 1, 2)
        assert destinations(0x2134) == [] and destinations(0x2135) == [2]
        assert destinations(0xa134) == [4]
        assert saved == {key: value for key, value in cpu.rows.items() if key[1] == second}
    return checked


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', required=True, type=Path)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if not __debug__:
        parser.error('assertions are required; omit -O')
    m = Classifier(args.stock_dir / 'ifc.ko')
    a, b = 54, 55
    checked = 0
    for etype in (0x0800, 0x86dd):
        m.steer(a, 6, 0)
        m.steer(b, 8, 0)
        m.configure(a, 0x2134, etype, False)
        m.configure(b, 0xa134, etype, True)
        m.steer(a, 5, 1, 2)
        m.steer(b, 5, 1, 4)
        assert m.rows[2,a,1][2] == 2 << 10 and m.rows[2,b,1][2] == 4 << 10
        m.steer(a, 5, 0, 2)
        m.steer(b, 5, 0, 4)
        m.steer(a, 6, 1)
        m.steer(b, 8, 1)
        for row, gem in ((a, 0x2134), (b, 0xa134)):
            for candidate in range(65536):
                assert m.matches(row, candidate, etype) == (candidate == gem)
                checked += 1
            for src in range(32):
                for encap in (0, 0x10, 0x20, 0x30, 0x400, 0x410, 0x420, 0x430):
                    assert m.matches(row, gem, etype, src, encap) == (src == 2 and not encap)
                    checked += 1
            assert not m.matches(row, gem, 0x0800 if etype == 0x86dd else 0x86dd)
        m.steer(a, 6, 0)
        assert not m.matches(a, 0x2134, etype) and m.matches(b, 0xa134, etype)
        m.field(a, 'GEM_LLID', 0x2135, 65535)
        m.steer(a, 6, 1)
        assert m.matches(a, 0x2135, etype) and not m.matches(a, 0x2134, etype)
        assert m.matches(b, 0xa134, etype)
    report = dict(module=m.sha256, ternary_checks=checked, families=2,
                          cpu_ring_service_checks=check_cpu_rings(args.stock_dir / 'ifc.ko'),
                          sif_checks=check_sif(args.stock_dir / 'ifc.ko'),
                          sif_model='SPORT-indexed key/mask bit',
                          row_replace=True, mmio='emulated')
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
        (args.output / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
