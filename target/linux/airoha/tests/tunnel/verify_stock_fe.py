"""Execute stock FE route setup and host tunnel table programming offline."""
import argparse
import json
from pathlib import Path
import sys

from unicorn import UC_HOOK_CODE
from unicorn import arm64_const as R

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'pon_offload'))
from stock_oracle import Module

BASE = 0xbfb50000
ROUTE = BASE + 0x2010
CTRL = BASE + 0x207c


class FrameEngine(Module):
    def __init__(self, path):
        self.registers = {}
        self.writes = []
        self.polls = self.delays = 0
        self.ready_after = 1
        super().__init__(path)

    def _hook(self, cpu, pc, size, data):
        name, tail = self.calls.get(pc, (None, False))
        if name not in ('get_frame_engine_data', 'set_frame_engine_data', '__const_udelay'):
            return super()._hook(cpu, pc, size, data)
        self.instructions += 1
        self.stub_calls[name] += 1
        address = cpu.reg_read(R.UC_ARM64_REG_W0)
        if name == 'set_frame_engine_data':
            word = cpu.reg_read(R.UC_ARM64_REG_W1)
            self.registers[address] = word
            self.writes.append((address, word))
            if address == CTRL:
                self.polls = 0
        elif name == 'get_frame_engine_data':
            word = self.registers[address]
            if address == CTRL:
                self.polls += 1
                if self.polls >= self.ready_after:
                    word |= 1 << 31
            cpu.reg_write(R.UC_ARM64_REG_W0, word)
        else:
            self.delays += 1
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)


class TunnelHost(Module):
    def __init__(self, path, fe):
        self.fe = fe
        super().__init__(path)

    def _hook(self, cpu, pc, size, data):
        name, tail = self.calls.get(pc, (None, False))
        if name not in ('memset', '__ECNT_HOOK'):
            return super()._hook(cpu, pc, size, data)
        x0, x1, x2 = (cpu.reg_read(reg) for reg in
                      (R.UC_ARM64_REG_X0, R.UC_ARM64_REG_X1, R.UC_ARM64_REG_X2))
        self.instructions += 1
        self.stub_calls[name] += 1
        if name == 'memset':
            assert (x1, x2) == (0, 252)
            cpu.mem_write(x0, bytes(x2))
        else:
            assert (x0, x1, self.get(x2, '<I')[0]) == (0x13, 0, 0x89)
            self.fe.cpu.mem_write(self.fe.DATA, bytes(cpu.mem_read(x2, 256)))
            assert self.fe.call('ecnt_fe_api_hook', self.fe.DATA) == 1
            cpu.mem_write(x2, bytes(self.fe.cpu.mem_read(self.fe.DATA, 256)))
            assert self.get(x2 + 0xf8, '<I') == (0,)
            cpu.reg_write(R.UC_ARM64_REG_X0, 1)
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)


def route_setup(fe):
    entry = fe.names['init_module']
    count = 0
    for hir in (0xa, 0xc, 0xe, 0xf, 0x10):
        for seed in (0, 0xffffffff, 0xa55a5aa5):
            fe.hir = hir
            fe.writes.clear()
            fe.registers = {address: seed for address in
                            (ROUTE, BASE + 0x500, BASE + 0x1500, BASE + 0x1100)}
            # The GET_HIR branch and route writes are inside module init.
            fe.cpu.emu_start(entry + 0x444, entry + 0x4d4, count=256)
            assert fe.cpu.reg_read(R.UC_ARM64_REG_PC) == entry + 0x4d4
            addresses = [addr for addr, _ in fe.writes]
            assert addresses == ([BASE + 0x500, BASE + 0x1500, BASE + 0x1100]
                                  if hir == 0xa else []) + [ROUTE] * 4
            value = seed
            for (_, actual), (mask, bits) in zip(fe.writes[-4:],
                    ((0x1e0, 0xc0), (31, 3), (15 << 21, 0), (31 << 16, 22 << 16))):
                value = (value & ~mask) | bits
                assert actual == value
            count += 1
    return count


def check_tables(host, fe):
    cases = 0
    for slot in (0, 1, 31, 63, 64, 0xffffffff):
        payload = [0xac000000 | ((slot & 255) << 12) | i for i in range(22)]
        if slot < 64:
            host.put(host.names['TUNNEL_SWTABLE'] + 88 * slot, '<22I', *payload)
        for clear in (False, True):
            for ready_after in (1, 3, 4):
                fe.writes.clear()
                fe.delays = 0
                fe.ready_after = ready_after
                logs = fe.stub_calls['_printk']
                op = 'PpeClearTunnel_table_ToHW' if clear else 'PpeSetTunnel_table_ToHW'
                result = host.call(op, slot)
                expected = []
                if slot < 64:
                    words = [0] * 22 if clear else payload
                    for bank, group in [(4, [0, 0, 0, words[0]])] + [
                            (b, words[1 + 4*b:5 + 4*b]) for b in range(4)]:
                        expected.extend(zip((CTRL+16, CTRL+12, CTRL+8, CTRL+4), group))
                        expected.append((CTRL, (bank << 16) | (slot << 8) | 0x11))
                assert fe.writes == expected, (slot, clear, fe.writes, expected)
                assert result == (-1 if slot < 64 else 0)
                groups = 5 if slot < 64 else 0
                assert fe.delays == groups * min(ready_after - 1, 3)
                assert fe.stub_calls['_printk'] - logs == (groups if ready_after > 3 else 0)
                cases += 1
    return cases


def check_rx_dispatch(qdma):
    # Stop at the first instruction of each destination. This fixture tests
    # selection only; skb allocation, reassembly and delivery follow it.
    text = qdma.text
    stops = {0x789c, 0x7c1c, 0x25510, 0x255ac, 0x257f8}
    def stop(cpu, pc, size, data):
        cpu.emu_stop()
    for off in stops:
        qdma.cpu.hook_add(UC_HOOK_CODE, stop, begin=text + off, end=text + off)
    def dest(start):
        qdma.cpu.emu_start(text + start, qdma.END, count=32)
        return qdma.cpu.reg_read(R.UC_ARM64_REG_PC) - text

    count = 0
    for ring in range(32):
        qdma.cpu.reg_write(R.UC_ARM64_REG_W22, ring)
        assert dest(0x7890) == (0x7c1c if ring in (21, 22) else 0x789c)
        for kind in range(8):
            for other_bits in (0, 0xfffffff8):
                qdma.put(qdma.DATA + 16, '<I', other_bits | kind)
                qdma.cpu.reg_write(R.UC_ARM64_REG_X27, qdma.DATA)
                qdma.cpu.reg_write(R.UC_ARM64_REG_W20, ring)
                expected = {(21, 1): 0x255ac, (22, 2): 0x257f8}
                assert dest(0x254ec) == expected.get((ring, kind), 0x25510)
                count += 1
    return count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stock-dir', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    fe = FrameEngine(args.stock_dir / 'fe_core.ko')
    host = TunnelHost(args.stock_dir / 'hw_nat.ko', fe)
    qdma = Module(args.stock_dir / 'qdma_lan.ko')
    result = dict(route_init_cases=route_setup(fe), table_cases=check_tables(host, fe),
                  qdma_rx_dispatch_cases=check_rx_dispatch(qdma),
                  hashes={m.path.name: m.sha256 for m in (fe, host, qdma)})
    args.output.parent.mkdir(exist_ok=True, parents=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
