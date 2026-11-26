#!/usr/bin/env python3
"""Execute stock AArch64 retirement and candidate C against scripted MMIO.

Only MMIO and delay/platform entry points are stubbed in the actual stock
retirement function. Neither the stock nor candidate path accesses hardware.
"""
import argparse
import shutil
import hashlib
import ctypes as C
import importlib.util
import json
import pathlib
import subprocess
import sys
from collections import Counter

HERE = pathlib.Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--source', required=True, type=pathlib.Path)
parser.add_argument('--stock-dir', required=True, type=pathlib.Path)
parser.add_argument('--output', required=True, type=pathlib.Path)
args = parser.parse_args()
SOURCE = args.source.resolve() / 'drivers/net/ethernet/airoha'
OUTPUT = args.output.resolve()
OUTPUT.mkdir(parents=True, exist_ok=False)
ORACLE = HERE / 'stock_oracle.py'
MODULES = args.stock_dir.resolve()
spec = importlib.util.spec_from_file_location('pon_stock_oracle', ORACLE)
stock = importlib.util.module_from_spec(spec)
spec.loader.exec_module(stock)
stock.HASHES['fe_core.ko'] = '368cd6f4fa5519454b735ceba7d9f4c36316ddf390595ef549cd86912e1c5dc9'
R = stock.R

CMD, TX, RX, BUSY = 0xbfb51520, 0xbfb51524, 0xbfb51528, 0xbfb51570
CMD_MASK = 0x1f3
AGE = (3 << 25) | (3 << 17) | 0xc
TX_INITIAL, RX_INITIAL = 0x55aa55aa, 0xaa55aa55


class MMIO:
    def __init__(self, channel, mode='ready', fail_write=None):
        self.ch, self.mode, self.fail_write = channel, mode, fail_write
        self.bit, self.qmask = 1 << channel, 0xff << ((channel & 3) * 8)
        self.close = 0xbfb560a0 + (channel & ~3)
        self.queue = 0xbfb57280 + (channel & ~3)
        self.regs = {CMD: AGE, TX: TX_INITIAL, RX: RX_INITIAL,
                     BUSY: ~self.bit & 0xffffffff, self.close: 0x12345678,
                     self.queue: ~self.qmask & 0xffffffff}
        self.initial = self.regs.copy()
        self.trace = []
        self.delays = self.samples = self.writes = 0
        self.issued = False
        self.error = None
        if mode == 'occupied':
            self.regs[CMD] |= (((channel + 1) & 31) << 4) | 1

    def read(self, address):
        if address not in self.regs:
            self.error = ('unknown MMIO read', hex(address))
            return 0
        value = self.regs[address]
        if address == CMD and self.issued and self.delays:
            self.samples += 1
            ready = self.mode != 'missing_done'
            if self.mode == 'last_round':
                ready = self.delays >= 9
            elif self.mode == 'too_late':
                ready = self.delays >= 10
            elif self.mode == 'done_flicker':
                ready = self.samples != 2
            if ready:
                value |= 2
            if self.mode == 'wrong_channel':
                value = (value & ~0x1f0) | (((self.ch + 1) & 31) << 4)
        elif address == BUSY and self.issued:
            if self.mode == 'busy' or (self.mode == 'busy_flicker' and self.samples == 2):
                value |= self.bit
        elif address == self.queue and self.issued:
            if self.mode == 'queued' or (self.mode == 'queue_flicker' and self.samples == 2):
                value |= self.qmask
        self.trace.append(['read', address, value])
        return value

    def write(self, address, value):
        self.writes += 1
        self.trace.append(['write', address, value])
        if self.fail_write == self.writes:
            self.trace.append(['dropped_write', address, value])
            return
        self.regs[address] = value
        if address == CMD:
            self.issued = bool(value & 1)
            if self.issued:
                self.delays = self.samples = 0

    def delay(self, us):
        assert us == 1000
        self.delays += 1
        self.trace.append(['delay_us', us])

    def summary(self):
        return {'delays': self.delays, 'command_reads_after_delay': self.samples,
                'writes': self.writes,
                'final': {hex(k): hex(v) for k, v in self.regs.items()}}


class StockRetire(stock.Module):
    def __init__(self):
        super().__init__(MODULES / 'fe_core.ko')
        self.names['retire_core'] = self.text + 0x72d0
        self.io = None

    def _hook(self, cpu, pc, size, unused):
        if pc not in self.calls:
            return super()._hook(cpu, pc, size, unused)
        name, tail = self.calls[pc]
        args = [cpu.reg_read(getattr(R, 'UC_ARM64_REG_W' + str(i))) for i in range(2)]
        if name == 'get_frame_engine_data':
            value = self.io.read(args[0])
        elif name == 'set_frame_engine_data':
            self.io.write(*args)
            value = 0
        elif name == '__const_udelay':
            assert args[0] == 0x418958
            self.io.delay(1000)
            value = 0
        elif name == 'mbi_hang_unlock_by_terminate':
            value = 0
        else:
            return super()._hook(cpu, pc, size, unused)
        self.instructions += 1
        self.stub_calls[name] += 1
        cpu.reg_write(R.UC_ARM64_REG_X0, value)
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)

    def run(self, io, wrapper=False):
        self.io = io
        if wrapper:
            self.put(self.DATA + 4, '<I', 1)
            self.put(self.DATA + 0x20, '<I', io.ch)
            return self.call('fe_api_set_channel_retire_one', self.DATA)
        return self.call('retire_core', 1, io.ch)


READ = C.CFUNCTYPE(C.c_uint32, C.c_uint32)
WRITE = C.CFUNCTYPE(None, C.c_uint32, C.c_uint32)
DELAY = C.CFUNCTYPE(None, C.c_uint32)


class Candidate:
    def __init__(self, lib, io):
        self.lib, self.io = lib, io
        self.callbacks = READ(io.read), WRITE(io.write), DELAY(io.delay)
        lib.candidate_reset(*self.callbacks)

    def call(self, action, channel=None):
        result = self.lib.candidate_call(action, self.io.ch if channel is None else channel)
        assert self.io.error is None, self.io.error
        return result

    def state(self, field):
        return self.lib.candidate_state(field, self.io.ch)


def check_restored(io, *, stock_path=False):
    assert io.regs[TX] == TX_INITIAL and io.regs[RX] == RX_INITIAL
    assert io.regs[CMD] == (0 if stock_path else AGE)
    assert io.error is None, io.error


def main():
    libpath = OUTPUT / 'retire_bridge.so'
    shutil.copyfile(SOURCE/'airoha_pon_retire.h', OUTPUT/'airoha_pon_retire.h')
    shutil.copyfile(HERE/'retire_bridge.c', OUTPUT/'retire_bridge.c')
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O2', '-shared',
                    '-fPIC', str(OUTPUT / 'retire_bridge.c'), '-o', str(libpath)], check=True)
    lib = C.CDLL(str(libpath))
    lib.candidate_reset.argtypes = [READ, WRITE, DELAY]
    lib.candidate_call.argtypes, lib.candidate_call.restype = [C.c_int, C.c_uint], C.c_int
    lib.candidate_state.argtypes, lib.candidate_state.restype = [C.c_uint, C.c_uint], C.c_uint32
    oracle, results = StockRetire(), []
    modes = ['ready', 'missing_done', 'busy', 'queued', 'done_flicker',
             'busy_flicker', 'queue_flicker', 'last_round', 'too_late']
    for channel in range(32):
        for mode in modes:
            a, b = MMIO(channel, mode), MMIO(channel, mode)
            expected = oracle.run(a)
            candidate = Candidate(lib, b)
            actual = candidate.call(1)
            assert actual == (0 if expected == 0 else -110), (channel, mode, actual, expected)
            check_restored(a, stock_path=True)
            check_restored(b)
            assert a.delays == b.delays, (channel, mode, a.delays, b.delays)
            # Extra readbacks/RMWs surround the candidate loop. Compare its
            # stock TX/RX write contract exactly, including failure cleanup.
            aw = [e for e in a.trace if e[0] == 'write' and e[1] in (TX, RX)]
            bw = [e for e in b.trace if e[0] == 'write' and e[1] in (TX, RX)]
            assert aw == bw
            assert candidate.state(0) == b.bit
            assert candidate.state(1) == (b.bit if actual == 0 else 0)
            assert b.regs[b.close] == (b.initial[b.close] | b.qmask)
            assert candidate.call(2) == (0 if actual == 0 else -16)
            if actual == 0:
                assert b.regs[b.close] == b.initial[b.close]
                assert candidate.state(0) == 0
            else:
                # Recovery preserves the first queue byte and succeeds later.
                b.mode = 'ready'
                assert candidate.call(1) == 0
                assert candidate.call(2) == 0
                assert b.regs[b.close] == b.initial[b.close]
            results.append({'channel': channel, 'mode': mode, 'stock': expected, 'candidate': actual})

    # Hardened behavior outside the stock success/failure predicate.
    for channel in range(32):
        io = MMIO(channel, 'wrong_channel')
        assert oracle.run(io) == 0
        io = MMIO(channel, 'wrong_channel')
        candidate = Candidate(lib, io)
        assert candidate.call(1) == -110
        assert candidate.call(2) == -16
        check_restored(io)
        io = MMIO(channel, 'occupied')
        original = io.regs.copy()
        candidate = Candidate(lib, io)
        assert candidate.call(1) == -16
        assert io.regs[CMD] == original[CMD]
        assert io.regs[TX] == TX_INITIAL and io.regs[RX] == RX_INITIAL
        results.append({'channel': channel, 'mode': 'wrong_channel_and_occupied', 'candidate': 'pass'})

    # Drop every write in a successful transaction, then retry using the same
    # state. This covers close, RX/TX setup, command, clear, restore, reopen.
    probe = MMIO(17)
    candidate = Candidate(lib, probe)
    assert candidate.call(1) == 0 and candidate.call(2) == 0
    write_count = probe.writes
    fault_results = []
    for channel in (0, 1, 3, 4, 15, 16, 30, 31):
        for fail in range(1, write_count + 1):
            io = MMIO(channel, fail_write=fail)
            candidate = Candidate(lib, io)
            result = candidate.call(1)
            if result == 0:
                result = candidate.call(2)
            assert result == -5, (channel, fail, result, io.trace)
            assert candidate.state(0) == io.bit
            if candidate.state(2):
                # Other channels cannot consume a failed global restoration.
                other = (channel + 1) & 31
                before = io.regs.copy()
                trace_count = len(io.trace)
                assert candidate.call(1, other) == -16
                assert io.regs == before and len(io.trace) == trace_count
                assert candidate.state(4) == TX_INITIAL
                assert candidate.state(5) == RX_INITIAL
            io.fail_write = None
            assert candidate.call(1) == 0, (channel, fail, io.trace)
            assert candidate.call(2) == 0
            check_restored(io)
            assert io.regs[io.close] == io.initial[io.close]
            assert candidate.state(0) == candidate.state(1) == candidate.state(2) == candidate.state(3) == 0
            fault_results.append({'channel': channel, 'dropped_write': fail, 'result': result, 'retry': 0})

    # Invalid channel is rejected without MMIO; reopen without a completed
    # retire is blocked, and repeated closes keep the original saved byte.
    io = MMIO(17)
    candidate = Candidate(lib, io)
    for channel in (32, 33, 255, 0xffffffff):
        for action in (0, 1, 2):
            assert candidate.call(action, channel) == -22
    assert io.trace == []
    assert candidate.call(0) == 0 and candidate.call(0) == 0
    assert candidate.state(6) == ((io.initial[io.close] >> 8) & 0xff)
    assert candidate.call(2) == -16

    # Restore only the owned byte when neighboring queue configuration changes.
    assert candidate.call(1) == 0
    neighbor_mask = 0xff << 16
    io.regs[io.close] = (io.regs[io.close] & ~neighbor_mask) | (0xed << 16)
    assert candidate.call(2) == 0
    assert io.regs[io.close] & neighbor_mask == 0xed << 16
    assert io.regs[io.close] & io.qmask == io.initial[io.close] & io.qmask

    # A persistent stuck command remains owned through repeated recovery;
    # clearing the hardware fault permits the original snapshot to recover.
    io = MMIO(17, fail_write=5)
    candidate = Candidate(lib, io)
    assert candidate.call(1) == -5
    assert candidate.state(2) and candidate.state(3)
    io.fail_write = io.writes + 2  # close RMW, then pending command clear
    assert candidate.call(1) == -5
    assert candidate.call(2) == -16
    assert candidate.state(4) == TX_INITIAL and candidate.state(5) == RX_INITIAL
    io.fail_write = None
    assert candidate.call(1) == 0 and candidate.call(2) == 0
    check_restored(io)

    # The actual vendor API wrapper discards its internal timeout error.
    wrapper_io = MMIO(17, 'missing_done')
    assert oracle.run(wrapper_io, wrapper=True) == 0
    assert wrapper_io.delays == 10
    output = {'status': 'pass', 'source_sha256': hashlib.sha256((SOURCE/'airoha_pon_retire.h').read_bytes()).hexdigest(), 'stock_module': {'path': str(oracle.path), 'sha256': oracle.sha256},
              'stock_functions': ['.text+0x72d0', 'fe_api_set_channel_retire_one'],
              'stock_stub_calls': dict(oracle.stub_calls), 'stock_instructions': oracle.instructions,
              'differential_cases': results, 'write_fault_cases': fault_results,
              'total_differential': 32 * len(modes), 'total_hardened_channel_checks': 64,
              'total_write_faults': len(fault_results),
              'additional_checks': ['invalid channel has no MMIO', 'repeated close preserves snapshot',
                  'reopen requires successful drain', 'actual wrapper masks timeout',
                  'CHN_RLS MBI aging bits retained', 'TX/RX snapshot retained across failed restore'],
              'environment': 'Actual AArch64 ELF instructions and compiled candidate header; scripted MMIO; no device I/O'}
    (OUTPUT / 'test-results.json').write_text(json.dumps(output, indent=2) + '\n')
    print(json.dumps({k: v for k, v in output.items() if k not in ('differential_cases', 'write_fault_cases')}, indent=2))


if __name__ == '__main__':
    main()
