"""Run the stock kernel's GET_HIR and apply its result to the stock FOE writer."""
import argparse
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_MEM_READ, UC_HOOK_MEM_WRITE, UC_MEM_READ
from unicorn import arm64_const as regs

from verify_stock_fe import Module


def stock_hir(image, sample):
    digest = hashlib.sha256(image).hexdigest()
    assert digest == '95fa70306e22e6bef37a8df612c8d3afade7c701ca9379da1330202276aba0e6'
    export = 0xebde04
    entry, name = struct.unpack_from('<ii', image, export)
    assert image.startswith(b'GET_HIR\0', export + 4 + name)
    cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
    cpu.mem_map(0, 0x1400000)
    cpu.mem_write(0, image)
    context, stack, end, scu = 0x2000000, 0x2100000, 0x2200000, 0x1fb00000
    for page in (context, stack, end, scu):
        cpu.mem_map(page, 4096)
    cpu.mem_write(0x1331478, struct.pack('<Q', context))
    cpu.mem_write(context + 8, struct.pack('<Q', scu))
    cpu.mem_write(scu + 0x64, struct.pack('<I', sample))
    accesses = []
    cpu.hook_add(UC_HOOK_MEM_READ | UC_HOOK_MEM_WRITE,
                 lambda _, op, addr, size, *args: accesses.append((op, addr, size)),
                 begin=scu, end=scu + 4095)
    cpu.reg_write(regs.UC_ARM64_REG_SP, stack + 4096)
    cpu.reg_write(regs.UC_ARM64_REG_LR, end)
    cpu.emu_start(export + entry, end, count=128)
    assert cpu.reg_read(regs.UC_ARM64_REG_PC) == end
    assert accesses == [(UC_MEM_READ, scu + 0x64, 4)]
    value = cpu.reg_read(regs.UC_ARM64_REG_W0)
    assert value == sample >> 16
    return value


def foe_cases(module_path, hir, active):
    host = Module(module_path)
    host.hir = hir
    for slot in (32, 63):
        for valid in (0, 1):
            host.put(host.names['PpeParseResult'] + 0x120, '<Q', (slot << 17) | (valid << 16) | 0x62)
            for kind in range(8):
                expected = bytearray([0xa5] * 80)
                struct.pack_into('<I', expected, 0, kind << 25)
                host.cpu.mem_write(host.DATA, bytes(expected))
                host.call('PpeSetTunnel_Info', host.DATA)
                if active and valid and kind in (0, 1, 2, 4, 5):
                    expected[0x28] = 0xc0 | slot
                    offset = 0x22 if kind < 4 else 0x3e
                    struct.pack_into('<H', expected, offset, 0xc005)
                assert host.cpu.mem_read(host.DATA, 80) == expected, (hir, slot, valid, kind)
    return 32


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--hw-nat', type=Path, required=True)
    args = parser.parse_args()
    image = args.image.read_bytes()
    cases = [(0x000e0000, True), (0x000effff, True), (0x000c000e, False)]
    for sample, active in cases:
        hir = stock_hir(image, sample)
        count = foe_cases(args.hw_nat, hir, active)
        print(json.dumps(dict(scu_064=hex(sample), hir=hir, foe_cases=count)))


if __name__ == '__main__':
    main()
