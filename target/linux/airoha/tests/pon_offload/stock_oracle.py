"""Execute SHA-pinned stock PON functions in process-local AArch64 Unicorn.

Only ELF relocations are applied to the stock instructions. Configuration and
kernel helper stubs are enumerated in metadata(); packet mapping/encoding and
PpeSetPortInfo execute from their real function entries through return.
"""
from collections import Counter
from pathlib import Path
import hashlib
import struct

from elftools.elf.elffile import ELFFile
from unicorn import Uc, UC_ARCH_ARM64, UC_MODE_ARM, UC_HOOK_CODE
from unicorn import arm64_const as R

HASHES = {
    'xpon_10g.ko': 'aab0b4191f4db514a04035f0e43fbae073eea44ad834345cbcb899136976e860',
    'hw_nat.ko': 'f8ab9e61d80ce1ace05fc367742be9640c692aa65d8ce20210a9e886769d0d24',
    'qdma_lan.ko': 'd0b13f68803c4c7ffdd6f1723ba01f98d5ae8de5b8cd0c512d78e7cf70d35e35',
    'qdma_wan.ko': '5b4dc829ab92f198546f53fd6e519c343abb46b1d3d497c0062e9ef7650d1685',
}


class Module:
    DATA, STACK, TASK, END, EXTERN = 0x40000000, 0x50000000, 0x51000000, 0x52000000, 0x60000000

    def __init__(self, path):
        self.path = Path(path)
        self.sha256 = hashlib.sha256(self.path.read_bytes()).hexdigest()
        assert self.sha256 == HASHES[self.path.name], ('stock hash', self.path)
        self.cpu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)
        self.calls, self.names, self.stub_calls = {}, {}, Counter()
        self.local_stubs, self.hir = {}, 0xa
        self.qos_remap = 0
        self.instructions = 0
        cpu = self.cpu
        cpu.mem_map(self.EXTERN, 0x100000)
        external_addresses = {}
        with self.path.open('rb') as stream:
            elf = ELFFile(stream)
            symbols = list(elf.get_section_by_name('.symtab').iter_symbols())
            bases = {}
            for idx, sec in enumerate(elf.iter_sections()):
                if not sec['sh_flags'] & 2:
                    continue
                base = 0x10000000 + idx * 0x200000
                assert sec['sh_size'] < 0x200000
                cpu.mem_map(base, max(4096, (sec['sh_size'] + 4095) & ~4095))
                if sec['sh_type'] != 'SHT_NOBITS':
                    cpu.mem_write(base, sec.data())
                bases[idx] = base
                if sec.name == '.text':
                    self.text = base
            def address(sym):
                if sym['st_shndx'] in bases:
                    return bases[sym['st_shndx']] + sym['st_value']
                if sym['st_shndx'] == 'SHN_ABS':
                    return sym['st_value']
                return external_addresses.setdefault(sym.name, self.EXTERN + len(external_addresses) * 64)
            for sym in symbols:
                if sym.name:
                    self.names[sym.name] = address(sym)
            for sec in elf.iter_sections():
                if sec['sh_type'] != 'SHT_RELA' or sec['sh_info'] not in bases:
                    continue
                for rel in sec.iter_relocations():
                    pc = bases[sec['sh_info']] + rel['r_offset']
                    sym = symbols[rel['r_info_sym']]
                    kind = rel['r_info_type']
                    target = address(sym) + rel['r_addend']
                    if kind in (282, 283) and sym['st_shndx'] == 'SHN_UNDEF':
                        self.calls[pc] = (sym.name, kind == 282)
                        continue
                    if kind in (257, 258, 261):
                        if kind == 257:
                            cpu.mem_write(pc, struct.pack('<Q', target))
                        else:
                            cpu.mem_write(pc, struct.pack('<I', (target - (pc if kind == 261 else 0)) & 0xffffffff))
                        continue
                    word, = struct.unpack('<I', cpu.mem_read(pc, 4))
                    if kind == 275:
                        imm = ((target >> 12) - (pc >> 12)) & 0x1fffff
                        word = (word & ~0x60ffffe0) | ((imm & 3) << 29) | ((imm >> 2) << 5)
                    elif kind in (277, 278, 284, 285, 286, 299):
                        shift = {277: 0, 278: 0, 284: 1, 285: 2, 286: 3, 299: 4}[kind]
                        assert not target & ((1 << shift) - 1)
                        word = (word & ~(0xfff << 10)) | (((target & 0xfff) >> shift) << 10)
                    elif kind in (282, 283):
                        word = (word & ~0x3ffffff) | (((target - pc) >> 2) & 0x3ffffff)
                    else:
                        raise AssertionError(('unsupported relocation', kind, hex(pc)))
                    cpu.mem_write(pc, struct.pack('<I', word))
        cpu.mem_map(self.DATA, 0x100000)
        cpu.mem_map(self.STACK, 0x10000)
        cpu.mem_map(self.TASK, 0x1000)
        cpu.mem_map(self.END, 0x1000)
        cpu.reg_write(R.UC_ARM64_REG_SP_EL0, self.TASK)
        cpu.hook_add(UC_HOOK_CODE, self._hook)

    def put(self, addr, fmt, *values):
        self.cpu.mem_write(addr, struct.pack(fmt, *values))

    def get(self, addr, fmt):
        return struct.unpack(fmt, self.cpu.mem_read(addr, struct.calcsize(fmt)))

    def _hook(self, cpu, pc, size, _):
        self.instructions += 1
        if pc in self.local_stubs:
            name, callback = self.local_stubs[pc]
            self.stub_calls[name] += 1
            callback(self)
            cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR))
            return
        if pc not in self.calls:
            return
        name, tail = self.calls[pc]
        self.stub_calls[name] += 1
        if name == 'GET_HIR':
            value = self.hir
        elif name == 'get_frame_engine_data':
            assert cpu.reg_read(R.UC_ARM64_REG_W0) == 0xbfb50f18
            value = 0x8100
        elif name == '__ECNT_HOOK':
            group = cpu.reg_read(R.UC_ARM64_REG_W0)
            command = cpu.reg_read(R.UC_ARM64_REG_W1)
            payload = cpu.reg_read(R.UC_ARM64_REG_X2)
            assert group in (0x11, 0x12) and command == 0 and self.get(payload, '<I')[0] == 0x9c, ('unexpected ECNT hook', group, command)
            # These two QoS queries return their enabled flag at payload+4.
            # A missing hook (-1) retains the stock default 0xff, which enables
            # channel +16 for T-CONT <16; zero explicitly disables remapping.
            if self.qos_remap is None:
                value = -1
            else:
                assert self.qos_remap in (0, 1)
                self.put(payload + 4, '<II', self.qos_remap, self.qos_remap)
                value = 1
        elif name == '_printk':
            value = 0
        else:
            raise AssertionError(('unexpected stock helper', name, hex(pc - self.text)))
        cpu.reg_write(R.UC_ARM64_REG_X0, value & 0xffffffffffffffff)
        cpu.reg_write(R.UC_ARM64_REG_PC, cpu.reg_read(R.UC_ARM64_REG_LR) if tail else pc + size)

    def call(self, name, *args):
        cpu = self.cpu
        cpu.mem_write(self.STACK, bytes(0x10000))
        cpu.reg_write(R.UC_ARM64_REG_SP, self.STACK + 0xf000)
        cpu.reg_write(R.UC_ARM64_REG_LR, self.END)
        for i, value in enumerate(args):
            cpu.reg_write(getattr(R, 'UC_ARM64_REG_X' + str(i)), value)
        cpu.emu_start(self.names[name], self.END, count=100000)
        assert cpu.reg_read(R.UC_ARM64_REG_PC) == self.END, ('stock did not return', name)
        result = cpu.reg_read(R.UC_ARM64_REG_W0)
        return result if result < 0x80000000 else result - 0x100000000


class StockOracle:
    def __init__(self, modules):
        self.tx = Module(Path(modules) / 'xpon_10g.ko')
        self.ppe = Module(Path(modules) / 'hw_nat.ko')
        self.ppe.local_stubs[self.ppe.names['GET_HIR']] = (
            'GET_HIR', lambda m: m.cpu.reg_write(R.UC_ARM64_REG_W0, m.hir))
        tx = self.tx
        tx.put(tx.names['gpWanPriv'], '<Q', tx.DATA + 0x10000)
        tx.put(tx.names['gpPonSysData'], '<Q', tx.DATA + 0x50000)
        tx.put(tx.names['ra_sw_nat_hook_tx'], '<Q', 1)  # enables metadata; function never calls this pointer
        # Local config/mark helpers are outside the target function. Preserve
        # defaults set by gwan_prepare_tx_message: meter=31, shaper=127.
        for off, name in [(0x4aa58, 'skb_mark_helper'), (0x48be8, 'shaper_config'),
                          (0x48cc4, 'meter1_config'), (0x48d94, 'meter0_config'),
                          (0x48e64, 'meter_mode_config')]:
            tx.local_stubs[tx.text + off] = (name, lambda m: m.cpu.reg_write(R.UC_ARM64_REG_W0, 0))

    def tx_message(self, gem, tcont, *, valid=True, alloc_valid=True):
        m = self.tx
        msg, skb, info, wan = m.DATA, m.DATA + 0x1000, m.DATA + 0x2000, m.DATA + 0x10000
        m.cpu.mem_write(msg, bytes(16))
        m.cpu.mem_write(skb, bytes(0x1000))
        m.cpu.mem_write(info, bytes(32))
        m.put(skb + 0xba, '<H', 1)  # selected mapping handle
        m.put(wan + 2 * (1 + 0x38), '<H', 0)  # mapping handle -> entry 0
        m.put(wan + 0x20070, '<I', gem)
        m.put(wan + 0x20074, '<I', 0)  # ANI index
        m.put(wan + 0x20078, '<B', tcont)
        m.put(wan + 0x2007c, '<B', int(valid))
        m.put(wan + 2 * (tcont + 0x18), '<H', 1 if alloc_valid else 0x3ff)
        result = m.call('gwan_prepare_tx_message', msg, 0, skb, 0, info)
        return dict(result=result, msg=list(m.get(msg, '<II')), info=bytes(m.cpu.mem_read(info, 16)).hex())

    def foe(self, gem, tcont, kind=0, *, hir=0xa, tpid=0, sid=0, vlan1=0, vlan2=0, qos_remap=0):
        m = self.ppe
        foe, info = m.DATA, m.DATA + 0x1000
        m.hir, m.qos_remap = hir, qos_remap
        m.cpu.mem_write(m.names['PpeParseResult'] + 0xc, struct.pack('>H', tpid))
        m.cpu.mem_write(foe, bytes(80))
        m.cpu.mem_write(info, bytes(32))
        # Feed real stock TX metadata into the real stock FOE handler.
        tx = self.tx_message(gem, tcont)
        assert tx['result'] == 0
        m.cpu.mem_write(info, bytes.fromhex(tx['info']))
        m.put(foe, '<I', (kind << 25) | ((1 if sid else 0) << 22))
        # PpeSetPortInfo only sets output fields; existing session/VLAN fields
        # are seeded exactly as preceding stock parser stages would provide.
        if kind < 4 and kind != 2:
            m.put(foe + 0x2c, '<H', vlan1)
            m.put(foe + 0x34, '<H', vlan2)
            m.put(foe + 0x3c, '<H', sid)
        else:
            m.put(foe + 0x30, '<H', vlan1)
            m.put(foe + 0x38, '<H', vlan2)
            m.put(foe + 0x3c, '<H', sid)
        m.call('PpeSetPortInfo', foe, info, 0x727a)
        return bytes(m.cpu.mem_read(foe, 80))

    def verify_hqos_hooks(self):
        """Execute each original dispatcher and its command-0x9c getter."""
        results = []
        for side, group, flag in [('lan', 0x12, 'qdmaLanHqosMode'),
                                  ('wan', 0x11, 'qdmaWanHqosMode')]:
            m = Module(self.ppe.path.parent / ('qdma_' + side + '.ko'))
            original_mode = m.get(m.names[flag], '<B')[0]
            assert original_mode == 0
            for mode in (original_mode, 1):
                m.put(m.names[flag], '<B', mode)
                m.put(m.DATA, '<III', 0x9c, 0xdeadbeef, 0xdeadbeef)
                ret = m.call('ecnt_qdma_' + side + '_hook', m.DATA)
                output = m.get(m.DATA + 4, '<II')
                assert ret == 1 and output == (mode, mode), (side, mode, ret, output)
                results.append(dict(module=m.path.name, sha256=m.sha256, group=group,
                                    command=0x9c, original_mode=original_mode,
                                    tested_mode=mode, hook_return=ret,
                                    return_field=output[0], enabled_field=output[1],
                                    instructions=m.instructions, helpers=dict(m.stub_calls)))
        return results

    def verify_tpid_encoding(self):
        """Run both stock conversion entries, then the real port encoder."""
        rows = []
        for tpid, want in [(0, 0), (0x8100, 1), (0x88a8, 2), (0x9100, 0)]:
            host = self.ppe.call('Convert_TPIDtoVPM', tpid)
            network = self.ppe.call('ppe_trans_tpid_to_vpm',
                                    struct.unpack('<H', struct.pack('>H', tpid))[0])
            for kind in (0, 5):
                raw = self.foe(321, 7, kind=kind, tpid=tpid, vlan1=100, vlan2=200)
                encoded = (struct.unpack_from('<I', raw)[0] >> 20) & 3
                assert (host, network, encoded) == (want, want, want)
                rows.append(dict(tpid=tpid, kind=kind, host_vpm=host,
                                 network_vpm=network, port_vpm=encoded))
        return rows

    def metadata(self):
        return dict(mode='actual-stock-AArch64-function-entry-to-return',
                    modules={m.path.name: m.sha256 for m in (self.tx, self.ppe)},
                    functions=['gwan_prepare_tx_message@0x4b7dc', 'PpeSetPortInfo@0x54bb0',
                               'ppe_trans_tpid_to_vpm@0x1073c', 'Convert_TPIDtoVPM@0x22a5c'],
                    stubs={m.path.name: dict(m.stub_calls) for m in (self.tx, self.ppe)},
                    instructions={m.path.name: m.instructions for m in (self.tx, self.ppe)},
                    environment='Optional hook pointers disabled; stock mapping table and skb handle supplied; QoS config helper defaults retained; HIR, outer TPID and explicit QoS remap state supplied per case; real VPM conversion reads a stubbed 0x8100 custom-TPID register; no device I/O')


if __name__ == '__main__':
    import sys, json
    oracle = StockOracle(sys.argv[1])
    for gem, tcont in [(1, 0), (1023, 31), (65534, 17)]:
        print(gem, tcont, oracle.tx_message(gem, tcont), oracle.foe(gem, tcont).hex())
    print(json.dumps(oracle.metadata(), indent=2))
