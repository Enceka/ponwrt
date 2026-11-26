"""Generate stock TX vectors, or compare a target-built GRE encoder with them."""
import argparse
import ctypes
import json
from pathlib import Path
import struct


def stock_vectors(modules):
    from verify_stock_fe import FrameEngine, SessionHost
    fe = FrameEngine(modules / 'fe_core.ko')
    host = SessionHost(modules / 'hw_nat.ko', fe)
    host.hir = 14
    host.put(host.names['ip_proto_chk'], '<H', 1)
    skb, packet, foe, tx_meta = (host.DATA + off for off in (0x400, 0x1000, 0x4000, 0x5000))
    result = {'rows': [], 'links': [], 'hashes': {m.path.name: m.sha256 for m in (fe, host)}}
    parsed, base = (host.names[name] for name in ('PpeParseResult', 'TUNNEL_SWTABLE'))
    for slot in range(64):
        head = base + slot * 88 + 72
        host.put(head, '<QQ', head, head)
    inner = bytes.fromhex('4500001c0033000040110000c0000202c63364031f40232800080000')
    for step in range(32):
        slot = 32 + step
        source = (0x0affff01, 0xc0000201, 0x6440ffff)[step % 3]
        destination = 0x0a01fff0 + step
        macs = bytes((2, step, 2, 3, 4, 5, 6, 7, 8, 9, step, 11))
        header = macs + struct.pack('!HBBHHHBBHIIHH', 0x800, 0x45, step * 7, 52,
                                    (65535 - step * 1771), 0x4000 if step & 1 else 0,
                                    255 - step, 47, 0, source, destination, 0, 0x800)
        host.put(skb + 0x180, '<QQ', packet, packet)
        host.put(skb + 0x12f, '<H', 0x135 + step)
        host.cpu.mem_write(packet, header + inner)
        host.put(foe, '<20I', *([0] * 20))
        fe.writes.clear()
        assert host.call('PpeParseLayerInfo', skb, tx_meta, 0x727a, foe) == 0
        host.bound.add(0x135 + step)
        assert host.get(parsed + 0x120, '<I') == (0x10062 | slot << 17,)
        assert len(fe.writes) == 25
        row = bytes(host.cpu.mem_read(base + 88 * slot, 68))
        result['rows'].append((header.hex(), row.hex()))
        for kind in (0, 1):
            for seed in (0, 0x55, 0xaa, 0xff):
                original = bytearray([seed] * 80)
                struct.pack_into('<I', original, 0, kind << 25)
                host.cpu.mem_write(foe, bytes(original))
                host.call('PpeSetTunnel_Info', foe)
                result['links'].append((slot, original.hex(), bytes(host.cpu.mem_read(foe, 80)).hex()))
    host.put(skb + 0x180, '<QQ', packet, packet)
    host.put(foe, '<I', 0)
    assert host.call('PpeParseLayerInfo', skb, tx_meta, 0x7297, foe) == 0
    assert host.get(parsed + 0x120, '<I') == (0x70072,)
    return result


def compare(library, vectors):
    lib = ctypes.CDLL(str(library.resolve()))
    lib.gre4_row.argtypes = (ctypes.c_void_p, ctypes.c_bool, ctypes.c_void_p, ctypes.c_size_t)
    lib.gre4_link.argtypes = (ctypes.c_void_p, ctypes.c_bool, ctypes.c_uint)
    for wire, reference in vectors['rows']:
        prefix = bytes.fromhex(wire)
        row = ctypes.create_string_buffer(bytes([0xa5]) * 68, 68)
        assert lib.gre4_row(row, True, prefix, len(prefix)) == 0 and row.raw.hex() == reference
    for slot, original, expected in vectors['links']:
        entry = ctypes.create_string_buffer(bytes.fromhex(original), 80)
        assert lib.gre4_link(entry, True, slot) == 0 and entry.raw.hex() == expected
    canary = bytes([0xa5]) * 68
    rejected = 0
    for offset, replacement in [(12, b'\x81\x00'), (12, b'\x88\x64'), (14, b'\x46'),
                                (20, b'\x20\x00'), (23, b'\x11'), (34, b'\x20\x00'),
                                (36, b'\x65\x58'), (36, b'\x86\xdd'), (0, b'\x01')]:
        bad = bytearray(prefix)
        bad[offset:offset+len(replacement)] = replacement
        row = ctypes.create_string_buffer(canary, 68)
        assert lib.gre4_row(row, True, bytes(bad), len(bad)) < 0 and row.raw == canary
        rejected += 1
    for encap, length in [(True, n) for n in range(38)] + [(False, 38)]:
        row = ctypes.create_string_buffer(canary, 68)
        assert lib.gre4_row(row, encap, prefix, length) < 0 and row.raw == canary
        rejected += 1
    for kind, flags, slot, encap in ([(k, 0, 32, True) for k in range(2, 8)] +
                                    [(0, 1 << 23, 32, True), (0, 0, 3, False), (1, 0, 32, False),
                                     (0, 0, 31, True), (1, 0, 64, True)]):
        initial = struct.pack('<I', kind << 25 | flags) + bytes([0xca]) * 76
        entry = ctypes.create_string_buffer(initial, 80)
        assert lib.gre4_link(entry, encap, slot) < 0 and entry.raw == initial
        rejected += 1
    print(json.dumps(dict(stock_rows=len(vectors['rows']), stock_links=len(vectors['links']),
                          rejected_without_modification=rejected, hashes=vectors['hashes'])))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--stock-dir', type=Path)
    mode.add_argument('--library', type=Path)
    parser.add_argument('--vectors', type=Path, required=True)
    args = parser.parse_args()
    if args.stock_dir:
        args.vectors.write_text(json.dumps(stock_vectors(args.stock_dir)) + '\n')
    else:
        compare(args.library, json.loads(args.vectors.read_text()))
