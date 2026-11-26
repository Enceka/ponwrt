#!/usr/bin/env python3
"""Compare the host RX service and port/reason masks to named stock consumers."""
import argparse
import hashlib
import json
import re
import struct
import subprocess
from pathlib import Path

from stock_oracle import Module, R


def stock_rx(m, w0, w1):
    arg, msg, out = m.DATA, m.DATA + 64, m.DATA + 128
    m.put(msg, '<III', w0, w1, 0)
    m.put(arg, '<QQQ', 0, msg, out)
    assert m.call('qdma_api_get_rxmsg_eth', arg) == 0
    gem, = m.get(out + 2, '<H')
    reason, port = m.get(out + 6, '<BB')

    # Execute the INT-2 consumer up to its printk call. Verify both the
    # relocated format string and the value actually passed for %X.
    m.cpu.reg_write(R.UC_ARM64_REG_X21, msg)
    m.cpu.emu_start(m.text + 0x1ec84, m.text + 0x1eca0, count=8)
    assert m.cpu.reg_read(R.UC_ARM64_REG_PC) == m.text + 0x1eca0
    addr = m.cpu.reg_read(R.UC_ARM64_REG_X0)
    fmt = bytes(m.cpu.mem_read(addr, 64)).split(b'\0', 1)[0]
    assert fmt == b'%s: %s [%d]: INT-2: error cpu reason, crsn=%X!\n'
    assert m.cpu.reg_read(R.UC_ARM64_REG_W4) == reason
    return gem, port, reason


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True, help='Patched Linux source tree')
    p.add_argument('--stock-dir', type=Path, required=True)
    p.add_argument('--output', type=Path, required=True)
    args = p.parse_args()
    d = args.source / 'drivers/net/ethernet/airoha'
    eth = (d / 'airoha_eth.c').read_text()
    regs = (d / 'airoha_regs.h').read_text()
    eth_h = (d / 'airoha_eth.h').read_text()
    start = eth.index('static void airoha_qdma_decode_pon_control(')
    decoder = eth[start:eth.index('\n}', start) + 2]
    masks = re.findall(r'^#define QDMA_ETH_RXMSG_(?:GEM|SPORT|CRSN|CHANNEL|OAM|NO_MIC)_MASK\s+[^\n]+', regs, re.M)
    assert len(masks) == 6
    masks += [re.search(r'^#define AIROHA_RXD4_PPE_CPU_REASON\s+[^\n]+', eth_h, re.M).group()]
    sport = re.search(r'static int airoha_en7581_get_dev_from_sport\([^{}]*\)\s*\{\s*(u32 sport = [^;]+;)', eth).group(1)
    rx = eth[eth.index('static int airoha_qdma_rx_process('):]
    reason = re.search(r'\breason = FIELD_GET\([^;]+;', rx[:rx.index('\n}')]).group()
    host = '''#include <stdint.h>
#include <stdio.h>
#include <stdbool.h>
#define BIT(n) (1u << (n))
#define GENMASK(h,l) ((UINT32_MAX >> (31-(h))) & (UINT32_MAX << (l)))
#define FIELD_GET(mask,val) (((val) & (mask)) >> __builtin_ctz(mask))
#define le32_to_cpu(x) (x)
#define READ_ONCE(x) (x)
typedef uint32_t u32;
struct airoha_qdma_desc { u32 msg1; };
struct airoha_pon_ctrl_rx_info { uint16_t id; uint8_t channel; bool oam,no_mic; };
''' + '\n'.join(masks) + '\n' + decoder + '''
int main(void) {
    unsigned w0, w1;
    while (scanf("%x %x", &w0, &w1) == 2) {
        struct airoha_pon_ctrl_rx_info info;
        struct airoha_qdma_desc raw = {w1}, *desc = &raw;
        u32 msg1 = w1, reason;
        ''' + sport + '\n' + reason + '''
        airoha_qdma_decode_pon_control(w0, &info);
        printf("%u %u %u\\n", (unsigned)info.id, sport, reason);
    }
    return 0;
}
'''
    m = Module(args.stock_dir / 'qdma_wan.ko')
    # Cover every pair, each service bit independently, IDs 0 and 0xffff,
    # and bits on either side of the service field (including bit 31).
    cases = [(((port * 2111 + reason * 971) & 0xffff) << 14 | 0xc0003fff,
              port << 21 | reason << 16 | 0xfc00ffff) for port in range(32) for reason in range(32)]
    cases += [(1 << bit, 2 << 21 | 19 << 16) for bit in range(32)]
    cases += [(0x3fffc000, 0), (0, 0)]
    expected = [stock_rx(m, *case) for case in cases]
    assert all(expected[i][1:] == divmod(i, 32) for i in range(1024))
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    src, exe = out / 'decode.c', out / 'decode'
    src.write_text(host)
    subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', str(src), '-o', str(exe)], check=True)
    rows = subprocess.check_output([str(exe)], text=True, input=''.join('%x %x\n' % c for c in cases)).splitlines()
    assert len(rows) == len(cases)
    for case, row, want in zip(cases, rows, expected):
        got = tuple(map(int, row.split()))
        assert got == want, (case, got, want)
    report = dict(cases=len(cases), stock_sha256=m.sha256, host_decoder_sha256=hashlib.sha256(host.encode()).hexdigest(),
                  stock_eth_info_offsets=dict(gem=2, cpu_reason=6, source_port=7), stock_reason_consumer='INT-2@0x1ec84')
    (out / 'result.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
