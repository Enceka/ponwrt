#!/usr/bin/env python3
"""Run the host QDMA learn gate against wire-format optical descriptors."""
import argparse
from pathlib import Path
import re
import signal
import subprocess
import tempfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--source', type=Path, required=True)
    a = parser.parse_args()
    d = a.source / 'drivers/net/ethernet/airoha'
    s = (d / 'airoha_eth.c').read_text()
    gate = s[s.index('static bool airoha_qdma_pon_learnable('):
             s.index('static int airoha_qdma_rx_process(')]
    h = (d / 'airoha_eth.h').read_text() + (d / 'airoha_regs.h').read_text()
    masks = sorted(set(re.findall(r'\b(?:QDMA_ETH_RXMSG|AIROHA_PON_QDMA)_\w+', gate)))
    defines = [re.search(r'^#define ' + name + r'\s+[^\n]+', h, re.M)[0] for name in masks]
    with tempfile.TemporaryDirectory(prefix='pon-rx-learn-') as tmp:
        tmp = Path(tmp)
        src = Path(__file__).with_name('rx_learn_test.c')
        def build(body):
            (tmp / 'production.h').write_text('\n'.join(defines) + '\n' + body)
            subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-I', str(tmp),
                            str(src), '-o', str(tmp / 'test')], check=True)

        build(gate)
        subprocess.run([str(tmp / 'test')], check=True)
        guard = 'rx_qdma != &dev->eth->qdma[1]'
        if gate.count(guard) != 1:
            raise ValueError('expected one optical RX queue guard')
        build(gate.replace(guard, '((void)rx_qdma, false)'))
        result = subprocess.run([str(tmp / 'test')], cwd=tmp, capture_output=True)
        if result.returncode != -signal.SIGABRT or b'learns == before' not in result.stderr:
            raise RuntimeError('wrong-queue negative control missed its assertion')
        print('Wrong-queue negative control detected')


if __name__ == '__main__':
    main()
