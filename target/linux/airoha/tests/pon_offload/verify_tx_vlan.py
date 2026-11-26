#!/usr/bin/env python3
"""Exercise the production software TX VLAN classifier and GEM lookup."""
import argparse
from pathlib import Path
import subprocess
import tempfile


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', type=Path, required=True)
    args = p.parse_args()
    source = (args.source / 'drivers/net/ethernet/airoha/airoha_eth.c').read_text()
    start = source.rindex('\nstatic ', 0, source.index(' airoha_pon_skb_vlan('))
    end = source.index('\n}', source.index('static u32 airoha_pon_select_flow(', start)) + 2
    fixture = Path(__file__).with_name('tx_vlan_test.c')
    with tempfile.TemporaryDirectory() as work:
        d = Path(work)
        (d / 'tx_vlan.inc').write_text(source[start:end])
        subprocess.run(['cc', '-std=c11', '-Wall', '-Wextra', '-Werror', '-O1',
                        '-I', work, str(fixture), '-o', str(d/'test')], check=True)
        subprocess.run([str(d/'test')], check=True)


if __name__ == '__main__':
    main()
