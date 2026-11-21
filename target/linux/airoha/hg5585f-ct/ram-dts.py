import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Emit a private HG5585F CT RAM trial DTS")
    parser.add_argument("factory", type=Path)
    parser.add_argument("sha256", help="Digest read independently from the board's factory volume")
    parser.add_argument("--connac2", action="store_true")
    parser.add_argument("--connac2-rx", action="store_true")
    args = parser.parse_args()
    if args.connac2_rx and not args.connac2:
        parser.error("--connac2-rx requires --connac2")
    data = args.factory.read_bytes()
    if len(data) != 1 << 20 or hashlib.sha256(data).hexdigest() != args.sha256:
        parser.error("factory size or live digest mismatch")
    eeprom = data[0x1000:0x2000]
    mac = data[0x2000:0x2006]
    if eeprom[:2] != b"\x16\x79" or not any(mac) or mac[0] & 1:
        parser.error("invalid MT7916 EEPROM or base MAC")
    suffix = "-connac2" if args.connac2 else ""
    print(f'#include "an7581-fiberhome-hg5585f-ct{suffix}.dts"')
    for label in ("pnand", "pnand_ecc", "xpon_mac", "hg5585f_bosa", "gdm2", "pon_pcs"):
        print(f'&{label} {{ status = "disabled"; }};')
    print('&{/chosen} { /delete-property/ bootargs-append; };')
    for label, offset in (("gdm4", 0), ("gdm1", 1)):
        addr = (int.from_bytes(mac, "big") + offset).to_bytes(6, "big")
        if addr[0] & 1:
            parser.error("invalid derived GDM MAC")
        print(f'&{label} {{ /delete-property/ nvmem-cells; /delete-property/ nvmem-cell-names; '
              f'local-mac-address = [{addr.hex(" ")}]; }};')
    print('&pcie1 { pcie@0,0 { wifi@0,0 { /delete-property/ nvmem-cells; '
          '/delete-property/ nvmem-cell-names; mediatek,eeprom-data = [')
    for start in range(0, len(eeprom), 32):
        print(eeprom[start:start + 32].hex(" "))
    print(']; }; }; };')
    if args.connac2_rx:
        print('&pcie1 { pcie@0,0 { wifi@0,0 { airoha,connac2-rx; }; }; };')


if __name__ == "__main__":
    main()
