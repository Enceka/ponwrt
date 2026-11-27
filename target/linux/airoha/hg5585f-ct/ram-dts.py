import argparse
import hashlib
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description="Emit a private HG5585F CT RAM trial DTS")
    parser.add_argument("factory", type=Path)
    parser.add_argument("sha256", help="Digest read independently from the board's factory volume")
    parser.add_argument("--gdm2-enum", action="store_true",
                        help="Enumerate native GDM2 with a local MAC and TX disabled; keep NAND and optics disabled")
    parser.add_argument("--connac2", action="store_true")
    parser.add_argument("--connac2-rx", action="store_true")
    parser.add_argument("--connac2-host-ppe", action="store_true",
                        help="Enable host PPE in this RAM image (requires Connac2 RX and verified firmware)")
    parser.add_argument("--ct-ppe-probe-seed", action="store_true",
                        help="Initialize CT SRAM during the reset-owned Ethernet probe before publishing ports")
    parser.add_argument("--wed-slot1", action="store_true",
                        help="Describe the slot 1 WED supplier for the MT7916 RAM trial")
    parser.add_argument("--wed-bm-debug", action="store_true",
                        help="Reserve the full slot 1 register block for owned BM selector snapshots")
    parser.add_argument("--firmware-dir", type=Path, help="Directory containing the two packaged NPU binaries")
    parser.add_argument("--native-pairs", action="store_true",
                        help="Enable the native ABI3 RAM path (requires WED slot 1 and rebuilt firmware)")
    parser.add_argument("--rebuilt-firmware-dir", type=Path,
                        help="Directory containing the two installed npu_rebuilt_*.bin files")
    args = parser.parse_args()
    if args.native_pairs and not args.wed_slot1:
        parser.error("--native-pairs requires --wed-slot1")
    if args.native_pairs != bool(args.rebuilt_firmware_dir):
        parser.error("--native-pairs and --rebuilt-firmware-dir must be used together")
    if args.connac2_rx and not args.connac2:
        parser.error("--connac2-rx requires --connac2")
    if args.connac2_host_ppe and not args.connac2_rx:
        parser.error("--connac2-host-ppe requires --connac2-rx")
    if args.wed_slot1 and not args.connac2_host_ppe:
        parser.error("--wed-slot1 requires --connac2-host-ppe")
    if args.ct_ppe_probe_seed and not args.connac2_host_ppe:
        parser.error("--ct-ppe-probe-seed requires --connac2-host-ppe")
    if args.wed_bm_debug and not args.wed_slot1:
        parser.error("--wed-bm-debug requires --wed-slot1")
    if args.connac2_host_ppe != bool(args.firmware_dir):
        parser.error("--connac2-host-ppe and --firmware-dir must be used together")
    if args.connac2_host_ppe:
        manifest = (Path(__file__).resolve().parents[4] / "package/firmware/hg5585f-ct-npu-firmware/SHA256SUMS")
        try:
            hashes = dict(line.split()[::-1] for line in manifest.read_text().splitlines())
            if set(hashes) != {"npu_rv32.bin", "npu_data.bin"}:
                parser.error("incomplete Connac2 firmware identity")
            for name, digest in hashes.items():
                if hashlib.sha256((args.firmware_dir / name).read_bytes()).hexdigest() != digest:
                    parser.error(f"Connac2 firmware digest mismatch: {name}")
        except (OSError, ValueError) as error:
            parser.error(str(error))
    if args.native_pairs:
        manifest = (Path(__file__).resolve().parents[4] / "package/firmware/hg5585f-ct-npu-firmware/SHA256SUMS.rebuilt")
        try:
            hashes = dict(line.split()[::-1] for line in manifest.read_text().splitlines())
            if set(hashes) != {"npu_rebuilt_rv32.bin", "npu_rebuilt_data.bin"}:
                parser.error("incomplete rebuilt native firmware identity")
            for name, digest in hashes.items():
                if hashlib.sha256((args.rebuilt_firmware_dir / name).read_bytes()).hexdigest() != digest:
                    parser.error(f"rebuilt native firmware digest mismatch: {name}")
        except (OSError, ValueError) as error:
            parser.error(str(error))
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
        if args.gdm2_enum and label == "gdm2":
            gdm2_mac = bytearray(mac)
            gdm2_mac[0] |= 0x02
            gdm2_mac[-1] ^= 0x80
            print('&gdm2 { /delete-property/ nvmem-cells; /delete-property/ nvmem-cell-names; '
                  f'local-mac-address = [{gdm2_mac.hex(" ")}]; status = "okay"; }};')
            continue
        print(f'&{label} {{ status = "disabled"; }};')
    if args.gdm2_enum:
        print('''&en7581_pinctrl {
    ram-tx-disable-hog {
        gpio-hog;
        gpios = <38 GPIO_ACTIVE_HIGH>;
        output-high;
        line-name = "ram-pon-tx-disable";
    };
};''')
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
    if args.connac2_host_ppe:
        print('&eth { airoha,connac2-host-ppe; };')
    if args.native_pairs:
        print('&npu { airoha,connac2-rebuilt-ram-lab; };')
        print('&eth { airoha,connac2-ram-native-pairs; };')
    if args.ct_ppe_probe_seed:
        print('&eth { airoha,connac2-ppe-probe-seed; };')
    if args.wed_slot1:
        wed_size = "0x1000" if args.wed_bm_debug else "0xb00"
        description = '''&{/soc} {
    ct_wed_slot1: wireless-offload@1fa03000 {
        compatible = "fiberhome,hg5585f-ct-wed-slot1";
        reg = <0 0x1fa03000 0 WED_SIZE>, <0 0x1fa06400 0 0x400>;
        reg-names = "wed", "wdma";
        interrupts = <GIC_SPI 68 IRQ_TYPE_LEVEL_HIGH>, <GIC_SPI 72 IRQ_TYPE_LEVEL_HIGH>,
                     <GIC_SPI 73 IRQ_TYPE_LEVEL_HIGH>, <GIC_SPI 74 IRQ_TYPE_LEVEL_HIGH>;
        interrupt-names = "wed", "wdma0", "wdma1", "wdma2";
    };
};
&pcie1 { pcie@0,0 { wifi@0,0 { airoha,wed-provider = <&ct_wed_slot1>; }; }; };'''
        print(description.replace("WED_SIZE", wed_size))


if __name__ == "__main__":
    main()
