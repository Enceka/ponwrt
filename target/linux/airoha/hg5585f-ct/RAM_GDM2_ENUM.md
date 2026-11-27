# HG5585F CT: enumerate GDM2 in RAM

Append `--gdm2-enum` to the existing `ram-dts.py FACTORY SHA256` command. It
only changes the generated private RAM DTS; keep the output private because it
contains calibration data. Without the option the original RAM DTS is unchanged.

The profile enables the native GDM2 PON netdev for enumeration. Its unicast MAC
sets the local bit of the factory base and flips bit 7 of the final octet to
keep it distinct from GDM4 (base) and GDM1 (base + 1), including for local
factory addresses. GDM2 has no NAND NVMEM references. NAND, ECC, the xPON MAC,
PCS and BOSA stay disabled. A GPIO hog requests active-high GPIO38/TX_DISABLE
as output high when Linux registers the GPIO controller; bootloader pin state
before that point is outside the DTS. Keep the fiber disconnected for this lab.

The expected scope is a registered, carrier-down `pon0`. With no line
controller, the PON open path returns `ENODEV`. Enumerating it reserves GDM2
against the GDM3/4 hardware QoS loopback. Use this profile for RAM netdev
enumeration; optical RX and offload acceptance follow separately.

Run the offline regression with a prepared PonWrt kernel include directory,
`cpp`, `dtc` and `fdtget`:

```sh
LINUX_INCLUDE=/path/to/prepared/linux/include python3 test_ram_dts_gdm2.py -v
```

`CPP`, `DTC` and `FDTGET` select explicit tool paths. For the prepared VM:

```sh
orb -m ponwrt env PYTHONDONTWRITEBYTECODE=1 \
  LINUX_INCLUDE=/workdir/gre-board-vvGJbf/include \
  DTC=/workdir/gre-board-vvGJbf/scripts/dtc/dtc \
  python3 target/linux/airoha/hg5585f-ct/test_ram_dts_gdm2.py -v
```

The five tests use synthetic factory bytes and temporary DTBs. They cover
unchanged output for the default, Connac2 and Connac2 RX profiles; disabled
optical/NAND nodes and GPIO38 output-high; six global/local MAC and carry
cases; and eight invalid-input/option cases. Whole-tree DTB comparisons check
that only GDM2's status/MAC/NVMEM properties and the GPIO hog change. These
comparisons retain the baseline phandle assignments explicitly because
removing GDM2's NVMEM reference can otherwise change dtc's assigned numbers.

For an existing native-pairs/WED RAM test, preserve the complete FDT from its
verified FIT. Decompile `fdt-1`, append only the generated `&gdm2` and
`&en7581_pinctrl` overrides, and rebuild with CPP and dtc. CPP needs
`dt-bindings/gpio/gpio.h` for `GPIO_ACTIVE_HIGH`. Keep the original phandles,
calibration, reserved memory, firmware selections and all other properties.
Compare every node and property against the extracted FDT: the only new node
is the GPIO hog, and GDM2 only changes status, local MAC and NVMEM references.
The kernel/initramfs and FIT hashes remain the responsibility of the RAM image
packing step.

The reviewed full-profile DTB is in VM directory
`/workdir/hg5585f-gdm2-enum-20261127.j4nfq_xg/`:

- `gdm2-enum.dtb`: SHA256
  `4f1d66be5af8ade1dbe33a4a465e0303333204183d34358e88431f985d7c3c48`.
- `gre4-original.dtb`: FDT extracted from
  `/Volumes/Workspace/5585f/build/gre-board.S2d31l/gre4-ram.itb`;
  FDT SHA256
  `4684709bc1e687183d954978db4c9e2bc6bf36f66002d1524c86f7c9480e85e9`.
- `gdm2-enum.dts`, `gdm2-enum-expanded.dts`, `dtc.log` and
  `verification.json`: source, CPP expansion, compiler output and whole-tree
  verification.

This artifact retains all original native-pairs, WED, host-PPE and probe-seed
properties. Its only additions are the GDM2 enumeration changes and explicit
GPIO38 TX_DISABLE hog. It contains the board's original calibration and stays
in the private VM output directory.
