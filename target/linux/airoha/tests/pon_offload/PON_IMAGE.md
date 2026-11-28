# PON full-image pair preflight

`verify_pon_image.py` checks the recovery FIT and sysupgrade FIT together before
board validation. Run it against files from the same SDK build. It reads images
and configuration, extracts selected squashfs content into a temporary directory,
then writes a JSON success report. PON production admission remains owned by the
production lifecycle; the build provenance currently records
`pon_production_admission: false` and this checker records `board_tested: false`.

## Inputs and invocation

Supply the final kernel config, original uncompressed `initramfs_data.cpio`,
and the source manifest used to generate `/etc/hg5585f-ct-build.json`. The FIT
helper must provide `Fit`, `verify_fit_hashes`, `text` and `integer`; use the
project's existing image helper used for the SDK image inspection. Its SHA256
is included in the result. `--unsquashfs` accepts an executable plus optional
arguments parsed with `shlex`, without a shell.

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/verify_pon_image.py \
  --recovery /absolute/image-build/initramfs-recovery.itb \
  --sysupgrade /absolute/image-build/squashfs-sysupgrade.itb \
  --initramfs-archive /absolute/image-build/initramfs_data.cpio \
  --config /absolute/image-build/kernel.config \
  --source-manifest /absolute/image-build/source.json \
  --image-helper /absolute/tools/image_helper.py \
  --unsquashfs '/absolute/bin/unsquashfs' \
  --output /absolute/evidence/verified-pair.json
```

The output file must be new and outside ponwrt, and its parent directory must
already exist. Input files remain unchanged. A failed check exits nonzero and
does not write a success report. Run with `-B` to avoid Python bytecode in the
repository. Keep generated images, extraction files and reports under `build/`
outside ponwrt.

## Checks

- FIT hashes, default configuration, LZMA/gzip ARM64 kernel, and load/entry
  `0x8a000000`. Recovery has no filesystem or auxiliary load targets.
  Sysupgrade has exactly one filesystem with no `load` or `entry`; an optional
  `loadables` must be exactly that node's single NUL-terminated name. Firmware,
  ramdisk, other targets and target lists are rejected.
- The two DTBs are byte-identical. The real resident verifier runs with
  `pon-full`: final kernel config, matching exclusive NPU/ETH selectors,
  fixed board/devices, supplier links and reserved-memory references.
  The network variant is `pon-full`; persistent NAND/PON/BOSA/GDM2/PCS devices
  are enabled, factory calibration references and PON data-path are present,
  and diagnostic PON mode and inline radio calibration are absent.
- Flash has exactly one `bl2` and one `ubi` partition with the expected offsets
  and sizes, plus `fit` and `factory` volume declarations. Kernel extent,
  FIT staging at `0x90000000`, and reserved-memory ranges fit in
  `0x80000000..0xa0000000` without overlap.
- Recovery contains the supplied raw cpio exactly once. The real newc parser
  checks its framing and safe paths; normalized path aliases cannot duplicate
  entries. Required selected entries must be regular files.
- Stock and PON firmware match package SHA256 pins. Both kernels contain the
  pinned PON loader digests. RAM/ordinary firmware packages are rejected.
  Required XPON, WLAN, WED and flow-table modules must be present.
- Rootfs module and CT NPU firmware inventories match across recovery and
  sysupgrade, including extra-file detection. All modules, pinned firmware,
  network generator/empty network seed, wireless config, authorized keys,
  module startup files and provenance are compared byte-for-byte. Selected
  squashfs entries must be regular files.
- Recovery provenance must equal the supplied source manifest as parsed JSON;
  whitespace and key order may differ. The sysupgrade provenance bytes must
  match recovery. The report records image, DTB, config, helper and source
  manifest hashes together with compared file/module counts.

## Offline regression tests

```sh
cd /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload
python3 -B -m unittest -v test_verify_pon_image
```

The tests require only Python's standard library. FIT parsing/hash delivery and
unsquashfs are stubbed; fixture kernels use real LZMA/gzip, fixture DTBs pass
through the real FDT parser and resident verifier, and raw archives pass through
the real newc parser. Firmware pins and installed contents use isolated temporary
fixtures. Every negative checks the intended failure reason, with positive
baselines for the accepted FIT forms and provenance formatting. Coverage includes
auxiliary targets, DT/profile/device and flash/RAM failures, firmware and loader
digests, raw cpio identity, selected-file types, module/firmware inventories,
cross-rootfs contents, provenance and CLI output protection. Temporary fixtures
are outside the repository and removed after each test.

## Production session in RAM

Before full-image flashing, use `prepare_npu_ram.py` and `pack_npu_ram.py`
with `--profile production-session` to exercise the real `pon_npu_flow`
candidate lifecycle in an isolated RAM system. The default remains
`diagnostic` for existing callers.

Preparation verifies the payload against the package's PON identity and the
RV32 acceptance report. It installs the production firmware names and checks
the canonical production loader digests without rewriting the loader. Optional
`--modules DIRECTORY` replaces existing rootfs modules with rebuilt ARM64
modules of the same kernel release. Use a flat directory containing the
selected `.ko` files; record the build/config and retain required external
WLAN/PON modules from the matching base. The preparation report records every
replacement digest.

Packing requires that exact prepared CPIO embedded in the transferred kernel,
the production session interface and pinned loader digests. It replaces the
paired RAM firmware profile with `connac2-pon-full` on both Ethernet and NPU,
removes the diagnostic marker, and runs the resident verifier for `pon-full`.
The base FIT must retain disabled NAND, ECC, xPON, PCS and BOSA nodes. Other DT
properties, memory reservations and the TX-disable GPIO hog are preserved.
The output is `pon-npu-session-ram.itb`, with `sealed.json` and resident checks.

Use the RAM loopback module's explicit production-session mode for netfilter
candidate admission, observation, hardware UNB learning, binding and withdrawal.
Keep the NAND-enabled recovery pair and its flashing workflow separate from
this RAM-only artifact.

Run preparation/profile regressions with:

```sh
python3 -B -m unittest test_prepare_npu_ram
```

## Recovery boot

`boot_pon_recovery.py` consumes a passing pair report and the exact recovery FIT.
Without `--run` it checks the image digest, resident checks, endpoint configuration
and new output location. With `--run` it verifies the current board boot UUID over
pinned SSH and checks serial access before restarting into U-Boot. It transfers
the FIT into RAM, checks its SHA256 on the board, and starts it with `bootm`.
The U-Boot IP settings are volatile; this command does not flash or save settings.

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/boot_pon_recovery.py \
  --fit /absolute/image-build/initramfs-recovery.itb \
  --evidence /absolute/evidence/verified-pair.json \
  --key /absolute/private-lab-ssh --pin /absolute/current/known-hosts \
  --toolkit /absolute/factory-toolkit --serial /dev/cu.usbserial-11330 \
  --previous-boot CURRENT-BOOT-UUID --output /absolute/evidence/recovery-boot \
  --run
```

Defaults use LAN control on `en6`, `192.168.1.120` to `192.168.1.1`, and transfer
on `en4`, `192.168.6.231` to `192.168.6.221`, UDP port 1069. Both host addresses
and the board's transfer address must exist before restart. The toolkit directory
must contain the project's `live.py` serial, pinned SSH and read-only TFTP helpers.

The output records the serial log, old/new board state and new SSH host pin. A
successful result requires the `pon-full` DT variant, tmpfs root, a changed boot
UUID and successful pinned SSH access. SSH startup retries are bounded. Failures
retain the serial evidence and write `recovery_ready: false`; inspect the current
console state before retrying. After success, use the new pin and boot UUID to
restore the lab WAN and check wireless connectivity. Production offload and
flash acceptance are subsequent checks. Preflight/readiness regressions run with
`python3 -B -m unittest -v test_boot_pon_recovery` in this directory.
