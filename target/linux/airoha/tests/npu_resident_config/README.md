# HG5585F CT rebuilt static resident preflight

`verify.py` checks a final kernel `.config` and the final DTB selected for the
HG5585F CT rebuilt image. Use it before packaging either a RAM image or a full
image. Supply the kernel build's `.config`, after all Kconfig resolution, and
the image's final merged DTB. OpenWrt's top-level `.config` and target config
fragments are different inputs. The checker records input SHA-256 values so the
image preflight can associate its result with those exact inputs.

Select `--profile pon-full` for the independent production-image loader profile.
The default remains `--profile rebuilt-ram-lab`. PON-full requires both the NPU
and Ethernet nodes to carry only the boolean `airoha,connac2-pon-full`; mixed,
missing, valued or mismatched selectors fail. The RAM mode requires the NPU RAM
selector exclusively. Its Ethernet native-pairs selector remains optional;
when present it must select RAM exclusively. Ordinary-full-test is outside the
resident startup profiles. All configuration, supplier and memory checks below
also run for PON-full. JSON records the requested `selector_profile` and reports
PON profile failures as `dt.pon-full-profile`.

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_resident_config/verify.py \
  --config /absolute/kernel-build/.config \
  --dt /absolute/image-build/final.dtb \
  --dtc /opt/homebrew/bin/dtc \
  --report /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/resident-preflight.json
```

The same `--dt` argument accepts preprocessed DTS or the DTS emitted by
`dtc -I dtb -O dts` / `fdtdump`. DTS requires `dtc`; run the kernel build's CPP
step first for board sources containing C `#include` and binding macros.
`-i DIR` adds a dtc include directory. `--format dtb|dts` overrides automatic
magic-based detection. DTB is preferred for image preflight because it is the
serialized input delivered to the boot path.

The default backend uses `dtc` to validate and normalize the input, then reads
the FDT's binary property values. Without dtc it uses `fdtdump` for DTB input.
Use `--backend fdtdump --fdtdump /path/to/fdtdump` to select that route explicitly;
it reads FDT v17. `DTC` and `FDTDUMP` environment variables supply defaults.
No fdtget, Python package, kernel build, device access or Git operation is needed.
Compilation stays in memory. JSON output paths inside ponwrt are rejected.
Report paths that overwrite either supplied input are rejected too.
`--report -` emits only JSON on stdout.

Exit status is `0` for static checks passing, `1` for failed policy requirements,
and `2` for unreadable inputs, malformed DT, tool failure or CLI/output error.
The JSON `failures` array identifies each failed requirement and its node or
configuration symbol. Independent checks continue after a policy failure.

## Minimal checked graph

- Built-in `NET_AIROHA`, `NET_AIROHA_NPU` and `COMMON_CLK_EN7523`.
  `OF_DYNAMIC`, `OF_OVERLAY`, `KEXEC` and `KEXEC_FILE` must be disabled.
  An absent disabled symbol is accepted, as with an unselected Kconfig
  dependency. Missing built-in symbols, quoted values, duplicates and malformed
  assignments fail. No configuration is edited or synthesized.
- Exact HG5585F CT root compatible list; fixed `/soc` identity mapping;
  ETH at `ethernet@1fb50000`, NPU at `npu@1e900000`, SCU at
  `clock-controller@1fb00000`, and chip-SCU at `syscon@1fa20000`.
  Their compatible values and MMIO ranges match `dts/an7581.dtsi`.
  Matching device compatibles must be unique. Each node and its ancestors
  must be available (`status` absent, `okay` or `ok`).
- ETH `airoha,npu` resolves to that NPU. ETH reset tuples resolve to that
  one-cell SCU supplier, with unique names including `fe`, `pdma` and `qdma`.
  SCU `airoha,chip-scu` resolves to that chip-SCU. This checks the supplier
  identity and tuple shape; reset selector numbers follow the kernel bindings.
- NPU has the boolean `airoha,connac2-rebuilt-ram-lab` and the CT Connac2
  `memory-region-names` list: `binary`, `ba`, `connac2-pkt`, `connac2-host-rx`.
  The four references select distinct available `/reserved-memory` children
  with fixed nonempty `reg`, `no-map`, and no `reusable`. Their ancestors are
  checked too. Pool sizing, overlap, firmware hashes and image contents belong
  to their existing firmware/memory qualification checks.
  With `--profile pon-full`, the NPU and ETH selectors are instead checked as
  described above; the same four reserved-memory references are required.
- Reject `/plugin/` in DTS and overlay fragments, `__overlay__`, `__fixups__`
  or `__local_fixups__` nodes in the submitted tree. A normal `__symbols__`
  table is allowed. Phandles, including `linux,phandle`, must be unambiguous.

The rebuilt selector follows `hg5585f-ct/ram-dts.py` and
`airoha_npu_load_firmware_from_dts()`. The Connac2 memory profile follows
`dts/an7581-fiberhome-hg5585f-ct-connac2.dts`. Firmware-name strings stay under
the driver's existing rebuilt selection logic. Ethernet native-pair/WED/PPE
feature toggles remain separate from resident provider admission. The checker
walks this bounded graph; it does not recursively enumerate all DT suppliers.

## Required before qualification: runtime lifecycle

A passing result is specifically **static config/DT preflight**. Reports always
carry `runtime_lifecycle: requires-separate-qualification` and a separate list
of runtime requirements. Flattened DT encodes the final properties and topology.
Linux `OF_DYNAMIC`/`OF_DETACHED` flags live on runtime nodes; bootloader or
build-time overlay history must be tracked by the image assembly pipeline.
The running driver admission must check live node flags and ancestors.

Driver-core detach is a separate lifecycle constraint. Runtime admission must
check the actual bound driver, owner, bind-attribute policy and the relevant
SCU suppliers/device parents while holding the appropriate device locks.
Built-in drivers close the module-unload route; `suppress_bind_attrs` closes
the driver's sysfs bind/unbind route. Kernel `device_release_driver()`, driver
unregister and parent/platform depopulation still need explicit product
constraints. Managed device links order consumer detach before supplier
detach. They are used together with that product lifecycle policy.

The main startup work owns provider binding, one-shot startup, retained boot
errors, reprobe constraints and runtime admission. The exposure ledger and
shared mailbox quarantine remain part of the retained provider lifetime.
Image qualification requires the startup/fault tests plus that driver-core
lifecycle review. This tool makes no runtime or hardware state changes.

## Regression tests

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_resident_config/test.py \
  --output /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/resident-config-tests-v1
```

The runner requires real `dtc` and `fdtdump`. The output directory must be new
and outside ponwrt. Generated DTBs/DTS, configuration mutations, subprocess logs
and `report.json` stay there. Both entry points run with `-B` to keep Python
bytecode out of the source tree.

The fixture is a small synthetic graph based on the product's node identities
and pool declarations; it is deliberately not a bootable board DT. Its three
reset selector numbers are arbitrary because these tests check routing and
tuple shape. Real dtc compiles each DTB case, and tests invoke the production
CLI with expected exit status and exact failure IDs. Regressions cover each
configuration gate, links/suppliers, unavailable ancestors, rebuilt selection,
pool references, overlay artifacts, malformed inputs and output placement.
PON-full coverage includes all 64 combinations of the three NPU and three ETH
selectors, valued booleans, profile mismatch, supplier/config/memory failures
and DTB, DTS, fdtdump-text and fdtdump-backend inputs.
Positive cases cover symbols, both phandle encodings, omitted statuses,
decompiled DTS, the fdtdump backend and fallback when dtc is unavailable.
