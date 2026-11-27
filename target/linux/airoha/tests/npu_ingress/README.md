# PON NPU ingress classifier transaction

`999-zd` adds `airoha_npu_ingress.h`. It prepares SPORT2 IPv4/IPv6 rows
56/57 that send packets to PSE6, channel7. Firmware AUTH checks the complete
service, tuple and encapsulation before reinjection into bank1. `999-zm`
adds the existing type0/type1 CPU cover encoding at rows58/59, ring4.
SPORT2 traffic that misses the NPU rows therefore reaches the CPU cover
before falling through to the GDM2 default.

This component implements row encoding, publication, readback audit and
restoration. `999-ze` connects the Linux owner, `999-zk` adds diagnostic
logging, `999-zl` permits normalization of unused TCAM data bits, and
`999-zm` publishes and audits all four rows.

## Caller contract

- The lifecycle owner serializes all calls and exclusively reserves optical
  rows 56–59. The existing row owner snapshots all four disabled rows;
  active/dirty become 15. Bits outside this four-row ownership return `-EBUSY`.
- Keep SPORT2 classification disabled throughout prepare, replacement,
  recovery and restore. Opening ingress is a separate
  operation after successful audit and current AUTH/GATE/ER checks.
- Hold the two existing short-packet LUT leases and verify their UDF/range
  dependencies. Supply distinct IPv4 and IPv6 LUT indexes, each below 32.
  The rows require the corresponding LUT hit to be absent.
- `io.read` returns actual hardware words; `io.put` acknowledges only after
  write/readback verification; `io.drain` completes any previous command.
  An error may follow a hardware effect. Callbacks return zero or a negative
  errno. All callbacks are the same transport used by the optical row owner.
- Retain the owner, original snapshots and LUT leases after any failure.
  Close ingress before retry or restore. A failed audit retains active rows
  for restoration; it never authorizes opening the source scope.

| API | Result |
| --- | --- |
| `airoha_npu_ingress_encode()` | Creates a plain IPv4 or IPv6 row; invalid inputs leave output unchanged. |
| `airoha_npu_ingress_prepare()` | Validates both LUT indexes, snapshots once, publishes CPU cover58/59 before NPU56/57, then audits all four complete rows. Replacement retains the original snapshot. |
| `airoha_npu_ingress_check()` | Requires active/dirty=15, exact TCAM masks and matching selected key bits on all four rows; every action bit remains significant. Transport failure retains pending I/O; significant mismatches return `-EUCLEAN`. |
| `airoha_npu_ingress_restore()` | Restores changed rows with original actions last, drains pending commands and releases the snapshot only after success. Repeated completed restoration is harmless. |

Source selection is `{BIT(2), U32_MAX}` using the verified SPORT-indexed SIF
predicate. The type0 rules match outer IPv4/IPv6 and exclude VLAN and PPPoE.
Service is deliberately wildcarded so cross-service tuples reach the
firmware's full authorization check. Action page0 selects PSE6, page1 forces
destination and channel7, and page2 enables the rule and stops classification.
It does not select forceCPU or PPE2. The following cover rows select
forceCPU/ring4, enable and stop for SPORT2 type0/type1 traffic.

## Validation

From the enclosing workspace:

```sh
/usr/bin/python3 -B build/ponwrt/target/linux/airoha/tests/npu_ingress/verify.py \
  --source build/pon-npu-diag-20261127/kernel-covered-route \
  --through-patch 999-zm-net-airoha-route-covered-pon-npu-ingress.patch \
  --stock-dir build/stage2/zip/root/lib/modules \
  --output build/ponwrt/target/linux/airoha/tests/npu_ingress/.results/through-zm-v1
```

The output directory must be new. Dependencies are Python3, Unicorn,
pyelftools, patch and Clang with ASan/UBSan. Supply a complete generated
source tree. The runner reconstructs all three tested production headers
from their creation patches and subsequent overlays, then compares every
byte with that tree. Patch application rejects offsets, fuzz and failed
hunks. `--through-patch NAME` optionally selects the last patch for a
historical generated tree; the default includes all available patches.
Tests compile the original verified headers. Source and applicable patch
chains are checked again after testing and their hashes enter the report.

The stock oracle executes the SHA-pinned original `ifc.ko` named field
setters and `ifc_set_action_forcePort`; only architecture and interface
behavior are reused. All 64 family/LUT combinations compare all 27 stored
words. Predicate checks cover all 32 sources, all 65,536 service IDs in both
families, VLAN/PPPoE flags, EtherType misses and selected/unrelated LUT hits.

The C harness requires both cover rows to finish publication before any NPU
row write, then verifies original snapshot retention, repeated replacement
and complete four-row restoration. A finite 320-vector classifier matrix
checks all 32 SPORT values against IPv4/IPv6 NPU hits, short-packet misses,
ARP, PPPoE, VLAN and type1 CPU coverage. Removing any active/dirty bit must
reject health checking before transport. The harness
injects failures before effects, after effects and with delayed completion
at every initial prepare, replacement, audit and restore command. Recovery
includes two failed drains, a late write completed during a failed drain,
then either republish or direct restore. Every bit of each audited hardware
word is independently flipped: unused TCAM key bits must succeed, while
changed masks, selected key bits and every action bit must return
`-EUCLEAN`. All four rows and all TCAM/action pages are exercised. The raw
transport has 148 initial-prepare, 100 replacement, 48 audit and 52 restore
boundaries; each has three failure timings and two recovery paths.

The read callback also normalizes unused bits to ones, zeroes or an
alternating pattern without changing the stored hardware image. It
reproduces row56/page1 `{0, 0}` reading as `{0xffffffff, 0}`, then checks
prepare, audit, replacement, original snapshot retention and restoration.
The bit matrix records accepted unused bits and rejected significant key,
mask and action bits separately. Four encoding controls and sixteen runtime
controls include restoring the old whole-word `memcmp` and independently
removing mask or selected-key validation. ZM controls skip cover audit or
publication, reverse publication order, change cover ring/type, and leave
cover rows behind on restore.

`source_binding_test.py --output NEW_DIRECTORY` checks a valid stacked
creation/logging/fix chain and rejects seven independent provenance faults:
wrong source bytes, a missing overlay, shifted hunk, reordered patch, changed
patch, newly inserted overlay and source change during a run. The harness
never edits the supplied production tree. All temporary outputs in these
examples stay inside the ignored `.results/` directory.

`kernel_test.c` also compiles the actual prepare/restore paths through the
Linux 6.18.60 AArch64 build with GCC 14.4.0. Copy this fixture and its
Makefile to a VM output directory, apply 999-zd to the kernel tree, and run
the normal kernel make command with `M=OUTPUT_DIRECTORY kernel_test.o`.
The 2026-11-27 build completed without warnings; its log is
`build/pon-er-consumer-20261127/npu-ingress-kernel-build.log`. This is an
object compilation check. The masked-readback host suite leaves current
kernel compilation and device integration to the main task.
