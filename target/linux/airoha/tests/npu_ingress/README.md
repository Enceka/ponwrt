# PON NPU ingress classifier transaction

`999-zd` adds `airoha_npu_ingress.h`. It prepares SPORT2 IPv4/IPv6 rows
56/57 that send packets to PSE6, channel7. Firmware AUTH checks the complete
service, tuple and encapsulation before reinjection into bank1. The GDM2
default must stay on its CPU receiver: a direct PPE2 default can match an
existing bound tuple before firmware sees the packet.

This component implements row encoding, publication, readback audit and
restoration. The Linux owner still needs to connect it to source-scope
closure/opening and AUTH/GATE/ER readiness. PON qualification remains off.

## Caller contract

- The lifecycle owner serializes all calls and exclusively reserves optical
  rows 56–59. The existing row owner snapshots all four disabled rows; only
  56/57 are changed. A dirty or active peer pair returns `-EBUSY`.
- Keep SPORT2 classification disabled and its GDM2 default on CPU throughout
  prepare, replacement, recovery and restore. Opening ingress is a separate
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
| `airoha_npu_ingress_prepare()` | Validates both LUT indexes, snapshots once, publishes rows56/57, then audits both complete rows. Replacement retains the original snapshot. |
| `airoha_npu_ingress_check()` | Requires the exact owned pair and compares all 48 hardware words, including unused TCAM fields and action flags. Transport failure retains pending I/O; mismatched words return `-EUCLEAN`. |
| `airoha_npu_ingress_restore()` | Restores changed rows with original actions last, drains pending commands and releases the snapshot only after success. Repeated completed restoration is harmless. |

Source selection is `{BIT(2), U32_MAX}` using the verified SPORT-indexed SIF
predicate. The type0 rules match outer IPv4/IPv6 and exclude VLAN and PPPoE.
Service is deliberately wildcarded so cross-service tuples reach the
firmware's full authorization check. Action page0 selects PSE6, page1 forces
destination and channel7, and page2 enables the rule and stops classification.
It does not select forceCPU or PPE2. Other traffic follows the CPU default.

## Validation

From the enclosing workspace:

```sh
/usr/bin/python3 -B build/ponwrt/target/linux/airoha/tests/npu_ingress/verify.py \
  --source build/pon-er-consumer-20261127/owner-source-bank1-retire \
  --stock-dir build/stage2/zip/root/lib/modules \
  --output build/pon-er-consumer-20261127/npu-ingress-validation
```

The output directory must be new. Dependencies are Python3, Unicorn,
pyelftools, patch and Clang with ASan/UBSan. The runner applies the production
patch exactly in its output tree and compiles the unchanged header with the
existing production row owner. It does not access devices.

The stock oracle executes the SHA-pinned original `ifc.ko` named field
setters and `ifc_set_action_forcePort`; only architecture and interface
behavior are reused. All 64 family/LUT combinations compare all 27 stored
words. Predicate checks cover all 32 sources, all 65,536 service IDs in both
families, VLAN/PPPoE flags, EtherType misses and selected/unrelated LUT hits.

The C harness verifies publication ordering, original snapshot retention,
untouched peer rows, repeated replacement and complete restoration. It
injects failures before effects, after effects and with delayed completion
at every initial prepare, replacement, audit and restore command. Recovery
includes two failed drains, a late write completed during a failed drain,
then either republish or direct restore. Every bit of each audited hardware
word is independently corrupted. Four encoding mutations must differ from
the executed stock output; eight control-flow mutations must compile and
fail a runtime assertion.

The completed run passed 2,773 scenarios, 1,188 transport faults,
1,260,874 C checks and 285,056 predicate checks; all 12 negative controls
were caught. It includes direct restoration after each of the 48 audited
words is corrupted, leaving the corrupted value present until restore.
Evidence is in `build/pon-er-consumer-20261127/npu-ingress-final` relative
to the enclosing workspace. The runner records patch, production header,
dependency and test hashes in `report.json`.

`kernel_test.c` also compiles the actual prepare/restore paths through the
Linux 6.18.60 AArch64 build with GCC 14.4.0. Copy this fixture and its
Makefile to a VM output directory, apply 999-zd to the kernel tree, and run
the normal kernel make command with `M=OUTPUT_DIRECTORY kernel_test.o`.
The 2026-11-27 build completed without warnings; its log is
`build/pon-er-consumer-20261127/npu-ingress-kernel-build.log`. This is an
object compilation check; the component has not been connected to live
owner routes or included in a newly flashed image.
