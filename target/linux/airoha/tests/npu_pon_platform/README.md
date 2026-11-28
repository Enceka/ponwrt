# PON full platform profile tests

Run the independent platform suite against the source before ZZ1:

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_pon_platform/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/platform-suite-final
```

The runner copies the snapshot into the output directory and applies the current
`999-zz1-net-airoha-match-pon-full-platform-profile.patch`. All four touched
files require exact hunk positions/context, a GNU patch dry run in `ponwrt`,
and host patch application with zero fuzz and offset. An already patched input
is first reversed in the output copy and then replayed. The original snapshot
and repository files remain unchanged. Input, patch, generated block and
patched-source SHA-256 values are recorded in `report.json`.

`profile_test.c` includes the actual profile block extracted from
`airoha_ppe_init()`, without rewriting its conditions. The 64 ETH/NPU bit
combinations each run with both `ct_requested` states and both allocation
outcomes (256 cases). Another 32 cases cover a missing NPU phandle. The
independent oracle allows no-profile operation and requires exactly one matching
ETH/NPU profile plus CT request before allocating pairs. Tests check error codes,
allocation count/size, native-pair state, and node reference release before
admission/allocation. Nine compiled mutations must fail runtime assertions.
AddressSanitizer, UndefinedBehaviorSanitizer and warnings-as-errors are enabled.

The image test includes the real `image/an7581.mk` in GNU make and expands
`Device/fiberhome_hg5585f-ct`. Its 216 configurations combine PON/rebuilt/full-test
package states (`n`, `m`, `y`), RAM trial, stock firmware and WED selection.
Checks cover selected DTS, package inclusion, initramfs/sysupgrade DTB paths,
RAM image suppression and the explicit PON/RAM/rebuilt/full-test conflicts.

By default, the runner preprocesses and compiles the real inherited PON-full
DTS using the VM's `cpp`, `dtc` and read-only kernel include files. All compiler
outputs go under the host output directory. `--vm` defaults to `ponwrt` and
`--vm-kernel` to `/workdir/pon-npu-989`. The DTB is decoded to verify matching
PON-only ETH/NPU profiles, the ETH NPU phandle, CT compatibility, host-PPE,
WED inheritance and `variant = "pon-full"`. Include hashes are checked before
and after compilation. `--skip-dts` explicitly skips this optional stage and
records that choice. GNU patch verification still uses the VM.

The overlay script is checked with `bash -n` and for the PON-full selection,
patch and DTS entries. This suite does not execute the payload-install workflow;
the integration thread owns the actual `prepare-overlay --pon-full` run.

## Existing regression suites

The following wrapper runs the existing CPU fallback and covered Bank1 route
suites against the final patched source, while keeping their legacy fixed
output paths in an output-only copy of the test tree:

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_pon_platform/verify_regressions.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/full-source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/platform-suite-regressions
```

CPU fallback covers all four ordinary/PON profile flag combinations, absent,
unqualified and qualified PPE state, all four GDM ports and every 16-bit
selector combination. Only unqualified PON or ordinary-full GDM2 PPE
destinations become WAN CPU; qualified PON retains its requested selectors.
Other destinations, unrelated register bits, readback errors and the existing
fallback/fault/retry cases remain checked. Bank1 covered routes run their
existing failure/recovery tests and negative controls with SourceBinding
through ZZ1. Separate logs and an aggregate report are saved by the wrapper.
