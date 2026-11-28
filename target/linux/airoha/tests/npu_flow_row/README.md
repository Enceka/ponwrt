# Checked PON Bank0 row operations

ZZ5 adds `airoha_npu_flow_row.h` and calls it from the real diagnostic bind
and install functions. Both helpers require `ppe_lock` and a BIND IPv4
HNAPT template. The caller owns producer quiescence, lifecycle validation,
row reservation and cleanup. These helpers do not enable host learning or
grant an owner permission to replace another flow.

- `airoha_npu_bank0_check_unbound(ppe, hash, expected)` checks Bank0 bounds,
  read ACK, UNB state, packet type, TCP/UDP and the original tuple. NAT output
  fields are not the ingress identity.
- `airoha_npu_bank0_install_checked(ppe, hash, entry, &write_attempted)` requires
  an entirely zero INVALID row, checks the read ACK, submits the copied BIND
  template, checks write ACK, then reads and compares all 80 bytes.
- `write_attempted` describes this invocation. It becomes true before writing
  the SRAM shadow or submitting the write and remains true on every subsequent
  error. A timeout may have written hardware. The caller retains the row and
  its cleanup obligation until verified retirement; a later pre-write failure
  does not cancel an earlier dirty obligation.

The diagnostic caller conservatively marks its cleanup cursor dirty before
calling install under `ppe_lock`, restoring the previous clean cursor only
when no write was attempted. Existing owner/mode/phase checks remain in place.

Run against the SDK snapshot before ZZ5; the runner copies it into the output
directory and applies ZZ5 with exact hunk positions and zero fuzz:

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_flow_row/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-candidate/full-source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/flow-row/suite-new
```

SourceBinding reconstructs the production header chain through ZZ5. The suite
extracts real diag functions and reuses the existing unmodified diag fixture.
The generated copy includes the new header, checks `write_attempted` at the
write boundary and expects the earlier conservative dirty marker on the first
read. All other existing diag assertions run unchanged. Direct helper tests
cover TCP/UDP, Bank0 boundaries, invalid arguments/templates, every original
tuple bit, every empty-row/readback bit, ACK and read/write failures, ambiguous
write completion and input/shadow aliasing. Plain and address/undefined
sanitizer builds run the same cases; runtime mutations exercise the checks.
An end-to-end diagnostic case retains ownership after an effective write
times out and cleanup fails, then retries cleanup before releasing references.
Call-site mutations verify that diag cannot bypass UNB checking or discard
the dirty-row obligation.

Only the output copy is patched. No VM, board, original source, old test suite
or ordinary host ownership gate is modified.
