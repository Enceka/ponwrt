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
- ZZ6 adds `airoha_npu_bank0_invalidate_unbound_checked(ppe, hash, expected,
  &write_attempted)`. It copies the BIND IPv4 HNAPT template before reading
  SRAM, validates the UNB original tuple/type/protocol and read ACK, marks
  the attempt before writing zero, checks write ACK and all 80 readback bytes.
  Bank1/out-of-range hashes and invalid arguments/templates return `-EINVAL`,
  an identity/state mismatch returns `-ESTALE`, read timeouts return
  `-ETIMEDOUT`, and ACK/readback failures return `-EIO`. Commit errors propagate.
- `write_attempted` describes this invocation. It becomes true before writing
  the SRAM shadow or submitting the write and remains true on every subsequent
  error. A timeout may have written hardware. The caller retains the row and
  its cleanup obligation until verified retirement; a later pre-write failure
  does not cancel an earlier dirty obligation.

The diagnostic caller conservatively marks its cleanup cursor dirty before
calling install under `ppe_lock`, restoring the previous clean cursor only
when no write was attempted. Existing owner/mode/phase checks remain in place.

Run against the SDK snapshot before ZZ5 or a source with ZZ5 already applied;
the runner copies it into the output directory and applies the missing ZZ5
and ZZ6 patches with exact hunk positions and zero fuzz:

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_flow_row/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-candidate/full-source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/flow-row/suite-new
```

SourceBinding reconstructs the production header chain through ZZ6. The suite
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

The invalidate cases exercise both protocols, all invalid learned states/types,
every original-tuple bit and zero-readback bit, all ACK fields at each operation,
input/shadow aliasing, a complete UNB -> INVALID -> BIND sequence, and refusal
to clear the resulting BIND row. Timeout retries cover both unchanged hardware
and a zero write that took effect despite a failed commit. Runtime mutations
remove identity, ACK, whole-row and attempt-order checks from the real helper.

## Production owner contract

The owner reserves the specific Bank0 row, freezes every producer capable of
relearning it (including shared native/WLAN paths where applicable), drains
in-flight traffic, and revalidates its pinned candidate/serial before calling.
Use the existing owner lifecycle mutex (`flow_offload_mutex`) before `ppe_lock`.
Do not sleep while holding `ppe_lock`; existing atomic control handshakes and
hardware drain polling must retain their bounded timeouts.
Keep the reservation and quiescence through checked invalidate, checked install,
AUTH publication and recovery; snapshot identity and NAT action in stable storage.
The expected original tuple is the ingress identity, while `new_tuple` contains
the action to install. This helper grants no ownership or ordinary host admission.

Premark the owner's row as dirty before the operation and retain that obligation
on every error, including a failure before writing. Never assign the durable dirty
flag from `write_attempted`: that output describes only the current call. A commit
timeout can leave zero in hardware, so an invalidate retry can return `-ESTALE`
with `write_attempted == false`. The owner must retain the reservation and perform
its reserved-row recovery/verified cleanup before releasing it; a new BIND row
must never be cleared by retrying this UNB-only helper. Success confirms this row
is zero at readback; installing a new BIND row creates a fresh cleanup obligation.

Diag keeps its ZZ5 flow unchanged. Its UNB bind check runs while learning is open,
before the whole-bank close/drain; its install runs after that clear has already
removed UNB. Neither location is a suitable checked-UNB-invalidate call site.
ZZ6 therefore adds a production-facing inline helper, exercised directly here,
while the actual diag callers continue using the ZZ5 check/install helpers.

Only the output copy is patched. No VM, board, original source, old test suite
or ordinary host ownership gate is modified.
