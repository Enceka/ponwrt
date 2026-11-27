# Optical CPU classifier row owner

Patch 976 adds only `airoha_ct_pon_ifc_owner.h`, including the words header from
975. It manages TCAM bank 0 and action bank 2, rows 56–59. Slot 0 uses rows
56/57 and slot 1 uses rows 58/59, with IPv4 followed by IPv6. It prepares no
scope or PPE changes and provides no user setter.

Zero-initialize `struct airoha_ct_pon_ifc_owner` before its first use. The
`dirty` and `active` fields are four-row bitmaps: slot 0 is `0x03`, slot 1 is
`0x0c`. A slot becomes active only after both enabled actions have been
acknowledged. All calls for an owner must be serialized by its kernel caller.

The I/O interface supplies an opaque context and three callbacks:

- `read(ctx, bank, row, page, words, count)` reads a complete hardware page.
- `put(ctx, bank, row, page, const words, count)` writes a page and acknowledges
  it only after readback verification.
- `drain(ctx)` waits for earlier commands to finish before admitting another
  command. A failed drain leaves the transport pending.

TCAM pages 0–8 contain two words each; action pages 0/1/2 contain 2/3/1 words.
The unused padding in each saved words structure is zero. The owner retains
the full original hardware words throughout every update and retry.

| API | Operation and reservation lifetime |
| --- | --- |
| `airoha_ct_pon_ifc_snapshot(owner, io)` | Reads all four rows, accepts only disabled original actions, then sets `saved_valid`. A repeated snapshot returns `-EBUSY` while the reservation is held. |
| `airoha_ct_pon_ifc_publish(owner, io, slot, rows)` | Requires a valid snapshot and two enabled candidate actions. Marks the pair dirty, disables both actions, writes every TCAM and action 0/1 dependency, then enables both actions. Other-slot words and active bits remain intact. |
| `airoha_ct_pon_ifc_withdraw(owner, io, slot)` | Disables and restores the selected pair, with original action 2 last. Clears that pair's dirty/active bits and retains `saved_valid`, including when both slots have been withdrawn. |
| `airoha_ct_pon_ifc_restore(owner, io)` | Disables every remaining dirty action before restoring any key. Restores all dirty dependencies, then original action 2. Releases `saved_valid` only after complete success. An empty owner is safe to restore repeatedly. |

Any read or put error immediately sets `pending` and returns the callback's
error. No subsequent command is issued in that call. Before the next I/O,
the owner calls `drain`; a drain error returns immediately with shadow and
dirty state intact. Failed snapshot recovery can also be drained by
`restore()` even when no valid shadow was established.

Dirty bits are set before any possible write and are retained until each row
has been fully restored. A failed final action restore keeps that row dirty,
including when the write reached hardware before reporting an error. Retrying
withdraw closes both rows again; retrying global restore closes all remaining
dirty rows again before changing dependencies. Original actions were disabled
at snapshot, so completed restoration returns those rows to disabled state.

The kernel caller owns scope closure, classifier/LUT dependencies, admission
and recovery scheduling. It must contain a failed publication before admitting
traffic; a timed-out command can have reached hardware even though its slot
was never marked active.

Run against a source tree with patches 975 and 976 applied:

```sh
python3 -B target/linux/airoha/tests/pon_offload/verify_ifc_owner.py \
  --source /path/to/linux --output /path/to/new/results
```

The runner compiles and executes the actual production headers in plain and
ASan/UBSan modes. The simulated transport checks row bounds, page sizes, dirty
ownership before every put, disabled-and-acknowledged actions before any key
change, and complete dependency acknowledgements before the final actions.
It compares original shadows and all hardware words, including the untouched
peer slot, throughout publication, withdrawal, failure and retry.

Every position is injected with four failure modes: failure before effect,
effect followed by `-EIO`, effect followed by `-ETIMEDOUT`, and timeout with
deferred completion during drain. The tested command counts are 48 snapshot
reads, 26 publication puts per slot, 52 global restoration puts, and 26
withdrawal puts per slot. The primary fault sweep follows every fault with two
failed drains, including one that completes the deferred operation, before a
successful retry. Both initial publication and replacement are covered.
An additional sweep restores the whole owner directly after every publication
and withdrawal fault, including deferred completion during the successful
drain. This covers the caller's stop path without a successful republish or
withdrawal in between.

A repeated-failure sweep first fails the final command after its effect, then
fails every I/O position of the retry in each of the four fault modes. It
covers snapshot, publication and withdrawal of both slots, and restoration
with only the final row still dirty. Both failures are followed by failed
drains, and each case ends with a successful retry and full restoration.

The host test supplies the Linux `EUCLEAN` value when the host libc lacks it,
so the same runner works with Clang on Linux and macOS. Sanitizer findings
terminate execution immediately, including undefined behavior.

Twenty negative controls alter only the production header. Every control
must compile successfully and terminate with a C assertion and `SIGABRT`.
Compilation failures, sanitizer failures and source-text failures do not count
as caught runtime mutations. The report includes header/test hashes, command
counts, fault counts and the exact runtime assertion for each control.
