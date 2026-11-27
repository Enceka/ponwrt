# Shared core0 mailbox quarantine

Run against an expanded kernel tree through `999-zg`:

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_mailbox/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/provider-tests-v4/kernel \
  --output /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/mailbox-tests-final
```

For an integrated tree that already includes ZH, add `--patched`. Output must
be a new directory outside the ponwrt repository. The runner copies only the
required driver sources, applies ZH with zero fuzz and zero offset, and leaves
the supplied source tree unchanged. It does not use Git, devices, or VMs.

The test compiles the verbatim production `__airoha_npu_send_msg()` function,
the normal sender, guard readiness, both WLAN wrappers, the complete transaction
implementation, and the private ER exposure provider. Register definitions and
mailbox enums are extracted from the same production source. Only kernel
primitives, MMIO, timing, and device-side completion are substituted.

The completion model delays coherent response visibility until `dma_rmb()`.
The pthread test parks a caller inside polling while another waits for the
actual transport lock, then verifies that the waiting caller observes the
quarantine before touching registers or the bounce buffer.

Coverage:

- Successive requests clear a pre-existing DONE through the existing CTRL3
  request write before incrementing CTRL2. A failed clear readback stops the
  request before trigger; the next correctly initialized request can retry.
- Each address, length, CTRL3 initialization, CTRL3 readback, and sequence-read
  failure propagates the original errno without a trigger. Write failures are
  tested with and without the write having reached the register.
- Trigger-write ambiguity, polling errors, and timeout latch quarantine under
  the core0 lock. Tests also cover a polling read that reports an error while
  the device concurrently completes the request.
- AUTH, ER, GATE, WLAN SET/GET, the normal sender, and all six outer function
  selectors share the same quarantine. Further requests make no MMIO access,
  no publication barrier, and no host write to the coherent bounce buffer.
- BIND, STOP, and UNBIND timeouts preserve both source exposure records and
  the exact stopped state. A delayed ACK writes back into the retained buffer;
  later commands remain blocked. Setting the guard flags again still leaves
  readiness false. Only a fresh fixture representing a boot clears the latch.
- Definite DONE with a mailbox NACK, or a well-formed ER error reply, remains
  retryable. No response copy occurs on transport failure.
- Native and swapped-endian message modes run under ASan/UBSan. Ten negative
  mutations must compile and fail runtime assertions. They cover quarantine,
  guard withdrawal, response ordering, stale DONE, pre-trigger error handling,
  ambiguous trigger retry, guard revival, and erroneous ER retirement.

`report.json` records input, patched source, patch and test SHA-256 values,
extracted function names, mode results, and negative-test exit status. Log files
and extracted functions accompany it. Full kernel and image integration run
separately in the main task.

## Protocol boundary

The existing sequence trigger is `MBQ0_CTRL(2)`. The status initialization is a
normal `MBQ0_CTRL(3)` write containing function and WAIT_RSP with DONE clear;
ZH uses that same write and checks DONE by reading it back before the sequence
increment. It does not introduce a W1C operation or a new register meaning.
The source basis is patch `949-net-airoha-publish-npu-mailbox-status-before-trigger.patch`
and fixed SDK `32b5aa356c2406edef8806aaf75451ff0a5286f2`,
`linux/arch/arm64/mach-econet/ecnt_npu.c:945`, `:998`, and `:1011`:
zero-initialize the control word, write CTRL0/1/3, advance CTRL2, then poll DONE.

Before the sequence write, an error leaves the attempt retryable. Once the
sequence write is attempted, an uncertain completion permanently sets the
private `transport_quarantined` latch and clears both guard flags. The first
failed request returns its original errno; later low-level sends return
`-ESHUTDOWN`. Guarded AUTH/ER/GATE entry points can return `-EOPNOTSUPP` before
entering the sender, and ER identity checks retain their original errors.
The ER ledger stays owned by ZG. ZH does not clear or retire its records.

## Remaining integration requirements

The quarantine is scoped to the existing provider lifetime. It has no software
reset/unquarantine API. This change implements the shared transport quarantine
alongside ZG's exposure ledger. Production qualification still requires the
fixed-DT/built-in admission checks, constraints on supplier/parent detach and
provider reprobe, and moving master startup after successful provider binding.
These lifecycle requirements remain pending. In particular, provider reprobe
must be prevented from allocating a fresh wrapper while old hardware accesses
remain possible.
