# Shared FE owner ARM

`997-net-airoha-arm-fe-through-npu-owner.patch` adds the private driver helper:

```c
static int airoha_ct_fe_owner_arm(struct airoha_ppe *ppe,
                                const void *owner, u64 generation, u32 epoch);
```

The caller holds `ppe_lock`. Owner, epoch and all 64 generation bits must
match the acknowledged owner QUIESCE. The existing `ct_fe.epoch` and
`ct_fe.generation` retain the ARM identity; no additional state fields are
needed. Native LAN writers remain excluded throughout ownership.

| State | `owner_quiesced` | `arm_pending` | `armed` | ARM behavior |
| --- | --- | --- | --- | --- |
| QUIESCE acknowledged | true | false | false | Send ARM for the exact identity |
| ARM attempted, result ambiguous | false | true | false | Retry the same identity |
| ARM acknowledged | false | false | true | Revalidate through another ARM command |
| QUIESCE pending | false | retained | retained | Reject ARM with `-EBUSY` |

Before sending, ARM clears `owner_quiesced` and `armed`, and sets
`arm_pending`. Every failed send preserves this attempted state. Success
clears `arm_pending` and sets `armed`; `active`, `touched`, saved LAN rows
and LAN health scheduling stay unchanged. Policy activation, existing
native pairs, pending QUIESCE, table ownership and pending PPE drain block
ARM. Stopping, health shutdown, native failure, failed CPU port and sticky
CPU fallback return `-ESHUTDOWN` before a command is sent.

After any ARM attempt, close must advance the epoch before owner QUIESCE.
The helper rejects `U32_MAX` for ARM, reserving it for close. Same-epoch
QUIESCE is rejected before setting its pending identity. Failed QUIESCE
retains its own `pending_epoch/pending_generation` and must retry that
identity. Its acknowledgement clears both pending flags and `armed`, and
sets `owner_quiesced`. Ownership can then be released or the new identity
armed. The lifecycle owner remains responsible for generation/mapping
revalidation and PPE, gate and route ordering around this helper.

Run from the ponwrt repository:

```sh
python3 target/linux/airoha/tests/npu_fe_owner_arm/verify.py
```

`--source` defaults to the local `owner-source-996-final` snapshot.
`--abi-source` defaults to `owner-source-993`, which supplies the unchanged
ABI3 offload header missing from the reduced 996 snapshot. Both accept a
complete kernel source tree. `--firmware` selects the local reconstructed
firmware repository. `--output` optionally retains a JSON report and the
applied production header; all compilation and mutation work uses a
temporary directory. The runner performs no VM or device operations.

The test applies 997 with zero fuzz and offset, compiles the entire FE
header and IFC command header, and extracts the production FE state layout,
host sender and mailbox transport without rewriting their logic. The
firmware's native mailbox and FE command handler run directly against
memory-backed mailbox access, modeled semaphore ownership and the FE
enable/disable hardware boundary. Tests use Linux errno values on macOS
to match numeric firmware responses.

Coverage includes exact owner and 64-bit identity checks, every echoed
request byte, each required capability bit, negative and positive status,
transport loss before and after firmware acceptance, bounded EAGAIN
retries, firmware epoch/QUIESCE/endpoint/fault rejection, every native pair
slot, close failure and recovery, the final close epoch, and native LAN
operation after owner release. Native writers cannot send or access IFC
rows while the owner is held. Fourteen compiled runtime mutants validate
the critical guards and pending-state assertions. Builds and executions
use AddressSanitizer and UndefinedBehaviorSanitizer.
