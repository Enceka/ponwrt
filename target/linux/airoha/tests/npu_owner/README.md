# PON NPU lifecycle owner

`993` connects the acknowledged `990` transaction to real driver callbacks:
exclusive GDM routes, AUTH/GATE transport, shared FE QUIESCE, and bank1-only
learning stop and drain. PON mapping updates close an existing owner before
retiring flows. Global shutdown closes it before changing host state and
releases it after hardware restoration. Provider teardown requires retirement.

The internal claim entry requires `flow_offload_mutex`, a running host PPE,
two banks, a published provider with PON gate capability, and idle native FE
policy. It checks that the requested generation fits the 32-bit gate ABI.
Shared FE identities remain 64-bit. Failed transactions preserve the owner,
phase, original bank1 registers, and exact attempted identity for retry.

While claimed, new bank1 BIND publications return `-EBUSY`. Bank0 and row
invalidation keep their existing paths. The claim is explicit; boot and normal
PON updates do not claim automatically. PON qualification remains disabled;
service admission, return preparation and reopening are explicit internal
operations.

`994` adds a PON return consumer owned by the same transaction. Preparation
requires a live GDM2/WAN lower, a valid GPON service table and the current
bridge generation. Delivery checks the complete ring configuration, exact
mapping object and all 16 GEM bits. Fault cutover routes traffic to CPU and
retries failed route writes without releasing the exposed DMA.

An attempted ER bind consumes the epoch even when its ACK is lost. Close
advances the identity, drains the producer, stops and unbinds the exact old
ring, then releases NAPI, the lower reference and deferred fault work. Failed
teardown retains the consumer and resumes without repeatedly advancing its
epoch. Preparation reserves the final epoch for closing and retirement.
This remains an internal explicit entry; optical qualification is unchanged.

`995` validates and publishes complete PON AUTH sets. `996` connects it to
the closed owner: every service must belong to the pinned return mapping,
the FE and ring identities must match, and generation is checked again after
ARM. Any attempted publication consumes the admission attempt until close
completes; malformed inputs send no AUTH command. READY checks current AUTH
count and identity, then checks generation again after the QUERY reply.
The renew entry fully closes the old identity and destroys its return ring
before beginning a new generation. Failed old or new close stages preserve
their attempted identity on retry.

`997` adds exact-identity FE ARM and reserves the final epoch for close.
`998` reopens only GDM2 while keeping the bank1 route owner. `999` connects
bank1 restoration, FE ARM, GATE OPEN and route opening. Every stage checks
the current return mapping, generation, route ownership and fault state,
including after waits and when resuming a partial open. Bank1 register
restoration retains the original snapshot and checks each write; bank0
is unchanged. Route opening revalidates the firmware gate before MMIO.

`airoha_ppe_npu_owner_open_locked()` requires the flow mutex. Call it after
claim/close, return preparation and authorization. Success retains the
owner and return consumer. Failure starts the complete close transaction;
a failed close preserves its phase and DMA resources for another close
attempt. Normal activation remains gated by `ct_pon_qualified`. Atomic
admission revocation, periodic owner health checks, cross-domain flow
isolation and hardware-reset DMA retirement are the next activation
prerequisites; boot and ordinary PON configuration still use existing paths.

Run against a kernel source tree containing patches through `999`:

```sh
python3 target/linux/airoha/tests/npu_owner/verify.py \
  --source /absolute/path/to/linux-after-999 \
  --output /absolute/path/to/results/npu-owner
```

The runner extracts the production owner and transaction headers from the
patches, applies the return-owner extension, checks both applied files byte
for byte, and extracts the actual
FOE commit function from the applied kernel. Clang ASan/UBSan runs argument,
generation, capability, identity, allocation, and protocol-failure scenarios.
Every close stage is retried with its original identity. Tests also cover
partial drain writes, BUSY and EN failures, bank0 preservation, old AUTH
identities, conflicting route owners, and BIND versus invalidation at bank
boundaries. The real global stop and shutdown functions run with a previous
native token and a cold saved EN state; route or FE release failure must resume
retirement without repeating an already completed hardware stop. Seven
intermediate restore failures check that a retry also preserves the completed
native producer stop. Six runtime mutants target the drain bank, snapshot
retention, generation truncation, premature release, and repeated native or
hardware restoration. Return ownership adds capability failures, uncertain
BIND outcomes, mapping changes, all 65,536 GEM values, exact configuration
checks, shutdown ordering, fault-work retries and epoch exhaustion. The
authorization tests cover lost BEGIN/ADD/ARM replies, a generation change
during publication or READY query, failed close retries, generation renewal
and aborting a partial reopen. Reopen tests add register write failures,
uncertain ARM, gate and route failures, generation changes during each
operation, stage retries, and failed ER teardown after a rejected open.
The report includes the check count and runtime mutation results. The return
consumer's NAPI/DMA implementation is tested separately by `eth_return`;
this suite injects its allocation, bind and teardown boundaries.

MMIO and transport boundaries use deterministic fault-injection stubs. The
real GDM helpers, FE owner helpers, and mailbox validators have their own
production-code suites in `bank1_routes`, `npu_fe_owner`, and
`npu_transaction_transport`. `report.json` records input and test hashes;
failed runs remove any previous success report. No device operations run.
