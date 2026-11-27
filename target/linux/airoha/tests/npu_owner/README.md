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
attempt. Normal activation remains gated by `ct_pon_qualified`. Patch `999-z`
adds atomic admission revocation and periodic owner health checks; `999-za`
blocks host learning into the claimed bank and validates native IP learning
against its physical source bank. Patch `999-zc` retires old host bank1 cookies
and clears the owned bank before reuse. Activation still requires completing
ingress-domain classification and hardware-reset DMA retirement. Boot and
ordinary PON configuration still use existing paths.

Run against a kernel source tree containing patches through `999`:

```sh
python3 target/linux/airoha/tests/npu_owner/verify.py \
  --source /absolute/path/to/linux-after-999 \
  --output /absolute/path/to/results/npu-owner
```

Add `--health` for a kernel tree with
`999-z-net-airoha-monitor-npu-owner-invalidation.patch` applied:

```sh
python3 target/linux/airoha/tests/npu_owner/verify.py --health \
  --source /absolute/path/to/owner-source-health \
  --output /absolute/path/to/results/npu-owner-health
```

Omitting `--health` keeps the original `999` regression mode. The health mode
reconstructs the added and changed production headers from `999-z`, applies
them with zero patch fuzz, and compares them byte for byte with the supplied
tree before compiling. Each run records the selected patch and source hashes.

Use `--bank1` against a tree containing `999-zc` to include bank1 retirement
and the health matrix:

```sh
python3 target/linux/airoha/tests/npu_owner/verify.py --bank1 \
  --source /absolute/path/to/owner-source-bank1-retire \
  --output /absolute/path/to/results/npu-owner-bank1
```

After GATE QUIET and the bank1 drain, the owner walks the complete host cookie
table. Bank1 L4 cookies lose their candidate link and row hash; legacy L2
parents retain only their non-bank1 subflows. Bank0 bindings and unbound
candidates remain available. All cookie references are detached before the
first row write. Each of the 8,192 bank1 rows is cleared under its own
`ppe_lock` section, with exact read/write completion selectors and a complete
zero readback. A failed row retains its cursor and the owner remains in
PPE_DRAIN. The original register snapshot survives retries.

Restoring bank1 resets the row cursor before the first register write, so
partial reopen failures and later closes also retire NPU rows. Owner release
requires completed cookie retirement and a cursor at the end of bank1. The
claim requires SRAM ownership. These changes add host driver state only.

The `--bank1` matrix exercises these integration boundaries with retirement
and SRAM fault stubs: failed cookie traversal, first/middle/last row retries,
unchanged epoch and snapshot, retained return DMA, repeated close, incomplete
release, and clearing after partial or complete reopen. The separate
`tests/npu_bank1` suite runs the actual cookie and SRAM helper code. Both
suites use ASan/UBSan and require runtime assertions to catch their mutants.

`999-z` embeds a delayed health worker and a monotonic invalidation sequence
in the owner. An atomic invalidation holds `ppe_lock`, latches admission off,
revokes the owned routes and synchronously sends GATE CLOSE with the last
submitted gate identity. The owner, transaction phase and exposed ER DMA stay
allocated until the complete close succeeds. `closed_ack` becomes true only
after transaction drain and ER destruction; preparation clears it before
BIND. Notifications return `-EAGAIN` while that drain is outstanding. A
device-specific notification targets the pinned PON lower, and a NULL device
targets the whole owner.

The worker uses `mutex_trylock` on the flow mutex and retries every 100 ms.
An OPEN owner queries GATE and AUTH, checking mapping, FE state, route state,
qualification and notifier registration both before and after the replies.
It leaves ARM and OPEN commands unchanged during healthy polling. Failures
trigger the complete close and a final route revocation; failure retains
`close_pending` for retry. A concurrent invalidation also keeps close pending
until a later pass closes the new sequence. A successful worker close keeps
the invalidation latch set. Explicit renewal completes close, reclaims closed
routes, and clears the latch only when the generation and invalidation sequence
still match. A saturated sequence remains latched.

CPU fallback with unfinished route or IFC shutdown is retried even when the
owner is already closed and its ring has been retired. Successful recovery
stops repeating those MMIO operations while periodic health monitoring remains
scheduled. The tests cover both operations unfinished and each partial state.

Retirement releases the route and FE ownership, detaches the owner under
`ppe_lock`, marks it retiring, and synchronously cancels its work before free.
The workqueue stub exercises a worker entering during that cancellation while
the flow mutex is held. Failed releases leave the owner and work available
for retry. ER mapping changes synchronously invalidate admission, while a
bad per-packet service or configuration is dropped without changing ownership.

The health matrix injects firmware status and query failures, mapping and FE
health changes, notifier withdrawal, every close transaction boundary, ER
STOP/UNBIND failures and route revocation failures. It checks retained DMA,
exact epoch advancement, notification status, no repeated close after success,
and invalidations during queries, BIND, renewal, and the lock windows before
FE ARM and GATE OPEN. Runtime negative controls independently remove the
latch, sequence, synchronous closure, health checks, retry, renewal fences or
retirement cancellation and must fail an executable assertion. Both modes use
ASan and UBSan.

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
