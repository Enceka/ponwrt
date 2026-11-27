# NPU transaction transport (988)

988 adds AUTH36, ER35 and GATE37 to `airoha_npu.c` through
`airoha_npu_transaction.inc`. `airoha_npu_transaction.h` declares
`airoha_npu_auth_command`, `airoha_npu_er_command` and
`airoha_npu_gate_command`; all three have `EXPORT_SYMBOL_GPL` in the NPU
module for the separate Ethernet module. The ER transport includes
`npu_eth_return_abi.h` directly and has no dependency on the prototype
`airoha_eth_return.h` or `eth_return_core.h`.

The three ABI headers are copied byte-for-byte from this project's firmware.
The ABI remains 1. There are no probe or lifecycle callers in 988, and PON
PPE qualification remains unchanged.

## Contract

| Transport | Accepted capabilities | Success validation |
| --- | --- | --- |
| AUTH36 | 7 | Existing count, inflight, enabled, epoch/generation and operation invariants |
| ER35 | 7, 15 | SPORT24 for 7; SPORT24/SPORT2 for 15; valid shared request state |
| GATE37 | 7, 15 | Mask1 for 7; masks1/4/5 for 15; aggregate queued at most 512/1024 |

ER_QUERY with all six config words zero is capability discovery under both
profiles. This follows `npu_er_control()` returning success before config
validation and `er_mailbox()` querying `npu_er_status(field, raw[6])`.
Its producer is zero because SPORT0 selects no ring; request-state and fault
remain global. Source-specific queries carry SPORT24 or SPORT2. BIND, STOP
and UNBIND never use the zero-config exception.

All transports check the complete immutable echo, exact known capabilities,
reserved reply fields and signed status. Protocol, readiness and transport
errors leave the caller's message unchanged. A structurally valid negative
firmware reply is copied back and its status returned, including an empty
snapshot from validation or semaphore failure. Success-only invariants do
not turn those negative statuses into a false protocol failure. In
particular, an old profile's negative reply to a PON request stays negative.

A successful OPEN must return exactly the requested mask. With caps15,
`GM_ER_FLAGS` aggregates all bound rings: an unselected stopped ring makes
the flags BOUND-only. Single-source OPEN therefore accepts flags1 or3;
mask5 and the caps7 profile require flags3. Selected-source active and
generation checks belong to the firmware OPEN decision. Idempotent OPEN
may observe queued work. QUIET still requires the complete global drain
snapshot, including all ER queues, channel7 completion, TDMA and auth work.

ER reply word11 is the producer for the requested source, not ring occupancy
or a combined producer. It is not bounded by ring size. The future owner
must discover capabilities before mutation, retain per-source consumer,
epoch/generation and lower-device/service ownership, and keep allocations
pinned across failed or ambiguous STOP/UNBIND. Source-specific handles must
share quiesce and global fault handling. Callers retain the existing NPU
lifetime reference while invoking these synchronous functions.

## Run

Requirements: Python3, clang with AddressSanitizer/UndefinedBehaviorSanitizer,
`patch`, and an offline kernel tree through 987. The runner creates a new
output directory, copies only `airoha_npu.c`, applies 988 with zero fuzz and
zero offset, then compiles the actual patched transport. The mailbox,
readiness and DT access are the only transport dependencies stubbed by C.
No firmware build or device access is involved.

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_transaction_transport/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-ifc-tuple-987-source \
  --output /Volumes/Workspace/5585f/build/npu-transaction-988-final \
  --firmware /Volumes/Workspace/5585f/an7581-npu-firmware
```

Use a fresh `--output` path for each run. `--firmware` is optional; it checks
all three ABI headers against that read-only checkout. `--cc`/`CC` and
`--patch`/`PATCH` select host tools. `report.json` records source and patch
hashes, positive runs, exports and mutation results.

The suite checks every immutable word, old/new caps, empty capability QUERY,
both sources, all gate masks, independent source producer values, valid
negative replies, malformed snapshots, readiness/timeouts, QUIET drain
fields, OPEN mask equality and aggregate stopped-ring semantics. Native
and simulated swapped-endian runs exercise the same real functions.
Eight compiled negative controls must fail at runtime, including rejecting
zero-config discovery or valid single-source OPEN, accepting old-profile
PON, unknown caps, wrong OPEN masks, inactive dual OPEN and corrupted AUTH
echo, and imposing the old queued limit on two rings.

## Integration dependencies

OpenWrt applies generic backport/pending/hack patches before the sorted
platform patches. 988 follows 987 and precedes 989/999. It needs the existing
coherent mailbox and verified rebuilt-RAM guard from 950/951, including
`airoha,connac2-rebuilt-ram-lab` readiness. The test input is a prepared
driver extract, not a complete kernel build directory.

The explicit patch/test list in `hg5585f-ct/prepare-overlay.sh` includes
988, 989 and their host regression suites.
Combined AArch64 module compilation and modpost check the kernel integration.
989 supplies the dual-source consumer and service checks; lifecycle
activation and cross-LAN/PON same-tuple FOE isolation remain later work.
