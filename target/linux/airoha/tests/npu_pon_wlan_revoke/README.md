# Production PON WLAN revoke regression

Run from `build/ponwrt` with Python 3, clang, and `patch`:

```sh
python3 target/linux/airoha/tests/npu_pon_wlan_revoke/verify.py \
  --source ../pon-production-session-20261128/source-v2 --mutations
```

The canonical input is `source-v2`, containing ZZ9 and preceding ZZA.
The runner copies four driver files to a temporary directory and applies
`999-zza-net-airoha-preserve-pon-session-on-wlan-revoke.patch` there. Hunk
positions and context must match exactly; offsets, fuzz, and an already
applied patch fail the run. It checks the original source, patch, and test
file bytes again before completion. Temporary sources and executables are
removed automatically. No kernel build, VM, or board is needed.

## Actual functions exercised

`revoke_test.c` is a host harness template. The runner inserts the canonical
FOE layout, masks, port enum, and these complete functions from the replayed
source:

- `airoha_ppe_npu_production_active`
- `airoha_ct_native_pair_revoke`
- `airoha_ppe_ct_flush_wlan`
- `airoha_ppe_ct_wlan_dest`, `airoha_ppe_ct_wlan_entry`
- `airoha_ppe_ct_epoch_locked`, `airoha_ppe_ct_wlan_epoch`
- `airoha_ppe_foe_compare_entry`, `airoha_ppe_ct_bridge_row_matches`
- `airoha_ppe_ct_remove_wlan_flow_locked`, `airoha_ppe_ct_remove_wlan_flow`

The harness calls the real flush → revoke → active chain. Host stubs provide
locks, lists, a hash-table walk, net-device state, and SRAM reads/writes.
Owner notification, legacy `revoke_closed`, pair failure, and bridge fault
close are instrumented boundaries: tests check call order, arguments, error
propagation, and the caller's state changes. Firmware mailbox processing and
hardware fault-close internals belong to their own suites. This suite uses
the current production-active predicate and has no dependency on the retired
production-stats helper.

## Coverage

- All 300 valid band/WCID combinations preserve active exclusive production
  with policy disabled and every native-pair slot unused. Each flush advances
  the epoch once, gates admission during cleanup, then unblocks the station.
- Matching bound IPv4/IPv6 WLAN rows, pending software candidates, and bridge
  source rows are removed. Other bands, WCIDs, and routed egress entries are
  retained. The walk includes `-EAGAIN` and a duplicate entry; cleanup occurs
  once per entry. Hardware writes preserve every byte except the state bits.
- Inactive-owner conditions and each of the 32 occupied native-pair slots use
  the owner-notification/legacy-revoke barrier. Global, LAN1 (band 2, ID 24),
  and invalid WLAN selectors retain this barrier. Notification failure stops
  before legacy revoke; both boundary errors propagate through flush.
- Every valid station at `U32_MAX` invokes pair failure before cleanup, keeps
  its epoch and blocked state, and retains rows. `U32_MAX - 1` advances to the
  terminal epoch without wrapping; subsequent flush fails closed.
- Reused hardware tuples, state, WLAN destinations, and bridge actions are
  preserved. Read/write errors retain the software cookie/hash for retry,
  remove its learning-list membership, and keep admission blocked. Successful
  retry finishes cleanup. Bridge read failure invokes its fault-close boundary.
- Invalid flush arguments, nonhost operation, and stopped-driver CPU-cutover
  prerequisites are checked. Lock stubs enforce mutex-before-spinlock order,
  spinlock-protected row access, and balanced lock release.

## Verified result

On 2026-11-28 against canonical `source-v2`:

```text
plain: PASS: 721 cases, 52368 checks
sanitized: PASS: 721 cases, 52368 checks
```

Both builds use `-Wall -Wextra -Werror`; the second enables AddressSanitizer
and UndefinedBehaviorSanitizer. `--mutations` additionally rejects all 12
targeted regressions: production requirement, global/upper-band/zero-WCID/
upper-WCID bounds, epoch exhaustion, epoch increment, owner notification,
bridge-source cleanup, hardware invalidation, station unblock, and exclusive
policy. Each mutation must compile and fail at runtime.

ZZA SHA-256:
`a05b2155882ae23b68152db94ebaf9b3db68d973f6b31ddd22d690705ffa362b`.
The runner also prints hashes of each extracted source group.
