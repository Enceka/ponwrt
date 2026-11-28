# PON candidate snapshots (ZZ4)

ZZ4 adds a software snapshot API for the future production PON owner worker.
It changes only `airoha_eth.h` and `airoha_ppe.c`; there are no hardware,
mailbox, route, qualification or worker operations.

## Worker API contract

Declared in `airoha_eth.h`:

```c
struct airoha_pon_candidate_snapshot {
	unsigned long cookie;
	u64 serial, generation;
	u32 key[19], service;
	struct airoha_pon_flow_entry mapping;
	struct net_device *ingress, *egress;
	struct airoha_foe_entry data;
};

int airoha_ppe_pon_candidate_snapshot(struct airoha_ppe *ppe,
	unsigned long cookie, struct airoha_pon_candidate_snapshot *snapshot);
int airoha_ppe_pon_candidate_validate(struct airoha_ppe *ppe,
	const struct airoha_pon_candidate_snapshot *snapshot);
void airoha_ppe_pon_candidate_put(struct airoha_pon_candidate_snapshot *snapshot);
```

- The caller holds `flow_offload_mutex` for snapshot and validate. Each performs
  a fresh cookie lookup, then takes `ppe_lock`. No flow-entry pointer escapes.
- Start with a zeroed output, or one cleared by `put`. Failure leaves its bytes
  and device references unchanged. Reusing a live snapshot returns `-EINVAL`.
- Success holds one reference to each netdev. A snapshot has one owner: copying
  the structure does not acquire additional references. `put` releases both and
  clears the structure; it accepts NULL or an already cleared snapshot and needs
  neither lock. Balance every successful snapshot, including stale validation.
- `serial` is allocated at successful candidate publication under `ppe_lock`.
  The per-PPE counter never resets during that PPE object's lifetime and never
  wraps. Exhaustion returns `-EOVERFLOW`; the cookie-first publisher rolls back
  the cookie. Duplicate tuple or cookie insertion failures consume no serial.
- `generation` captures `br_flow_offload_generation()` at snapshot time.
  Validate compares it with the current generation. This is the host flow
  generation, not an AUTH transaction generation or firmware epoch.
- `key` is the original 19-word observed identity; `data` is the complete FOE
  software action template. Validate uses the existing tuple/action comparator,
  preserving NAT, MAC, VLAN, PPPoE and destination metadata. STATE/timestamp
  changes are ignored, including retire clearing STATE. Unbound means software
  `hash == 0xffff`; the template's STATE bits do not establish hardware ownership.
- `mapping` holds the unique current GPON service entry by value (tag including
  GEM/TCONT/pbit, VLAN and pbit mask). Validate compares fields, not table pointer
  or padding. EPON, absent/invalid mappings and ambiguous GEM entries are rejected.
- Both operations require a seen, conflict-free, unbound IPv4 candidate, a live
  pon-full host/native-pairs profile, the PON ingress/controller/WAN-QDMA identity,
  and ready ingress/egress devices in the same namespace. Ordinary/diagnostic
  profiles and sticky CPU fallback are rejected. `ct_pon_qualified` may be false.
- Returns: `0` success, `-ENOENT` missing cookie, `-ESTALE` ineligible or changed
  candidate, `-EINVAL` invalid snapshot argument/ownership state.
- Keep the PPE object alive until the worker is drained and snapshots are put;
  netdev references do not extend PPE lifetime. Reacquire the mutex and validate
  after sleeping or releasing it, immediately before the eventual owner action.
  The future owner transaction must still enforce its own gate/epoch and failure
  handling; this API performs no owner authorization or row binding.

## Offline validation

Use the baseline containing ZZ2/ZZ3, before ZZ4. The output must be a new directory
outside `ponwrt`, separate from the input source. For example, from the workspace:

```sh
python3 build/ponwrt/target/linux/airoha/tests/npu_pon_candidate_snapshot/verify.py \
  --source build/pon-npu-diag-20261127/production-candidate/full-source \
  --output build/pon-npu-diag-20261127/production-candidate/candidate-snapshot-suite-v1
```

The verifier checks exact ZZ3 reverse/replay, applies ZZ4 without offsets or fuzz
to an independent source copy, extracts actual production functions and header
types/prototypes, then compiles with Clang, ASan and UBSan. It tests real cookie
publication, rollback and destruction; snapshot and validation; semantic FOE
action comparison; reference balance; and lock order. Device/table/hash helpers
are host fixtures; hardware access stubs fail immediately if reached.

Cases include same-cookie/same-address reuse, serial exhaustion and retry,
deleted/conflicted/bound entries, profile/carrier/device/mapping/generation
changes, all 19 key words, NAT/L2 actions, table replacement, retire STATE and
timestamp changes, failed-output atomicity, and idempotent put. Expected-failure
lock tests and runtime mutations check that the important guards are exercised.
`report.json` records results, source/patch/function hashes and all commands.
No SDK build, VM or board operation is performed by this suite.
