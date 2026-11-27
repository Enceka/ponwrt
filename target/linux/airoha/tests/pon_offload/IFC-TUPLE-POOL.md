# IFC tuple LUT pool helper

`airoha_ct_ifc_tuple_pool.h` adds a reference-counted owner for exact IFC tuple
LUT predicates. It reserves disabled rows, writes predicates, verifies readback,
and restores each row's original contents when its last reference goes away.
The header performs no locking, allocation or kernel registration.

Verified against the headers produced by patches
`980-net-airoha-encode-shared-exact-tuple-lut-predicates.patch` and
`985-net-airoha-share-transactional-ifc-tuple-lut-pool.patch` with
`ifc_tuple_pool_test.c` on 2026-11-27. This covers the helper lifecycle only;
kernel integration and hardware behavior are outside this test.

## API

The pool is caller-owned storage and needs no initializer beyond zeroing it:

```c
struct airoha_ct_ifc_pool pool = {};
struct airoha_ct_ifc_pool_io io = {
	.ctx = device,
	.read = read_row,
	.put = put_row,
	.drain = drain,
};
```

`airoha_ct_ifc_pool_valid(pool, io)` reports whether the pool and all three I/O
callbacks are present. The callbacks are:

```c
int read(void *ctx, unsigned int slot, u32 words[2]);
int put(void *ctx, unsigned int slot, const u32 words[2]);
int drain(void *ctx);
```

The public operations are:

- `airoha_ct_ifc_pool_acquire(pool, io, words, lease)`: reserve or share every
  predicate in `words`, write missing rows, read them back, then publish
  `lease`. Returns `0` on success.
- `airoha_ct_ifc_pool_release(pool, io, lease, consumer_disabled)`: drop one
  reference from every row in `lease`; the last reference restores the saved
  row. `consumer_disabled` must be `true`. Returns `0` on success.
- `airoha_ct_ifc_pool_has(pool, lease)`: membership test by lease pointer.
- `airoha_ct_ifc_pool_sync(pool, io)`: issue a pending `drain` and clear
  `pending` on success.
- `airoha_ct_ifc_pool_recover(pool, io)`: drain, restore orphaned reservations
  and a blocked release, then clear their shadows and reservations.
- `airoha_ct_ifc_pool_orphans(pool)`: rows reserved with no live reference.
- `airoha_ct_ifc_pool_predicate(words)`: accepts only the supported exact
  predicates: fields 3-12 with `0xe0xx`, fields 24-25 with the IPv4/IPv6 TCP or
  UDP protocol value (6 or 17) masked by `0xff`, and fields 28-29 with a 16-bit
  port and `0xffff` prefix.

Tuple encoding produces 5 rows for IPv4 and 11 for IPv6 (`AIROHA_CT_IFC_TUPLE_MAX`).
`acquire` rejects zero, over-limit and unsupported predicates with `-EINVAL`.
`-ENOSPC` means the pool lacks enough disabled, unreserved rows. `-EOVERFLOW`
means a row's 32-bit reference count is saturated. `-EUCLEAN` means an already
shared row's hardware readback no longer matches its pooled words. `-EIO` means
a write readback did not match. Transport errors are returned unchanged.

## Lease storage and initialization

A lease is embedded in caller-owned storage. The pool links that exact address
intrusively, so the address must remain fixed and the object must stay alive and
untouched from successful `acquire` until `release` completes or recovery has
cleared it. Copying a lease does not create another reference: `release` on a
copy returns `-EINVAL`, and the original remains live.

Zero-initialize each lease before `acquire`. `acquire` rejects non-zero
`count`, `mask` or `next`, and rejects a lease already in the pool, with
`-EBUSY`. On failure the output lease stays zero and is not published.
On successful release or recovery the lease object is zeroed, so it can be
reused. The pool stores row shadows and words in fixed arrays; there is no heap
allocation in this header.

## Serialization and teardown order

The caller serializes every pool operation and every I/O callback. The header
has no lock, and `pending`/`dirty` are updated without atomics. One request may
be outstanding at a time; overlapping `acquire` or `release` calls on the same
pool are not supported.

Retire the packet/consumer path before releasing. `consumer_disabled == false`
returns `-EBUSY` without touching references. The intended order is:

1. Stop new packets or rules from selecting the lease's predicates.
2. Finish or drop work already using those rows.
3. Call `release(..., true)`.
4. On error, call `recover` after the transport drains; do not free or copy the
   lease in the meantime.

While a lease is live, other owners can acquire the same predicate and share
the existing row. Releasing one lease only decrements its references; the row
and its saved contents remain until the last reference is released. The saved
row is restored only when the reference count reaches zero.

## Pending, drain and recovery

Any failed read or write sets `pool->pending`. After validation, `acquire`
returns `-EBUSY` while an orphan reservation or blocked release exists.
`release` rejects orphans and a blocked release of a different lease; it
allows retrying the lease already being released. Calls that pass these
gates drain a pending transport before issuing further I/O. A failed drain
returns its error and leaves `pending` set for the next recovery attempt.

`acquire` reserves rows in fixed arrays before writing and publishes the lease
only after every write and readback succeeds. If a write fails, no lease is
published; the reserved rows and `dirty` bits remain for `recover`.

`recover` restores:

- every reserved row with no live reference (orphan), and
- every row of a blocked release whose reference count is one.

It writes each saved row, verifies readback, then removes the release's
remaining references, unlinks and zeroes the lease, clears `releasing`, clears
the restored shadows and words, and clears the corresponding `reserved` and
`dirty` bits. If drain or a restore write fails, it returns that error with
`pending` set and keeps the reservation and shadow for another `recover`; retry
after the transport drains. A release that fails partway remains blocked:
`release(..., false)` still returns `-EBUSY`, and `recover` or another
`release(..., true)` finishes teardown.

An interrupted `acquire` is rolled back by `recover`, not by the output lease
object. An interrupted `release` keeps its lease pointer and count until
`recover` completes, which is why the lease must remain at a fixed address.

## Capacity

The pool has 32 LUT slots and allows up to 11 predicates per tuple. A row is
usable only when its control word has the enable bit (`BIT(15)`) clear and the
row is not already reserved. The test model marks slots 30 and 31 as enabled,
leaving 30 usable rows.

Observed reservations in that model:

- Four distinct tuples (two IPv4 at 5 rows, two IPv6 at 11 rows) consume 21
  rows for three leases; the fourth returns `-ENOSPC` without a partial write.
- Four tuples with common protocol and ports share identical predicates and
  consume 24 unique rows across all four leases, with reference counts above
  one on the shared rows.
- Four fully distinct tuples consume all 32 rows when no guard is enabled.

These counts are test-model expectations. Real capacity depends on how many
rows the caller marks enabled and on the predicates being shared.

## Verification

The runner is `verify_ifc_tuple_pool.py`. It rejects Python optimization mode,
requires a new `--output` directory, resolves `--source` to a tree containing
`drivers/net/ethernet/airoha`, and copies both headers plus the test source
before compiling. It runs the same test with:

```text
clang -std=gnu11 -O1 -g -Wall -Wextra -Werror
```

for plain and `-fsanitize=address,undefined -fno-sanitize-recover=all
-fno-omit-frame-pointer` builds. Compile commands, stdout, stderr, return codes
and SHA256 values are stored under `plain/` and `sanitized/`; both run stdout and
stderr must match byte-for-byte. Any compile failure, runtime failure, timeout,
non-JSON test output or differing output leaves logs in place, writes
`summary.json` with `passed: false`, and exits non-zero.

Commands used:

```sh
cd /Volumes/Workspace/5585f/build
work=$(mktemp -d pon-ifc-pool-985-exec-XXXXXXXX)
mkdir -p "$work/drivers/net/ethernet/airoha"
patch -d "$work" -p1 --batch --forward \
  < ponwrt/target/linux/airoha/patches-6.18/980-net-airoha-encode-shared-exact-tuple-lut-predicates.patch
patch -d "$work" -p1 --batch --forward \
  < ponwrt/target/linux/airoha/patches-6.18/985-net-airoha-share-transactional-ifc-tuple-lut-pool.patch
python3 ponwrt/target/linux/airoha/tests/pon_offload/verify_ifc_tuple_pool.py \
  --source "$work" --output "$work/final"
```

Result: both patches applied cleanly, both modes compiled and ran with exit code
0, stdout was identical, and the test reported:

```json
{"passed":true,"cases":300,"fault_cases":294,"recovery_fault_cases":64,
 "review_cases":8,"failed_drain_checks":582,"checked_io":21531}
```

Sanitizer stderr was empty. The verified output directory was
`/Volumes/Workspace/5585f/build/pon-ifc-pool-985-exec-ys02LmZP/review-13`.
This run does not cover kernel compilation, hardware access or real transport
timing.
