# Bank1 retirement host fault tests

Run from `/Volumes/Workspace/5585f`:

```sh
python3 build/ponwrt/target/linux/airoha/tests/npu_bank1/verify.py \
  --source build/pon-er-consumer-20261127/owner-source-bank1-retire \
  --output build/pon-er-consumer-20261127/bank1-helpers
```

The source tree is required and the output directory must be new. Without
`--output`, the runner creates a timestamped directory under `_results/`.
`--cc` selects the compiler; the default is `$CC` or `clang`. Python's standard
library and a host compiler supporting ASan/UBSan are sufficient. Generated
sources, compiler temporary files, executables, logs and `report.json` stay
inside the output directory. `_results/` is ignored by Git.

## Production code under test

The runner reads the applied `airoha_npu_bank1.h` and reconstructs the newly
added header from
`999-zc-net-airoha-retire-host-bank1-before-npu-reuse.patch`. It requires exact
byte equality before compiling the complete, unchanged header. It also extracts
the real `airoha_ppe_ct_sram_ack()` and the production FOE types, flow object
layout and relevant constants. The approach follows the neighboring
`pon_offload/verify_lifecycle.py` production extraction and host fault stubs.

Cookie reuse tests execute the complete production
`airoha_ppe_flow_offload_stats()` and `airoha_ppe_flow_offload_destroy()`
functions, together with 16 actual callees covering hash gating, row matching,
idle updates, generic removal, PON removal, WLAN removal and L2 traversal.
The exact function list and all input SHA-256 values appear in `report.json`.
The runner checks production inputs again after execution to catch concurrent
changes.

Kernel list/hash containers, allocation bookkeeping, lock tracking, clock,
SRAM transport and counter transport are host stubs. L2 children use actual
`calloc`/`free`, with ASan checking lifetime errors. Tests call the real
stats/destroy functions under the flow mutex; the outer kernel command
dispatcher and real rhashtable implementation are outside this suite. The
WLAN fail-close dependency is an assertion trap, and these successful reuse
cases leave that branch uncalled. Owner integration and the kernel build are
handled separately.

## Coverage

- L4 hashes at both bank boundaries, invalid/unbound and DRAM hashes, six
  cookie patterns including high bits, all four IB1 states, bridge/dead flags,
  already detached candidates and repeated retirement. Non-state data,
  counters, cookie identity and bridge list membership are preserved.
- Empty walks, repeated objects, repeated `-EAGAIN`, and `-EIO`, `-ENOMEM`,
  `-EINVAL` at the first/middle/end of a walk. Hard errors drain temporary
  `gc_node` links without retiring partially collected objects; retry succeeds.
- L2 parent preservation and rotating child list orders. Only hashes in
  `[8192, 16384)` are freed; bank0, invalid and higher hashes remain linked.
- SRAM ownership/cursor guards, the full 8192-row bank, partial starting
  offsets and a completed cursor. Each row gets its own PPE lock and exact
  write/read ACK verification; rescheduling happens after PPE unlock while
  the flow mutex remains held.
- Faults at offsets 0, 4096 and 8191: write error/timeout, missing ACK,
  mismatched ACK row/direction, a still-set request bit, read timeout,
  acknowledged-but-dropped writes and corrupt readback. Corruption is injected
  separately into every one of the 80 bytes at all three offsets.
- Lost write ACK with an actual SRAM write, repeated failure at the same
  cursor, continued clearing across calls and ownership loss before retry.
  Exact per-row access counts verify resume position and untouched suffixes;
  bank0 hardware and shadow arrays are checked byte-for-byte.
- Reused NPU rows with exactly the old tuple and action at the same first,
  middle and last bank1 hashes. Real stats/destroy functions run for generic,
  PON egress, PON ingress, WLAN and bridge cookies using IPv4/IPv6 and four
  cookie patterns. All low-level row/counter accesses must remain zero.
  Repeated stats/destroy after removal return `-ENOENT`.
- L2 parent stats/destroy after bank1 child retirement: real traversal reads
  and destroys the two remaining bank0 children, frees the parent and leaves
  the reused bank1 hardware/shadow rows unchanged. Any bank1 transport access
  during these reuse tests fails immediately.

## Results and negative controls

Both baseline and all mutants compile with `-Wall -Wextra -Werror`,
`-fsanitize=address,undefined`, `-fno-sanitize-recover=all` and
`-fno-omit-frame-pointer`. Runtime sanitizer options stop on the first error.

The baseline currently runs 703 scenarios and 87,963,540 checks. The 28 mutants
cover bank bounds, stale cookie references, bridge state, L2 removal/free,
resize deduplication/error handling, GC cleanup, lock boundaries, SRAM
ownership, clearing width, commit errors, both ACKs, full-row comparison and
cursor advancement. ACK mutants keep correct ACKs valid while deliberately
accepting a wrong row, wrong direction or pending request.

A mutant counts as caught only after successful compilation, exit status 1
and a `CHECK failed:` runtime assertion. Compilation errors, sanitizer crashes
and timeouts fail the suite instead. `report.json` includes each assertion,
compiler version, exact commands, test/input hashes and the baseline totals.
