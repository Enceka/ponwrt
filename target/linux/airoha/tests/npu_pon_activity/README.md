# Owned PON session activity

Run from the ponwrt repository against a kernel source tree immediately before
ZZ9. The runner replays the complete submitted patch in a temporary directory,
requires exact hunk positions and context, and leaves its inputs unchanged:

```sh
python3 -B target/linux/airoha/tests/npu_pon_activity/verify.py \
  --baseline /absolute/path/to/kernel/before-zz9
```

Add `--source /absolute/path/to/kernel/after-zz9` to also compare every applied
driver file with that source tree.

The C harness uses the real FOE and candidate layouts and extracts the actual
`FLOW_CLS_STATS` dispatch, stats handler, production activity/validation/active
functions, candidate reader/validator, row matcher and timestamp calculation.
Mock boundaries are flow-table lookup, netdev/MMIO state, SRAM reads and ACKs,
ordinary-flow activity/counters, and lock scheduling. Both normal and
AddressSanitizer/UndefinedBehaviorSanitizer builds run.

Cases cover hardware timestamps and their 15-bit wrap, jiffies wrap, inactive
rows, every non-timestamp bit of the complete 80-byte owned row, stale
cookie/serial/owner/generation, all non-OPEN phases, close latches, candidate and
bearer replacement, lock-boundary invalidation, read timeout and ACK failure.
Each candidate stats request checks that its hash, candidate data, snapshot,
installed row template and packet counters remain unchanged. Failed requests
keep the previous `lastused`; successful requests also pass the actual snapshot
validator again. Ordinary-flow accounting runs through the same dispatch.
