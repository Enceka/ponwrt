# Idle production PON row relearning

Run the host regression against source-v4 (ZZB applied):

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_pon_relearn/verify.py \
  --baseline /Volumes/Workspace/5585f/build/pon-production-session-20261128/source-v4
```

The runner replays the entire ZZD patch with exact hunk positions and context,
rejects offset/fuzz, and extracts the real production step and event helper.
Optional `--source` compares the reconstructed driver with an applied tree.
It reuses the production/timestamp harness, real transaction and bank0 row
helpers. Only the unused ZZ9 idle function is omitted from the host translation
unit. The additional mock controls inject SRAM read/ACK failures and change the
hardware clock; source files and shared harnesses stay unchanged. All temporary
build products reside in this test directory and are removed on exit.

The tests cover rebind through health work with a fresh epoch and timestamp,
unchanged software snapshots and NAT action, no-event operation without SRAM
access, queued stale events against a complete matching BND row with an updated
timestamp, event identity/hash rejection, BND action/flag/tail-byte conflicts,
UNB tuple/protocol/state conflicts, read/ACK/install failures, and no revival
after withdrawal. A bound session only accepts its existing owned bank0 hash.
Matching BND events leave the epoch, authorization, hardware row and install
count unchanged. All conflicting events use the existing failure/close path.

Normal and AddressSanitizer/UndefinedBehaviorSanitizer builds run with clang.
Four mandatory runtime mutations restore the bound early return, ignore BND
content conflicts, ignore the owned hash, or ignore the BND read ACK. Every
mutation must compile and fail a host assertion. Host tests cover construction
and lifecycle; actual idle aging, packet forwarding and hardware timestamp
updates are exercised by the board acceptance run.
