# Production PON dynamic timestamp row regression

Run the host suite with the kernel trees immediately before and after ZZB:

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_pon_timestamp/verify.py \
  --baseline /Volumes/Workspace/5585f/build/pon-production-session-20261128/source-v3 \
  --source /Volumes/Workspace/5585f/build/pon-production-session-20261128/source-v4 \
  --cc clang
```

The runner replays the complete repository ZZB patch with exact hunk context and
line positions, rejects offset/fuzz, and compares every reconstructed driver file
with the applied tree. It reuses `npu_pon_production/production_test.c` and its
function extractor without copying the harness. Only the unused ZZ9
`airoha_npu_production_idle` function is filtered from the extracted core. The
original lifecycle STATIC assertion is inverted in this runner. Production
step/install/withdraw, owner close, health work, transaction and checked row
helpers execute from the reconstructed source.

Four focused cases cover normal learning/bind/withdraw, incoming STATIC snapshot
clearing, uncertain install ACK cleanup, and withdrawal drain retry. The STATIC
case checks the installed row and saved bound entry, replacement of state and
timestamp, preservation of NAT/action fields and candidate snapshots, repeated
step behavior, row removal, and reference release. Two mandatory mutations
restore the actual baseline production step or omit clearing inherited STATIC;
both must compile and fail the installed hardware STATIC assertion in the
expected test.

Normal and AddressSanitizer/UndefinedBehaviorSanitizer builds run on the host.
Host coverage checks row construction
and lifecycle with mocked MMIO/SRAM, mailbox, candidate lookup and scheduling.
Hardware timestamp advancement on packet hits is covered by board testing.
Temporary files stay in this directory and are removed on exit; source trees,
patch and harness inputs are checked unchanged after execution. No VM, board or
Git commit operations are used.
