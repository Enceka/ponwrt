# PON ingress owner transport

`999-ze` connects `999-zd` to the PON owner. The owner keeps the GDM2 default
selectors on the CPU, closes SPORT2 before restoring classifier rows, prepares
and reads back rows 56/57 with the source closed, and opens SPORT2 after the
current AUTH/GATE and return identity checks. Open-owner health checks verify
the rows, shared short-packet LUT/UDF guards, CPU receiver and source scope.
The legacy CPU probe is excluded while this owner holds the classifier.

Run this test with the complete generated kernel source including `999-zl`:

```sh
python3 -B target/linux/airoha/tests/npu_ingress_owner/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/kernel \
  --through-patch 999-zl-net-airoha-mask-unused-pon-tcam-readback.patch \
  --output target/linux/airoha/tests/npu_ingress_owner/.results/through-zl-v1
```

The runner rebuilds all six production input headers by applying their
creation patches and every later overlay in sorted order, rejects patch
offsets/fuzz, and requires exact bytes against the generated source. The
owner chain includes `999-ze`, diagnostic logging in `999-zk`, and the
readback fix in `999-zl`; it is no longer pinned to the original `999-ze`
file alone. `--through-patch NAME` selects an explicit historical boundary.
Every tested header and applicable patch is rechecked at completion and
hashed in `report.json`.

The runner extracts the actual shared dependency checker and constants,
then runs them with the real ingress transaction. It injects a timeout at
every prepare, health-check and restore
transport boundary; a failed drain retains the owner for retry. All failures
belong to the NPU owner and leave the legacy probe state untouched. Register,
LUT, TCAM and action drift, dropped writes, source closure, old-probe
conflicts and fallback restoration receive separate checks.

The transport stub normalizes unused key bits to ones, zeroes and an
alternating pattern on reads only. Row56/page1 `{0, 0}` reads as
`{0xffffffff, 0}` in the first pattern, matching the reported RAM failure.
Prepare, health checking, replacement and restoration run through the
unmodified production functions. Snapshots retain the observed TCAM
representation, peer rows stay untouched, and successful operations leave
the NPU owner and legacy transport free of pending errors.

The direct put matrix flips every bit of both production rows: masked-out
key changes must succeed; mask changes, selected key changes and every
action bit must return `-EIO` and retain the NPU pending flag. Tests alternate
diagnostic ownership to exercise the real ZK logging branch through
`diag_lower`, `eth->dev` and a format-checked `dev_err` stub. A deliberately
tolerant transport fixture permits one/three-word TCAM requests, isolating
the owner's post-readback count rejection (`-EIO`); zero/four words are
rejected before transport (`-EINVAL`).

Eleven compiled negative controls must trigger assertions under ASan/UBSan,
including whole-word TCAM comparison, skipped mask/key/count checks and
relaxed action checking. The shared source-binding helper has independent
stacking/tamper tests in `npu_ingress/source_binding_test.py`. Results and
scratch copies stay in the ignored `.results/` directory.

`bank1_routes --ingress` tests the actual route/scope MMIO helpers;
`npu_owner --ingress` tests transaction sequencing and notifier races.
`npu_ingress` retains the full classifier transaction and stock-interface
encoding matrix. Kernel compilation and live-board integration remain with
the main task; this suite changes only host tests.
