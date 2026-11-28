# Selected PON production session tests

Run against the applied ZZ8 kernel source and its source immediately before ZZ8:

```sh
python3 -B target/linux/airoha/tests/npu_pon_production/verify.py \
  --source /absolute/path/to/kernel/source \
  --baseline /absolute/path/to/kernel/before-zz8
```

The runner applies the complete repository patch to a temporary copy of the
baseline, checks each hunk's exact context and line positions, and compares all
ten changed files and their header dependencies against the applied source.
It then extracts the production session functions, debugfs show,
`airoha_ppe_npu_production_active`,
`airoha_ppe_ct_remove_pon_flow`, `airoha_ppe_npu_owner_close_locked`, and
`airoha_npu_owner_health_work` directly from that source. It also uses the real
FOE and candidate layouts, transaction core, authorization publisher, and
checked bank0 row helpers from the reconstructed driver. It prints hashes of
the patch and extracted code and runs normal
and AddressSanitizer/UndefinedBehaviorSanitizer builds. Temporary build products
stay inside this test directory and are removed on exit. Input hashes are
checked again after execution to catch source changes during the run.

Mock boundaries are mailbox replies, MMIO/SRAM, candidate lookup, return-ring
allocation/destruction, ownership claim/retirement, and work scheduling. The
tests exercise learning to BND with the snapshot NAT action, cookie/serial
withdrawal, invalidation before cleanup, partial drain retry, uncertain write
ACK cleanup, lost replies after BEGIN/ADD/ARM, controller/UNB mismatch, release retry, and
health-work lock/phase gating. The actual active predicate covers every native
pair slot, policy, invalidation, pending close, generation, controller/private
identity, carrier, update blocking, and QDMA selection. The actual delete function must clear seen/event
and unlink before invalidation, with its spinlock released before close.

The tests reject stale hardware events independently by serial, generation,
GEM, source MAC and bank; test profile/startup guards and return-ring allocation
failure; and retry each saved bank-register restoration and owner-retirement
failure while retaining both endpoint references. Subsequent health ticks keep
the original authorization failure in status.

The actual debugfs show function must list only eligible candidates, retry
walk `-EAGAIN`, return other walk errors, retain balanced locks/references, and
show `bound=0` after close even while retaining the saved binding action.

The suite uses the shared exact-hunk checker from `npu_ingress` and the patch
`999-zz8-net-airoha-run-selected-pon-candidate-session.patch`.
