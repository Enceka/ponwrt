# PON ingress owner transport

`999-ze` connects `999-zd` to the PON owner. The owner keeps the GDM2 default
selectors on the CPU, closes SPORT2 before restoring classifier rows, prepares
and reads back rows 56/57 with the source closed, and opens SPORT2 after the
current AUTH/GATE and return identity checks. Open-owner health checks verify
the rows, shared short-packet LUT/UDF guards, CPU receiver and source scope.
The legacy CPU probe is excluded while this owner holds the classifier.

Run this test with the complete generated kernel source through `999-ze`:

```sh
python3 target/linux/airoha/tests/npu_ingress_owner/verify.py \
  --source /absolute/path/to/linux-after-999-ze \
  --output /absolute/path/to/new-results-directory
```

The runner compares the new I/O header with the patch, extracts the actual
shared dependency checker and constants, and runs them with the real ingress
transaction. It injects a timeout at every prepare, health-check and restore
transport boundary; a failed drain retains the owner for retry. All failures
belong to the NPU owner and leave the legacy probe state untouched. Register,
LUT, TCAM and action drift, dropped writes, unmasked-word corruption, source
closure, old-probe conflicts and fallback restoration receive separate checks.
Six negative controls must trigger runtime assertions under ASan/UBSan.

`bank1_routes --ingress` tests the actual route/scope MMIO helpers;
`npu_owner --ingress` tests transaction sequencing and notifier races.
`npu_ingress` retains the full classifier transaction and stock-interface
encoding matrix. This change leaves `ct_pon_qualified` disabled. The next
activation dependency is reset/provider DMA retirement and live-board
validation before building the qualified image.
