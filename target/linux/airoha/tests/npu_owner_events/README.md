# NPU owner notification callers

The verifier extracts these production functions from the supplied kernel tree:

- `airoha_ppe_ct_bridge_event`
- `airoha_ct_native_pair_revoke`
- `airoha_ct_native_pair_revoke_closed`
- `airoha_ct_pair_wired_event`

The C harness exercises bridge PRE cleanup despite an incomplete owner close,
first-error retention, native failure containment, PON notifications before the
LAN1 filter, internal shutdown, complete-close acknowledgements, generic FE
ownership guards and repeatable native row retirement. It includes eight
negative controls, with AddressSanitizer and UndefinedBehaviorSanitizer enabled.

Owner notification, firmware/MMIO operations and kernel scheduling primitives
are stubs. The owner transaction and worker lifetime have their own tests in
`../npu_owner/`; this harness checks the event callers and native cleanup.

Run with a fresh output directory:

```sh
python3 target/linux/airoha/tests/npu_owner_events/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/owner-source-health \
  --output /Volumes/Workspace/5585f/build/pon-er-consumer-20261127/owner-events-health
```

`report.json` records source hashes, extracted function names, scenario/check
counts and the failed assertion for each negative control. Each variant retains
its extracted source, executable and build/run logs for inspection.
