# Trusted PON unbound events

ZZ7 records one pending hardware learning event per PON software candidate.
The receive call site checks WAN QDMA, GDM2 source, UNB-rate reason, Bank0
bounds, GEM mapping and a single linear Ethernet frame. LRO, GSO, stripped
VLAN metadata and checksum-error descriptors are rejected. Ordinary ER
identity observation does not publish a hardware learning event.

The event stores the descriptor's hardware hash, candidate serial, flow
generation, original key and service. The software entry remains unbound.
Publication uses RCU and `ppe_lock`; no packet or entry pointer escapes.
Withdrawal, identity conflict and Bank0 retirement clear pending events.

`airoha_ppe_pon_take_unbound(ppe, cookie, serial, event)` requires
`flow_offload_mutex`. It takes `ppe_lock`, checks the current candidate and
consumes one matching event. Stale callers cannot consume an event belonging
to a replacement candidate. Output remains unchanged on error.

The production worker must still reserve the row, revalidate its candidate
snapshot and read the actual hardware UNB tuple before binding. Consuming
an event grants no row ownership. ZZ7 does not create a worker or program
hardware.

Run against the complete SDK source containing ZZ4 and ZZ5:

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_pon_unbound_event/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-candidate/zz45-sdk/source \
  --output /absolute/new-evidence-directory
```

The runner applies the patch to an independent copy, extracts the actual
receive and PPE functions, and runs AddressSanitizer/UndefinedBehaviorSanitizer
checks, provenance and lifecycle cases, runtime mutations and lock negatives.
