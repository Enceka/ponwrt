# Service0 CPU probe and RAM loopback

Patch `999-zf-net-airoha-support-zero-service-cpu-probes.patch` adds service0
to the existing CPU diagnostic lifecycle. Its base is ponwrt
`860580c75c8b49c34bd3730330d58668edd15111`, with generated production source
through `999-ze` at
`build/pon-er-consumer-20261127/owner-source-ingress-lifecycle` in the enclosing
workspace.

## Production behavior

`set 0 0`, `set 1 0` and `tuple 0 0` accept a zero service value. Both service
slots retain their existing IPv4/IPv6 rules and CPU ring assignments. The
tuple command still requires slot0, an installed slot1 cover and available
shared LUT leases. Healthy same-value `set` republishes its rows; another
slot using the same exact service returns `-EEXIST`. A typed wildcard cover
coexists with an exact zero service in either slot. Reissuing `tuple` while
its consumers or leases remain owned returns `-EBUSY`; use `clear 0` before
reinstalling it.

Tuple health uses the tuple flag, both active row bits, lease membership,
pool state and hardware readback. Service values stay separate from rule
liveness. `clear`, `off` and the repair worker retain the existing pending
command, saved-row and lease lifecycle. Timeouts retain ownership until the
command drains and restoration succeeds. Clearing the cover retains a live
zero-service tuple; clearing slot0 releases its leases after withdrawing
the consumers.

The implementation follows the stock field interface documented in
`../EPON-SERVICE.md` (E3/E4 and S1/S2): validity is independent of channel or
service value, and the full 16-bit key has a separate mask. Exact service0
uses page7 key `0x00000000`, mask `0xffff0430`; a typed cover has page7 mask
zero. The independent implementation uses the existing production encoders
and owner machinery. NPU ownership still rejects every CPU probe store
command, and `ct_pon_qualified` remains closed.

## Loopback interface

`ram_loopback/ct_pon_loopback.c` now passes an explicit `enable` argument
through `mapping(service, enable)` to the PON configuration API. Preparation
uses `mapping(0x2134, true)`, every transmit uses `mapping(service, true)`,
and restoration uses `mapping(0, false)`. `send 0 ipv4` and `send 0 ipv6 4`
are valid commands. All seven existing packet kinds accept service0.

The existing board runner retains its nonzero service matrix. The new host
suite exercises zero directly through the production `mapping` and full
`transmit` function bodies. The loopback fixture records configuration API
calls and bounded skb submissions; checksum, scheduler and network-device
services are host stubs. It checks service enable/withdrawal, packet markers,
all kinds/variants, failures and timeout retention. The two preparation and
restoration call sites are also checked against the module source.

## Reproduction

Apply `999-zf` after `999-ze`, then run from the ponwrt repository:

```sh
python3 -B target/linux/airoha/tests/pon_offload/service0/verify_service0.py \
  --source /absolute/path/to/patched/source \
  --output /absolute/path/to/new/service0-results
```

The suite requires Python 3 and Clang. Its output directory must be new.
It extracts unchanged production function bodies, includes the production
word encoders, owner and LUT pool headers, and reuses the existing MMIO and
lock-order fixture. No VM, SSH or device access participates in this run.
`report.json` records source SHA256 hashes, counters and mutation results;
the directory retains generated C, compiler commands, logs and executables.

Existing `verify_ifc_probe.c` and `verify_ifc_probe_tuple.c` remain unchanged.
The runner adapts only their temporary copies: it supplies the current
bank1/NPU fixture fields and production dependency functions, and replaces
the two obsolete zero-is-invalid vectors with out-of-range values. All
other legacy lifecycle and fault assertions execute against the patched
production functions.

## Host results, 2026-11-27

Both ordinary and ASan/UBSan runs pass the same checks:

| Suite | Result per build mode |
| --- | --- |
| Exact service, cover and tuple lifecycle | 36 lifecycle checks; 1,835,072 predicate vectors |
| IFC transport timeout retention | 2,541 injected timeouts; 5,091 rejected/recovered retries |
| Shared LUT retention | 1,341 timeout cases retain lease or pool ownership |
| Readback and guards | 302 readback faults; 35 API/owner/qualification checks; 2 repair-worker steps |
| Loopback configuration | 131,072 configure/withdraw checks over every 16-bit value |
| Loopback transmit | 60 full function calls over four service values, seven kinds and tuple variants; 15 failure checks |
| Existing wide-service suite | 6,915 cases |
| Existing tuple suite | 2,226 cases |

Five production mutations are rejected: restoring either zero-value input
restriction, restoring the tuple health value sentinel, treating a cover
as exact service0, and bypassing NPU ownership at the store dispatcher.
The full 16-bit sweeps include service0 and the former `0x2134/0xa134`
regression pair, both families and both wide-service slots.

Evidence in the enclosing workspace:
`build/pon-service0-cpu-20261127/validation-v4/report.json`.
These results exercise production C functions on the host. Hardware service0
packet/ring observations belong to the subsequent RAM kernel validation.

## Overlay integration

Include `target/linux/airoha/tests/pon_offload/service0/*` in the test overlay
alongside the existing parent probe fixtures and
`target/linux/airoha/tests/pon_offload/ram_loopback/ct_pon_loopback.c`.
The new directory contains `verify_service0.py`, `service0_test.c`,
`loopback_test.c` and this README. Packaging files are unchanged by this work.
