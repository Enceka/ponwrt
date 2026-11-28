# Original PON ingress observation tests

This standalone host suite verifies
`999-zz-net-airoha-observe-pon-ingress-flow-identity.patch` against the complete
`production-ingress/source` snapshot. It only writes a new output directory.

```sh
python3 /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_flow_observe/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/source \
  --firmware /Volumes/Workspace/5585f/an7581-npu-firmware \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/observe-suite
```

`--cc` defaults to `$CC` or `clang`. Output must be a new directory outside
the repository and separate from the snapshot and firmware trees.

## Source binding

The existing `npu_ingress/source_binding.py` reconstructs the public AUTH,
IPv4 encoder and new observation headers through ZZ. Every hunk must match
its exact position and context, and the reconstructed bytes must equal the
snapshot. The mailbox ABI must also match the firmware header.

For `airoha_eth.h`, `airoha_eth.c` and `airoha_ppe.c`, whose bases come from
upstream, the runner checks the reversed ZZ hunks against the supplied source,
reverses them in an output copy, checks the forward hunks, then replays them.
Both directions require zero offset/fuzz and restore the exact source bytes.
The report records complete input hashes, patch hashes and extracted-function
hashes, and checks the inputs again at the end.

The runtime functions are extracted verbatim from the bound snapshot:

- `airoha_ppe_foe_get_entry_hash()` and `airoha_ppe_foe_compare_entry()`.
- `airoha_ppe_ct_pon_dev_ready()` and `airoha_ppe_pon_observe_frame()`.
- `airoha_qdma_pon_learnable()` and `airoha_qdma_observe_pon_skb()`.
- `airoha_ppe_ct_remove_pon_flow()`.

FOE layouts, enums, descriptor masks and layout assertions are extracted from
the real headers. Host stubs supply netdev/skb state, list operations,
lock/RCU accounting and fault-injected hardware row operations. The RX call
site is checked to keep observation before ordinary learning and GRO.

## Parser differential coverage

`parser_test.c` compiles the unchanged firmware `src/ingress_auth.c` and
compares its `npu_auth_parse()` result with
`airoha_npu_ingress_parse_ipv4()`. Accepted IPv4 keys must equal the encoder's
complete 19-word key. Every rejected parse must preserve the output bytes.

The frame matrix covers TCP/UDP, TCP options, payload lengths, no/single/double
VLAN, full VLAN TCI bits and PPPoE. Every truncation is allocated at its exact
length, so sanitizers check the declared frame boundary. Every bit of every
matrix frame is flipped separately, exercising MAC, TPID/TCI, PPP session and
length, IP lengths/fragments/protocol/tuple, TCP flags/offset and UDP length.
Additional cases cover Ethernet padding, the 1518-byte limit, a third VLAN,
null arguments, service overflow and valid IPv6 rejected by the IPv4-only
parser. Source frame bytes must remain unchanged.

## Observation and withdrawal coverage

`observe_test.c` places an original ingress cookie and a deliberately colliding
NAT-output cookie into the same bucket. The actual hash and tuple comparison
functions select the original IPv4 TCP/UDP identity; NAT addresses/ports,
output MAC actions, cookie and hardware hash remain unchanged.

Tests cover:

- Wrong device, flow type, bridge, packet type, absent PPE/flow table, non-PON
  port and NBQ; blocked, stopped, administratively down and carrier-down state.
- Identical repeated observations leave the complete entry unchanged.
- Changed GEM/service, either MAC, VLAN TCI/stack or PPPoE cause sticky conflict;
  neither the original nor the changed frame can reactivate that cookie.
- Complete MAC frames from WAN QDMA, the matching skb device, linear data and
  an intact MAC header; truncated frames and stripped/offloaded VLANs fail.
- GPON uses the current valid GEM table rather than a stale default tag;
  EPON uses the current channel and LLID. Error/control descriptors and stale
  or invalid mappings fail. A second valid GEM conflicts with the old identity.
- Withdrawal clears `pon_ingress_seen` under `ppe_lock` before list removal,
  hardware reads or invalidation writes. Unbound, bound, FIN, missing and
  mismatching rows, commit failure and retry are covered. Failed withdrawal
  retains cookie/hash while preventing another observation of the unlinked flow.

All binaries use warnings as errors, AddressSanitizer and
UndefinedBehaviorSanitizer. Runtime negative controls alter parser fields,
tuple selection, gates, conflict handling, frame length, mapping checks and
withdrawal ordering. Each mutant must compile and fail a CHECK assertion;
compiler failures and sanitizer failures do not count as caught mutants.

`report.json` contains baseline counts and all negative-control outcomes.
Per-binary build/run logs, exact bound headers and replay logs remain in the
output directory. Hardware row I/O and concurrency are stubbed here; production
integration and the broader retirement/reuse suite are handled separately.
