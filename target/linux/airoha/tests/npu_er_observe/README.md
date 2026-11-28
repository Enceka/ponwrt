# Authorized PON Ethernet Return observation

`999-zz2-net-airoha-observe-authorized-pon-return-frames.patch` adds the optional
ER operation:

```c
void (*observe)(void *ctx, struct net_device *lower,
                const struct er_config *config, u32 service,
                const unsigned char *frame, u32 bytes);
```

`er_poll()` invokes it once after descriptor validation, successful live
binding and skb allocation/copy, while holding RCU and before
`eth_type_trans()`. `frame` points to the complete ER payload including Ethernet,
VLAN and PPPoE headers; `service` retains the validated ER service word. The
callback is synchronous, must not sleep, and must finish using the borrowed
payload before returning. Slots remain owned by the consumer until afterward.
The optional pointer preserves existing LAN1 operations and empty-op users.

The PON owner callback requires pon-full, excludes
ordinary/diagnostic configurations and diagnostic owners, and checks stopping,
retirement, close-pending, transaction OPEN and owned/open/ready/non-revoked
ingress routes. It then reuses `airoha_npu_return_binding()` to recheck the
bound config, service mapping, generation, lower device, QDMA, carrier and
fallback state after allocation. It passes the full frame and low 16 service
bits to the existing `airoha_ppe_pon_observe_frame()` entry. Closed or diagnostic
paths may still drain packets through the existing ER delivery path but do not
feed the production observer. No worker or new row admission is introduced.

Lifecycle fields are sampled with `READ_ONCE`; the callback then performs the
post-allocation binding check under RCU. The existing frame observer takes
`ppe_lock` and rechecks stopping/device readiness before recording an identity.
Bearer replacement first blocks updates, waits for network readers and retires
affected cookies before publishing its replacement mapping. A route close that
starts after the callback's final sample can overlap the last identity record;
the record is software observation only. Any later production action must
validate its own current owner/cookie contract. Taking `ppe_lock` around this
callback would recurse into the existing observer's lock.

## Offline verification

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/npu_er_observe/verify.py \
  --source /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/full-source \
  --output /Volumes/Workspace/5585f/build/pon-npu-diag-20261127/production-ingress/er-observe-next
```

Use the pre-ZZ2 SDK source snapshot. Output must be new, outside ponwrt and
separate from source. The runner copies the source into output, applies the
three-file patch without fuzz or offsets, compiles the complete actual ER
consumer plus extracted owner mapping/binding/observe functions, and verifies
input and patch hashes remain unchanged. It never changes the supplied source.
Requirements are Python 3, patch and clang with AddressSanitizer and
UndefinedBehaviorSanitizer.

The existing `eth_return` fixture is reused read-only; a generated fixture copy
renames its main, allocation and protocol-conversion host functions so the new
tests can instrument ordering and allocation-time lifecycle changes. Production
functions are used unchanged. The existing 108 ER scenarios run first, including
LAN1 and optional operations. New tests cover descriptor/service corruption,
all mapping failures, allocation failure, optional callback, production and
diagnostic gates, route closure, and mapping/service changes during allocation.
Positive cases run with global `ct_pon_qualified` both false and true; observation
uses the specific owner/binding contract without enabling global host learning.
Frames include QinQ and PPPoE with payload beyond the 128-byte diagnostic
snapshot, and service values zero and 65535. The actual frame parser verifies
MAC/VLAN/PPPoE/five-tuple/service identity; host instrumentation verifies RCU,
full payload, callback count and pre-protocol-conversion ordering.

Native and swapped-endian modes run with sanitizers. Eight generated mutations
must fail assertions: omitted callback, truncated payload, lost service,
diagnostic owner/config admission, non-pon-full admission, closed
route admission and missing post-allocation binding recheck. Mutation inputs
are restored afterward. Logs and `report.json` retain baseline, patched source,
fixture, patch and test hashes in the external evidence directory.
