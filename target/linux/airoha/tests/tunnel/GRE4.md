# EN7581 plain IPv4 GRE egress

Patch 967 builds the 17-word egress row from the first 38 bytes of a resolved
outbound Ethernet/IPv4/GRE header. The caller must qualify the EN7581 HIR and
provide the actual underlay MACs, addresses and IPv4 fields. The encoder accepts
untagged unicast Ethernet, a fixed 20-byte outer IPv4 header, and plain GRE
carrying IPv4. The link helper takes a prepared IPv4 HNAPT or IPv4 route FOE and
a dynamic slot (32–63). Both helpers require `FLOW_ACTION_TUNNEL_ENCAP`. They
modify caller-owned memory only; the caller must acquire the row before publishing
the FOE and hold the reference until the hardware entry is retired.

For the stock transmit path, `gwan_prepare_tx_message` writes the `0x727a`
tag, `qdma_transmit_packet` passes the tag from metadata `+6` to the TX hook,
and `PpeTxHandler` passes the tag to `PpeParseLayerInfo`. The oracle runs the
actual parser on a full transmitted Ethernet/IPv4/GRE/IPv4/UDP frame and calls
`PpeSetTunnel_Info` on the resulting parse state. The `0x727a` path selects
action 6 and creates a dynamic row containing the outgoing MAC and outer IPv4
addresses. The same frame tagged `0x7297` selects action 7 and fixed slot 3.
The test supplies skb storage, flow bind status, allocator and FE register
responses; packet parsing, row encoding and FOE linking execute stock code.

Generate reference vectors on a machine with Python, Unicorn and pyelftools:

```sh
python3 verify_gre4.py --stock-dir /path/to/stock/lib/modules --vectors /tmp/gre4.json
```

From a configured kernel tree with patch 967 applied, compile the test wrapper
with the same ARM64 Kbuild configuration as `airoha_ppe.o`. Link its two entry
points as an ARM64 shared library. Run the comparison on ARM64 Linux:

```sh
cp "$TEST_DIR/gre4_vectors.c" drivers/net/ethernet/airoha/
make ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" drivers/net/ethernet/airoha/gre4_vectors.o
gcc -shared -o /tmp/gre4.so drivers/net/ethernet/airoha/gre4_vectors.o
python3 "$TEST_DIR/verify_gre4.py" --library /tmp/gre4.so --vectors /tmp/gre4.json
```

The comparison covers all 32 dynamic rows, both FOE types and four initial
byte patterns (256 complete 80-byte entries). Negative cases cover truncation,
GRE flags and inner protocol, outer IPv4 options and fragments, tagging,
direction, FOE types, and slot bounds. A rejected call must preserve its
entire output buffer.

## Dynamic row ownership (patch 968)

The pool starts with no available slots. Its owner supplies an immutable mask of
clean rows it controls; bit 0 is slot 32. One pool must cover every user of the FE
command port, including operations targeting different slots. Acquire a reference
before publishing a learnable flow. Identical 17-word rows share a slot. Keep each
reference, including that of a pending flow, in its owning cookie until `put`
succeeds. A timed-out FE write blocks new acquisitions; recovery drains the old
command, then clears its row. After a failed last release, retry `put` on the
original reference; an acknowledged flow retirement is performed only once.

The production path still needs an exclusive MMIO owner and hardware completion
and drain callbacks. For PPE integration:

- Under `flow_offload_mutex`, acquire and link the row, index its cookie, then
  publish the candidate using the cookie-first order in `airoha_ppe_ct_bridge_publish`.
- In `airoha_ppe_foe_insert_entry`, qualify the current underlay and serialize
  bind attempts under `ppe_lock`. Preserve every attempted hash until its FOE
  retirement is acknowledged, including after a timeout or an intervening stats
  update. The ordinary path can overwrite `e->hash` on a later learn event.
- On cookie destroy, device removal or route withdrawal, unlink the learner under
  `ppe_lock`, verify the binding's identity including its GRE action and slot, and
  confirm invalidation and completion of in-flight reads before acknowledging
  retirement. The generic `airoha_ppe_foe_remove_flow` drops SRAM commit errors.
  Keep a failed withdrawal indexed and retryable.

Run the pool tests against the compiled driver helpers on ARM64 Linux, using
the same kernel tree and toolchain as the encoder test:

```sh
cp "$TEST_DIR/gre4_lifetime_vectors.c" drivers/net/ethernet/airoha/
make ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" drivers/net/ethernet/airoha/gre4_lifetime_vectors.o
gcc -shared -o /tmp/gre4_lifetime.so drivers/net/ethernet/airoha/gre4_lifetime_vectors.o
python3 -c 'import ctypes; r = ctypes.CDLL("/tmp/gre4_lifetime.so").gre4_lifetime_test(); assert not r, r'
```

The FE model delivers a late write during drain. Cases include both ends of the
dynamic range, sparse ownership, pool exhaustion, a one-word difference at each
of the 17 positions, a shared row after an earlier hole, a failed FOE retirement,
and repeated recovery failures during both row creation and final release.

## FE row transaction (patch 972)

With an exclusively owned, clean slot mask, `airoha_ct_gre4_prepare` validates
the outbound header and FOE type, acquires a shared row through the supplied I/O
backend and updates a caller-owned, unpublished FOE only on success. The FE
adapter stages four words at offsets `0x208c` down to `0x2080`, then issues the
bank command at `0x207c` and waits for bit 31. Bank order is 4, 0, 1, 2, 3.
A timeout stops staging and quarantines the port. Draining this command port
and draining FOE packet readers are separate operations.

The driver returns `-EOPNOTSUPP` for flower tunnel encap. The current action
provides `ip_tunnel_info`; a flow owner still needs a route-qualified, complete
wire header, exclusive access to the table and acknowledged retirement of the
FOE consumers. No hardware owner or packet path is registered by this patch.

Run the compiled row transaction with traced register I/O on ARM64 Linux:

```sh
cp "$TEST_DIR/gre4_port_vectors.c" drivers/net/ethernet/airoha/
make ARCH=arm64 CROSS_COMPILE="$CROSS_COMPILE" KCFLAGS=-fno-stack-protector drivers/net/ethernet/airoha/gre4_port_vectors.o
gcc -shared -o /tmp/gre4_port.so drivers/net/ethernet/airoha/gre4_port_vectors.o
python3 -c 'import ctypes,itertools; f=ctypes.CDLL("/tmp/gre4_port.so").gre4_port_test; assert all(f(s,n,c)==0 for s,n,c in itertools.product(range(32,64),range(6),range(2)))'
```

Only the user-mode test wrapper disables the per-task kernel stack canary.
The 384 cases check each staging word, command, completion boundary and slot;
failed creation preserves the draft and a shared acquisition emits no writes.
