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
