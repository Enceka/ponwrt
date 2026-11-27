# Stock full-packet IFC tuple oracle

`verify_ifc_tuple_packet.py` executes the SHA-pinned original AArch64
`ifc.ko` in Unicorn. It extends the existing loader and simulated TCAM
interface through imports; `stock_oracle.py` and `verify_ifc_service.py`
remain unchanged. All packet storage, descriptors, tables and registers
live in the test process. There is no device or network access.

## Reproduce

From the workspace root:

```sh
/usr/bin/python3 -B build/ponwrt/target/linux/airoha/tests/pon_offload/verify_ifc_tuple_packet.py \
  --stock-dir build/stage2/zip/root/lib/modules \
  --output /tmp/pon-ifc-tuple-packet-results
```

The output directory must be new. The existing local environment provides
Python 3.9.6, Unicorn 2.1.4 and pyelftools through `/usr/bin/python3`.
Other hosts need `unicorn` and `pyelftools` available to their Python.
Assertions must be enabled; the runner rejects `-O`.

The stock module SHA256 is
`d10c1b67b2368a0f2a9255feb851621f8bd73ab16eb6d6a47c9992e4617e3bf7`.
`result.json` includes runtime details, input/source hashes, symbol offsets,
adapter counts, instruction count, interfaces and aggregate observations.
`vectors.json` contains every packet, descriptor service/source, original
parsed output, packet read requests, LUT result, type0 comparison, and the
separate candidate admission decision. Table configurations include all
32 LUT RAM entries and both nine-page type0 rows.

## Executed interfaces

| Original symbol | `.text` offset | ABI exercised |
| --- | --- | --- |
| `skb_parser` | `0x1bdf4` | `x0=skb`, `x1=156-byte parsed output`; `w0=return code` |
| `ifc_get_value_by_field` | `0x1c94c` | `x0=skb`, `x1=RX message`, `x2=parsed`, `w3=field`; `w0=status`, `w1=low value` |
| `ifc_set_lut1_rules` | `0x1261c` | Eight integer arguments: index, valid, END, field, operation, mask/range-high, auxiliary, value/range-low |
| `ifc_lut1_rule_parser` | `0x1da84` | `x0=skb`, `x1=parsed`, `x2=RX message`, `w3=index`, `x4=next-index output`; zero matches, minus one misses |
| `ifc_set_field_LUT1_hit` | `0x7a98` | Existing named-setter parameter ABI; type0 page4 key and mask |

The fixture supplies stock `skb->head` at `+0x180` and `skb->data` at
`+0x188`. Original local helpers calculate the transport/network/MAC
offsets at `+0xae/+0xb0/+0xb2`. Tests cover zero and 128-byte headroom.
For ordinary untagged traffic the parsed L2/L3/L4 offsets are
`0/14/34` for IPv4 and `0/14/54` for IPv6. Observed skb reads are checked
against precisely these pointer/header fields; the exercised parser does
not read a packet-length field.

Service and SPORT enter through an explicit two-word RX descriptor fixture:
`msg0[29:14]=service`, `msg1[25:21]=SPORT`. The original field getter
extracts them. GEM/LLID is descriptor metadata, separate from Ethernet
packet bytes. Optical production of that metadata remains a board task.

Original `isTPID`, header-offset helpers, protocol parser, field getter,
LUT encoding/comparison and TCAM setters run normally. The adapters are:

- `memcpy`, `memset`, `memcmp`: ordinary process-local operations, with
  frame bounds checked before memory-helper reads.
- `GET_HIR`: the existing loader's AN7581 value `0xa`; logging returns zero.
- FE register fixtures: custom TPID `0x9100`, local MAC `02:00:00:00:00:01`,
  and UDF0/UDF1 selectors `L3+2` / `L3+4` at `0xbfb50220=0x00110009`.
- `write_all_ifc_rule_to_hw`: suppressed at its function entry, after the
  original LUT setter has encoded RAM. Named TCAM/action setters use the
  existing process-local indirect-register adapter.

The final type0 comparison is the existing Python masked-key model over
the original setter's nine TCAM pages. Independent `END=1` LUT predicates
contribute one modeled hit bit each. Silicon hit generation, priority and
cross-type chain execution remain separate hardware checks.

## Coverage and isolation

The reproducible parsed-header suite contains **804 cases**: two address
families, independent predicates and contiguous LUT chains, correct UDP
tuples, then every bit of both addresses, protocol and both ports flipped
individually. All matching and mismatching decisions execute the original
LUT parser and field getter.

The full-packet suite contains **1,276 cases** covering IPv4/IPv6 TCP/UDP:

- Valid packets with generated IP/transport checksums, both service rows,
  wrong service, wrong SPORT, every address/port bit, and alternate protocol.
- Two services sharing the same tuple predicates; then distinct destination
  ports with the other predicates still shared. The four combinations of
  service A/B and tuple A/B admit only the two authorized pairs.
- IPv4 MF, nonzero fragment offset, MF plus offset, maximum offset, and DF.
- IPv6 Hop-by-Hop, Routing, Destination Options, and Fragment headers;
  Fragment covers atomic, first-with-M, and nonfirst cases.
- Declared short/overlong IP lengths, actual guard range boundaries, every
  truncated prefix of each complete base packet, and headroom relocation.

The tuple occupies 5 LUT entries for IPv4 and 11 for IPv6. Test rows 56/57
are process-local indices. Their page4 key is `tuple_bits`; the mask is
`tuple_bits | BIT(short_guard)`. Changing one service's destination port
uses one additional LUT entry and changes only that service's hit mask,
so the test catches accidental Cartesian-product authorization.

Short guard fixtures retain the current host ranges: IPv4 total length
20..57, IPv6 payload length 0..17. These are the `ct_ifc_guard` definitions
in the host IFC header, introduced by the short-packet guard patch and
extended in `945-net-airoha-offload-ct-wireless-ipv6.patch`. The original LUT
setter must produce RAM words `{0xc0a0, 0x00390014}` and
`{0xc0a1, 0x00110000}`. These RAM word pairs are control/value order, while
the hardware staging interface presents value/control order.

## Read boundaries and admission findings

Every original instruction read within the packet arena is monitored.
The adapters separately monitor `memcpy`/`memcmp`, since Unicorn host
`mem_read` does not trigger guest memory hooks. Storage outside the supplied
frame is filled with `0xa5`; the first request outside the exact frame
raises `PacketBounds` before those bytes are used. The trace records the
original PC, frame-relative offset, size and instruction/helper origin.
This is the harness reporting an overread request, not a stock error return.

| Ordinary packet | Minimum bytes requested by stock parser | Final L4 read site |
| --- | ---: | --- |
| IPv4 TCP | 54 | `0x1c44c`, 20-byte TCP copy |
| IPv4 UDP | 42 | `0x1c4d4`, 8-byte UDP load |
| IPv6 TCP | 74 | `0x1c720`, 20-byte TCP copy |
| IPv6 UDP | 62 | `0x1c790`, 8-byte UDP load |

Across the four truncation sweeps, **232** prefixes trigger the bounds
monitor. The remaining packet cases return normally: **1,044** including
full headers whose declared IP payload exceeds the supplied bytes. The
stock parser copies fixed headers and calculates IPv4 L4 position from
IHL; it does not validate the available length or the declared IP length.
The minimums above describe these fixtures, with IPv4 IHL=5 and no IPv6
extension headers. Nonlinear skb parsing and malformed IHL need additional
fixtures before broader parser use.

The raw predicate results preserve important gaps:

1. IPv4 fragment flags/offset do not exclude the tested packet from tuple
   matching. Eight fragment cases retain the service row match.
2. IPv4 declared lengths 0/1 miss the existing 20..57 short range and retain
   a tuple match when the supplied backing frame contains full headers.
3. Overdeclared lengths and truncated payload after complete headers also
   retain matches. Together with item 2, 200 length-invalid cases match the
   modeled type0 row.
4. The tested IPv6 extension headers are not traversed. Their base
   Next Header differs from TCP/UDP, so the tuple does not match. An atomic
   Fragment header follows this same exclusion.

`ordinary_admission()` is an explicit **candidate software reference**:
linear untagged IPv4 IHL=5 or ordinary IPv6, complete declared lengths,
TCP/UDP header lengths, no IPv4 fragments and no IPv6 extension headers.
Its rejection and proposed resulting rows are recorded separately from
the original parser/LUT and raw type0 results. It is not a production
driver change or an emulation of an existing hardware validity gate.
Checksum bytes are generated for normal fixtures; checksum validation is
outside this reference's scope.

The next implementation decision is how to enforce those length/fragment
conditions before publishing a tuple consumer. The board follow-up then
checks independent LUT hit bits and the type0 positive/negative mask on
the already established SPORT2 CPU path. Hardware receive-error flags,
service validity and fragment admission remain explicit open points.
