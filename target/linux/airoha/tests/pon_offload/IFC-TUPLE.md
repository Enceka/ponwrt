# Shared exact tuple words

`980-net-airoha-encode-shared-exact-tuple-lut-predicates.patch` adds only
`airoha_ct_ifc_tuple_words.h`. It provides a pure tuple encoder, with no
service row composition, eligibility argument, allocation, ownership,
hardware I/O, overlay integration or PPE authorization.

## Encoder interface

`struct airoha_ct_ifc_tuple` contains `family` (4 or 6), `protocol` (6 or 17),
`src[4]`, `dst[4]`, `sport` and `dport`. Address elements are host integer
values of successive network-order 32-bit chunks, most significant first.
192.0.2.1 is `src[0] = 0xc0000201`; 2001:db8::1 is
`{ 0x20010db8, 0, 0, 1 }`. IPv4 requires the remaining three chunks zero.
Ports are host-order numbers. Zero addresses and ports have ordinary exact
match semantics. Invalid family/protocol or IPv4 tail chunks return
`-EINVAL` without changing output.

`airoha_ct_ifc_tuple_encode(words, tuple)` returns `words.count` and
`words.lut[11][2]`, with unused entries zero. Each pair is hardware bank1
page0 DATA0/DATA1 order. No service, ring or physical index is encoded.

| Logical order | Stock field ID | DATA0 | DATA1 |
| --- | --- | --- | --- |
| IPv4 destination, source | 3, 4 | address | `0xe000 \| field` |
| IPv6 destination low chunk through high chunk | 5–8 | `dst[3]` through `dst[0]` | `0xe000 \| field` |
| IPv6 source low chunk through high chunk | 9–12 | `src[3]` through `src[0]` | `0xe000 \| field` |
| IP protocol / base IPv6 next header | 24 / 25 | `0x00ff0000 \| protocol` | `0xc000 \| field` |
| Destination, source port | 28, 29 | `0xffff0000 \| port` | `0xc000 \| field` |

Every entry has ENABLE bit15 and END bit14. Addresses select 32-bit
comparison with bit13, equality with bit6 clear, and full-width prefix
encoding zero. There is no chain or adjacency requirement, including at
physical indices 15 and 31. IPv4 uses five entries; IPv6 uses eleven.

## Type layout review and regression

The initial uncommitted consumer incorrectly treated type0 page7 bits8/9 as
L4 protocol/port validity. Those bits belong to type0 `dmac_type`. The L4
validity setters use a separate software layout and accept a caller-supplied
type byte without checking that the requested field belongs in that type.
Resetting each setter's shadow and OR-merging its output concealed this
layout conflict. The consumer and its nonzero eligibility-mask API have
been removed; prior row-comparison results are superseded.

The regression now executes original setters followed by `ifc_read_rule`
and original named getters. It tests both type bytes and all four validity
bit combinations, without merging independent setter outputs. The two
layouts use per-row stride `0x74`, with hardware words at shadow offset
`0x08` for type0 and `0x2c` for type1, as selected by the original writers.

| Hardware row | Readback getter results |
| --- | --- |
| type0, page7 key/mask `0x300/0x300` | `dmac_type=3/3`, both L4 valid getters `0/0` |
| type1, page7 key/mask `0x300/0x300` | `dmac_type=0/0`, both L4 valid getters `1/1` |

Original `ifc_get_rule_type` also classifies field31 (`dmac_type`) as type0.
Relevant stock symbols: `ifc_read_rule@0xd48`,
`ifc_get_field_dmac_type@0xc964`, `ifc_get_field_L4PrtcoVLD@0xca74`,
`ifc_get_field_L4PortVLD@0xcb74`, and `ifc_get_rule_type@0xaac`.

The independent `0e23697` full-row investigation in `IFC-FIELD-LAYOUT.md`
also executes the normal `ifc_set_rule` dispatch: fields49/51 naturally
select type1, as do fields52–55 (outer-IP and IPv4/IPv6 validity).
Its complete type classification and nine-page readbacks complement the
eight forced-layout regressions here. No page7 or page8 validity fields
are added to type0 by this encoder.

## Packet conditions required before integration

The intended initial packet domain is complete plain IPv4 with IHL=5 or
ordinary IPv6, carrying TCP/UDP, without fragmentation, unsupported
encapsulation or IPv6 extension headers. Completeness includes declared IP
length within the received frame, TCP header length within the IP payload,
and consistent UDP length. Checksum validation remains separate.

Numeric tuple encoding does not enforce these packet conditions. A future
consumer must validate the actual type-specific protocol/family gates and
implement fragment, extension and length protection before publication.
There is no API that accepts an arbitrary mask as evidence of eligibility.
Service consumers must preserve full service IDs and require all assigned
tuple hits plus the appropriate negative short predicate, with any required
guards included in ownership and capacity accounting.

The full-packet oracle at `9e7ca40` shares field identities and address/port
representation. Its source-first predicate order differs from this encoder's
destination-first order; compare by field identity. Its protocol mask is
`0xffff`, while this encoder uses the exact 8-bit mask `0x00ff`. A future
980 packet profile should use the encoder's order and mask. Its raw profile
retains eight matching IPv4 fragment cases, 200 matching length-invalid
cases and 232 truncated-packet read-boundary interceptions as regressions.

The packet agent tested IPv4 UDF candidates for no fragments (L3+6,
mask `0x3fff`, value0, DF allowed) and version/IHL (L3+0, mask `0xff00`,
value `0x4500`). They need ownership of shared UDF selectors and LUT entries.
IPv6 base Next Header rejects the tested extension/fragment packets in the
stock parser; hardware field semantics require a corresponding board check.
Declared length versus actual received length still needs a validated
receive-status condition or ingress contract. Existing short ranges alone
leave the documented malformed-length cases admitted.

## Capacity and future ownership

There are 32 physical LUT1 entries. Two existing short guards leave at most
30 before additional packet guards and other owners. Without sharing:

| Tuple consumers | Base entries | Including two short guards |
| --- | ---: | ---: |
| One IPv4 | 5 | 7 |
| One IPv6 | 11 | 13 |
| Two IPv4 | 10 | 12 |
| Two IPv6 | 22 | 24 |
| One IPv4 and one IPv6 | 16 | 18 |
| Two IPv4 and two IPv6 | 32 | 34 |

Identical complete predicate words may be shared. Admission must count
actual distinct entries and references; the 34-entry case exceeds capacity
before any additional guards. A future owner must withdraw all consumer
actions before releasing their final LUT reference and retain saved state
across I/O errors. This encoder assigns no slots or reservations.

## Independent stock validation

Reference `ifc.ko` SHA-256:
`d10c1b67b2368a0f2a9255feb851621f8bd73ab16eb6d6a47c9992e4617e3bf7`.
The test executes relocated original AArch64 instructions in Unicorn:

- `ifc_set_lut1_rules@0x1261c` constructs predicate words.
- `ifc_lut1_rule_parser@0x1da84` checks each independent END predicate,
  with explicit field values/validity supplied to its getter. Every
  significant bit flip and invalid field status must miss.
- The read/get regression above preserves the discovered layout conflict.

Stock software LUT storage is control/data; the writer at `0x107b8..0x1081c`
loads offset4 into DATA0 and offset0 into DATA1. The test normalizes this
order. Hardware publication is stubbed after stock LUT construction. Full
packet parsing remains in `verify_ifc_tuple_packet.py`.

Run with patch980 applied to a source directory:

```sh
python3 -B target/linux/airoha/tests/pon_offload/verify_ifc_tuple_words.py \
  --source /path/to/linux \
  --stock-dir /path/to/pinned/modules \
  --output /path/to/new/results
```

The runner compares plain and ASan/UBSan production-header output, records
source/test/stock hashes, and varies both families, protocols, physical LUT
placements and address/port boundaries. Negative API cases verify output
preservation. Runtime mutants must compile and fail a C assertion;
compiler and sanitizer failures do not count as mutation catches.
Run with Python assertions enabled; the runner rejects `-O` before creating
its output directory. Reports include hashes of the runner and imported
stock/MMIO adapters as well as the production header and C harness.
