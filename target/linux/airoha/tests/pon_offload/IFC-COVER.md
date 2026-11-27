# Typed SPORT2 forceCPU cover words

`verify_ifc_cover_words.py` compares the production
`airoha_ct_pon_ifc_cover_encode(row, ring, type)` with the SHA-pinned stock
IFC setter instructions and complete TCAM/action readback. It only runs
inside local test processes. No device access is performed.

From `build/ponwrt`:

```sh
/usr/bin/python3 -B target/linux/airoha/tests/pon_offload/verify_ifc_cover_words.py \
  --source tmp/ifc-cover-982/source \
  --stock-dir ../stage2/zip/root/lib/modules \
  --output tmp/ifc-cover-982/stock-cover
```

The output directory must be new. The runner requires Python with Unicorn
and pyelftools, and a C compiler with ASan/UBSan. It rejects Python `-O`.
The candidate header is copied unchanged into the output directory and
compiled with a generated C harness. The output includes that header,
harness, binary, compiler log, exact inputs, stdout/stderr and `result.json`.
The report records source hashes, original function offsets, all readback
words, decoded SIF fields and helper-call counts.

## Exact configuration

Only the following TCAM pages have nonzero masks. All other pages are
zero, including GEM/service, EtherType, VLAN/PPPoE and LUT predicates.

| Cover type | page0 key/mask | page8 key/mask |
| --- | --- | --- |
| type0 | `00000004/00000004` | `00000000/000000c0` |
| type1 | `00000004/00000004` | `00000040/000000c0` |

SIF setter values are raw 32-bit words. SPORT2 uses `BIT(2)` in this
source bitmap. The receive metadata's SPORT field is a separate numeric
five-bit value; it contains 2, rather than 4, for source2.

For both types the enabled forceCPU action is:

| Action page | Words |
| --- | --- |
| 0 | `0, 0` |
| 1 | `0, 0, ring << 10` |
| 2 | `d0000000` |

RX2 encodes `0x800`; RX4 encodes `0x1000`. The original setter masks the
ring to five bits. The candidate accepts only the established rings2/4.
Disabling changes page2 to `0x50000000`, preserving ring and TCAM words.
The candidate structure pads each action page to three words; the runner
also checks those padding words are zero. CPU destination/source mapping
and ring receiver readiness belong to the publisher's route transaction.

## Reading the original design

The rule type selects a field layout. It is independent of the ingress
source number and of the action's CPU RX ring. Type0 contains the L2 and
service predicates; type1 contains the IPv4/L4 and validity predicates;
type2 dedicates pages0..7 to IPv6 address words. An IPv6 service can use
a type0 EtherType/service row, with shared LUT predicates for its tuple.
Do not equate rule type1 with IPv4 packets or rule type2 with all IPv6
packets when choosing a source cover.

SIF is explicitly implemented in both type0 and type1. The original
setter branches on the requested type, uses that type's shadow buffer,
and writes page8 bits7:6 with mask c0. This differs from the fixed-layout
L4-valid setters audited in `IFC-FIELD-LAYOUT.md`: selecting type1 for SIF
follows an actual original branch. Type2 has no SIF setter/getter branch.
Its page0 is destination-address data, so clearing the type mask would
extend the comparison into a different field layout.

Three separate controls participate in the ingress decision:

| Control | Role |
| --- | --- |
| Global IFC source scope | Admit selected physical sources to classifier processing |
| Row SIF predicate | Restrict this rule to SPORT2 within the admitted scope |
| Source CPU map plus forceCPU ring | Select the host CPU destination and its receive ring after a CPU action |

Keep the SPORT2 SIF predicate even when the global scope already includes
SPORT2. Other native sources share the classifier. A source-only cover
wildcards service, EtherType, encapsulation and LUT results within its
selected layout, while retaining the physical source restriction. Its
CPU action applies directly to packets missing the service consumer.

The forceCPU setter puts the ring at action page1 word2 bits14:10 and
enables the forceCPU bit in page2. Its emitted action has no force-port
destination in page0. In the host integration the existing SPORT2 CPU
map selects CDM2/WAN QDMA, and the action supplies RX2 or RX4. GDM2's
default forwarding route is a separate control from this source CPU map.
The publisher must preserve the source CPU map while changing the GDM2
route used to enter classifier processing.

The original word writer and reader expose a 64-row table; arbitration
between simultaneously matching rows is performed by hardware. The
ascending loops in `get_ifc_index@0x1e2c4` select among eight LUT0 and
32 LUT1 entries. `ifc_match_rule@0x234c` searches configured shadow rules
during rule management. Those loops describe software lookup order.
Record physical row numbers, matched predicates and ring destinations
when measuring TCAM priority. Existing service/short-guard predicates
are disjoint, with opposite requirements on the short-LUT hit bit.

For the cover/service experiment, the cover and service row overlap on
the service-positive packet; the wrong-service packet selects the cover.
Keeping both actions on CPU makes either overlap winner a host receive
path. Swap the cover and service physical slots while keeping each
predicate's ring assignment fixed. A service-positive result that follows
the physical slot identifies the winning slot; the wrong-service packet
continues to check fallthrough. Retain the other typed cover throughout.
Install and read back covers and consumers before enabling the ingress
route; restore CPU routing before withdrawing them.

## Coverage and original evidence

Sixteen vectors cover rows56..59, types0/1 and rings2/4. Each compares all
27 candidate words against complete original `ifc_read_rule` and
`ifc_read_act` output: 432 word comparisons. Each case also clears the
software shadows, reads the row into its proper type-specific layout,
executes the original SIF getter and checks `(4,4)`. Every case exercises
the disabled forceCPU action and verifies unchanged TCAM contents.

The generated C harness checks 167 invalid calls: null output plus invalid
ring/type combinations across rings0..32/UINT_MAX and types0/1/2/3/UINT_MAX.
Every invalid call with a non-null output must preserve the entire row.
Valid encoding starts from an A5-filled row to check complete assignment.

Original module: `build/stage2/zip/root/lib/modules/ifc.ko`, SHA256
`d10c1b67b2368a0f2a9255feb851621f8bd73ab16eb6d6a47c9992e4617e3bf7`.
Original disassembly: `build/private-ram-trials/ct230-ipv6/ifc.dis`.

| Original symbol / ELF text offset | Checked behavior |
| --- | --- |
| `ifc_set_rule@0x10ec` | Dispatch field14 with explicit type via parameter +0x10 and classification bypass +0x11 |
| `ifc_set_field_sif@0x4e94` | Explicit type0/type1 branches; SIF at shadow +0x28/+0x4c, emitted page0; type mask c0 |
| `ifc_get_field_sif@0xc0c8` | Read each selected type's SIF shadow after full hardware-model readback |
| `ifc_read_rule@0xd48` | Read all nine key/mask pages |
| `ifc_set_action_forceCPU@0xb1e8` | ForceCPU bit28, ring bits14:10, action control bits31:29 |
| `ifc_read_act@0xed8` | Read all six physical action words |
| `ifc_set_field_dipv6_w0@0x42c0` | Type2 page0 contains the low32 bits of the IPv6 destination |

The existing `PacketOracle` supplies the relocated original instructions
and process-local kernel/MMIO adapters. TCAM comparison in the type2
regression uses an explicitly labeled Python ternary model. Row priority,
packet-type availability and live source-to-CPU routing are board tests.

## Type2 regression and priority experiment boundary

The runner naturally classifies field5 as type2 and reads back four
destination words: 0, 4, 0x12345678 and 0xffffffff. Both typed cover masks
exclude all these type2 keys. Removing the page8 mask instead matches the
type2 keys whose destination bit2 is set. That wildcard would interpret
the same page0 bit as address data. An additional original SIF call with
type2 produces no TCAM writes. The candidate rejects type2 without
changing output.

Use explicit type0/type1 covers; keep page8 mask c0. For numerical
priority testing, compare two otherwise identical type0 SPORT2 covers
with distinct CPU RX rings and retain a separate type1 cover. Swap the
two type0 ring assignments only while the route is back at CPU5. Read
back all owned rules/actions and source CPU mapping before route8.
Observe the known numbered service-preserving packets and per-packet
health, returning to CPU5 on error. Restore CPU routing before retiring
covers. No row-number arbitration assumption is encoded by this test.
