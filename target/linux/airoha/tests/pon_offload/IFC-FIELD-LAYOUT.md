# Stock IFC field types and complete row readback

The type0 page7 bits 9:8 encode `dmac_type`. The same physical bits encode
`L4PrtcoVLD` and `L4PortVLD` in type1. IPv4/IPv6 validity and outer-IP flags
in page8 bits 3:0 also belong to type1. The earlier recommendation to OR
these validity fields into a type0 service row was incorrect.

The named setters use fixed shadow layouts and copy the caller's type
byte into the emitted type bits. Calling a type1 setter with type zero
therefore produces a type0 row containing the type1 field positions.
The normal `ifc_set_rule` entry first classifies the field. Its parameter
byte at +0x11 explicitly bypasses classification when nonzero.

## Reproduce

From the workspace root, with Python, Unicorn and pyelftools installed:

```sh
/usr/bin/python3 -B build/ponwrt/target/linux/airoha/tests/pon_offload/verify_ifc_field_layout.py \
  --stock-dir build/stage2/zip/root/lib/modules \
  --output build/pon-offload-ifc-field-layout-20261127
```

Choose a new output directory for each run. `-O` is rejected. Only this
process's Unicorn memory and the result directory are written. There is
no device access. The runner reuses the existing stock loader and its
explicit kernel/MMIO adapters without modifying them.

The SHA-pinned `ifc.ko` is:

`d10c1b67b2368a0f2a9255feb851621f8bd73ab16eb6d6a47c9992e4617e3bf7`

`result.json` contains all 51 classified fields, their natural types,
dispatch slots, setter/getter names and ELF text offsets. It also contains
ten complete nine-page readbacks, decoded getters, input parameters and
helper-call counts. The runner asserts:

- Original `ifc_get_rule_type` agrees with all three original field lists.
- Original `ifc_set_rule` performs classification and dispatch itself.
- Original `ifc_read_rule` returns every stored page, including zero pages.
- After clearing both shadows, a second original read fills the selected
  layout; original getters recover exactly the expected fields.
- Four forced-type0 L4 combinations decode as DMAC_TYPE 0, 1, 2 and 3,
  with both type1 L4 getters zero.

The test adapter selects shadow +0x08 for type0 and +0x2c for type1 based
on the emitted type. This is explicit test plumbing derived from the
setters/getters. `ifc_read_rule` itself is a raw nine-page reader.

## Readback results

Numbers below are hexadecimal `(key, mask)` pairs.

| Fields | Natural type | page8 | page7 |
| --- | --- | --- | --- |
| 31 DMAC_TYPE=3 | 0 | `(00,c0)` | `(300,300)` |
| 49 L4PrtcoVLD=1 + 51 L4PortVLD=1 | 1 | `(40,c0)` | `(300,300)` |
| 52 outterIPv4=1 | 1 | `(48,c8)` | `(0,0)` |
| 53 outterIPv6=1 | 1 | `(44,c4)` | `(0,0)` |
| 54 IPv4VLD=1 | 1 | `(42,c2)` | `(0,0)` |
| 55 IPv6VLD=1 | 1 | `(41,c1)` | `(0,0)` |
| Forced type0, fields49/51 both 1 | bypass | `(00,c0)` | `(300,300)` |

The final row decodes as `dmac_type=(3,3)`, `L4PrtcoVLD=(0,0)` and
`L4PortVLD=(0,0)` after type0 readback. Thus type0 page8 `{2,cf}` or
`{1,cf}` must also be removed from the proposed family guard profile.
The pure tuple LUT encoder is independent of this layout correction.
The raw packet oracle's eight fragment matches and 200 length-anomaly
matches used none of these added validity bits and retain their meaning.

## Exact original evidence

Binary: `build/stage2/zip/root/lib/modules/ifc.ko`.
Disassembly: `build/private-ram-trials/ct230-ipv6/ifc.dis`.
Offsets below are relative to ELF `.text`.

| Symbol / offset | Evidence |
| --- | --- |
| `ifc_get_rule_type@0xaac` | Lists at `.rodata+0xe8/+0x130/+0x190`; parameter +0x11 bypass at 0xb70; resulting type at parameter +0x10 |
| `ifc_set_rule@0x10ec` | Calls classification at 0x11dc; fields48..67 use dispatch slot field-16; indirect setter dispatch |
| `ifc_set_field_dmac_type@0x677c` | Type0 shadow +8; page7 bits9:8 |
| `ifc_set_field_L4PrtcoVLD@0x6a6c` | Type1 shadow +0x2c; value at shadow +0x30 bit8; writes from +0x2c at 0x6bdc |
| `ifc_set_field_L4PortVLD@0x6d54` | Same type1 layout, value bit9 |
| `ifc_get_field_dmac_type@0xc964` | Load shadow +8 at 0xc98c, extract bits40..41 at 0xc990 |
| `ifc_get_field_L4PrtcoVLD@0xca74` | Load shadow +0x30 at 0xcaa0, extract bit8 at 0xcaa4 |
| `ifc_get_field_L4PortVLD@0xcb74` | Type1 shadow +0x30 bit9 |
| `ifc_read_rule@0xd48` | Reads pages8..0 into nine contiguous key/mask words |
| `ifc_dump_hw_msg@0x181c` | Calls raw reader at 0x1880 and prints words |
| `ifc_get_rule_from_reg@0x14da8` | Separate eight-entry LUT0 reader; calls `ifc_parser_lut0_rule` at 0x14f44 |
| `ifc_get_rule_from_hw@0x15394` | Parses LUT0 rule array; separate from the 64-row TCAM field layouts |

## SPORT2 fallback and numerical priority

The board operator reported that unmatched SPORT2 reached nativeFE after
GDM2 PPE2 activation; `!decision` set `stop_requested`, followed by op6
`-5`. The restored firmware and CPU-default configuration remain the
baseline. These observations supply the next experiment's constraints;
this test does not operate the board or inspect firmware state.

Numerical TCAM arbitration between row56 and row62 remains an open point.
The existing service predicate requires the short-LUT bit clear, whereas
the corresponding row62/63 guard requires it set. Their disjointness is
documented in `IFC-CPU.md` and patch960. Existing success therefore tests
those disjoint predicates. `get_ifc_index@0x1e2c4` scans eight LUT0 entries
and 32 LUT1 entries; its ascending scan is a software LUT selection path.
`ifc_match_rule@0x234c` searches configured shadow rules during rule
management. Neither path implements the silicon's 64-row TCAM arbiter.

The next reversible board experiment should be prepared in this order:

1. Establish a SPORT2-only, all-service/all-EtherType/all-encapsulation CPU
   catchall, including its type applicability and complete word readback.
   It must have no service, tuple, short-bit or IP-validity exclusions.
   Reserve a separate owned row; retain the existing row62/63 guards.
2. Use overlapping diagnostic service and catchall actions that BOTH send
   to host CPU, with distinct already-supported WAN RX rings. Read back
   both enabled actions before any route change. The overlap resolves
   winner priority while either winner keeps traffic out of nativeFE.
3. Exercise service hit, wrong service/tuple, short, non-IP and tagged
   packets; record row counters and ring destinations. Include unchanged
   native-source counters/health. Return GDM2 to CPU before withdrawing
   either diagnostic row. Choose the final catchall row from the observed
   priority, rather than assuming an ordering from row numbers.
4. Only after the service consumer is ready and CPU fallthrough is verified
   should service acceleration be considered. On stop or failed setup,
   restore the CPU route first and retain catchall ownership until route
   readback succeeds; withdraw consumers before their LUT dependencies.

The diagnostic route transition still requires a scoped owner/readiness
design. It must preserve the default-CPU invariant for other native
sources. A general PPE default without this catchall is excluded.
