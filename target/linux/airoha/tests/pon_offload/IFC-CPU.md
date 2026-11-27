# Optical service CPU row encoder

Patch 975 supplies `airoha_ct_pon_ifc_cpu_encode()`. It prepares a type0 row
for SPORT2, a complete 16-bit service ID, plain IPv4 or IPv6, and a miss in
the existing short-packet LUT. The destination is WAN CPU RX ring 2 or 4.
The helper prepares words in memory; publishing and restoring hardware rows
belongs to the shared IFC owner introduced by patch 974.

The corrected source predicate is page0 `{BIT(2), U32_MAX}`. SIF selects
the bit indexed by numeric SPORT:

```text
sif_match = ((key >> SPORT) & 1) || !((mask >> SPORT) & 1)
```

The old `{BIT(2), BIT(2)}` encoding admits every source: SPORT2 has a set
key bit and all other sources have a clear mask bit. The earlier claim
that 4/4 isolates SPORT2, and the Python full 32-bit one-hot ternary model,
were incorrect. Original setters/readback established storage layout;
the paired board sweeps establish indexed SIF behavior. Type bits,
service, EtherType, encapsulation, LUT and action encodings are unchanged.

The board reports under enclosing workspace
`build/pon-sif-983-v2-board/sif-only/report.json` and
`build/pon-sif-983-v2-board/sif-absent/report.json` each contain 32 numbered
SPORT2 returns on boot `b0743a03-8269-4061-b560-db7beb37a7c6`. With
`key=BIT(N), mask=U32_MAX`, only N2 selects RX2 and all others select the
RX4 cover. With `key=0, mask=BIT(N)`, only N2 selects RX4 and all others
select RX2. All 64 recorded results match the indexed-bit model.
`IFC-COVER.md` lists original initialization call sites: all nine explicit
field14 calls use full masks, including both single-source and multi-source
keys. Native source consumers must use the same SIF semantics.

The caller supplies the LUT index reserved for the corresponding address
family by the existing 62/63 short-packet guards. That reservation and its
range/UDF configuration must remain valid throughout the service row's
lifetime. A service row requires the LUT bit to be clear; the short-packet
guard requires it set. The resulting predicates are disjoint.

The publisher must snapshot its reserved TCAM/action rows, confirm that
their actions are disabled, write and read back all dependencies, then
enable action page 2 last. It must stop the actions before changing keys or
releasing the LUT dependency. A failed restoration retains its ownership
and saved words for retry. The encoder does not change `ct_ifc_pon_ready`,
the IFC port scope or the PON PPE qualifier.

Run against a source tree with the service encoder and full-SIF-mask
correction applied (candidate `tmp/ifc-sif-984/source`):

```sh
python3 -B verify_ifc_cpu_words.py --source /path/to/linux \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results
```

The runner compiles the production header with ASan/UBSan. It executes the
stock `ifc.ko` named field and `forceCPU` setters through the existing
Unicorn oracle, then compares all 27 TCAM/action words, including unused
action padding. Its 640 vectors cover five service values, both address
families, both diagnostic rings and all 32 LUT indices. Another 24,960
predicate checks cover a differing service high bit, the selected LUT hit,
an unrelated LUT hit, all 32 source ports and PPPoE. Of these, 20,480
checks exercise source isolation. The compiler defines `U32_MAX` as
`UINT32_MAX` for the unchanged userspace C harness. Invalid protocol,
ring, LUT index and null output are rejected before modifying the row.

`verify_ifc_service.py` keeps the full 16-bit service sweeps and per-source
encapsulation checks. Its 3,200 additional SIF comparisons cover only-N,
absent-N and legacy key=mask rows over all 32x32 selected/source pairs,
plus four full-mask source sets. It reads back the original setter's
page0 words before the only/absent/legacy comparisons. Full-packet tests
inherit this source model through `Classifier.matches()`.

The named setters select type0 with the parameter byte at offset `0x10`
cleared. `ifc_set_field_LUT1_hit` writes the hit bitmap to page 4 and the
type mask to page 8; it preserves the service and EtherType predicates.
PON OAM, receive-error flags and service-validity flags have no dedicated
setter in this field interface. The future PPE publisher must establish
their hardware control path before enabling service acceleration.
