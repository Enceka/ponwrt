# Optical service CPU row encoder

Patch 975 supplies `airoha_ct_pon_ifc_cpu_encode()`. It prepares a type0 row
for SPORT2, a complete 16-bit service ID, plain IPv4 or IPv6, and a miss in
the existing short-packet LUT. The destination is WAN CPU RX ring 2 or 4.
The helper prepares words in memory; publishing and restoring hardware rows
belongs to the shared IFC owner introduced by patch 974.

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

Run against a source tree with patch 975 applied:

```sh
python3 -B verify_ifc_cpu_words.py --source /path/to/linux \
  --stock-dir /path/to/stock/lib/modules --output /path/to/results
```

The runner compiles the production header with ASan/UBSan. It executes the
stock `ifc.ko` named field and `forceCPU` setters through the existing
Unicorn oracle, then compares all 27 TCAM/action words, including unused
action padding. Its 640 vectors cover five service values, both address
families, both diagnostic rings and all 32 LUT indices. Another 5,120
predicate checks cover a differing service high bit, the selected LUT hit,
an unrelated LUT hit, another source port and PPPoE. Invalid protocol,
ring, LUT index and null output are rejected before modifying the row.

The named setters select type0 with the parameter byte at offset `0x10`
cleared. `ifc_set_field_LUT1_hit` writes the hit bitmap to page 4 and the
type mask to page 8; it preserves the service and EtherType predicates.
PON OAM, receive-error flags and service-validity flags have no dedicated
setter in this field interface. The future PPE publisher must establish
their hardware control path before enabling service acceleration.
