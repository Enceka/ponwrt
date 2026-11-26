# PON PPE admission and retirement verification

The tools execute production functions extracted from the kernel source given
by `--source`. They need a C compiler supporting AddressSanitizer and
UndefinedBehaviorSanitizer. All outputs go into a fresh `--output` directory.

```sh
python3 verify_admission.py --source /path/to/linux-after-962 --output /path/to/admission-results
python3 verify_pon_flows.py --source /path/to/linux --output /path/to/flow-results
```

Files to keep together:

- `verify_admission.py` and `admission_test.c`
- `verify_pon_flows.py` and `pon_flows_test.c`

The admission runner executes the production exact-match validator, ingress
resolution, PON gate/admission functions, actual learn/bind function, cookie
publication, duplicate-tuple exclusion, netfilter lower-path parser and EN7581
source-port decoder. It covers 617 cases and 20 runtime mutation controls.
The retirement runner executes checked row comparison/removal, the two-way
device walk and the actual flow-destroy function. It covers 62 cases and 7
runtime mutation controls. SRAM reads/writes, allocation indices and kernel
primitives use deterministic test doubles; ownership and retry decisions run
the extracted production C. Host transaction/publication is tested separately
by `verify_transaction.py`; the retirement runner does not depend on the host
`airoha_eth_pon_commit_config()` implementation.

## Production gate

`ct_pon_qualified` starts false through the zeroed PPE allocation. There is no
runtime setter, device-tree switch, debugfs control or module parameter for
turning it on. Both PON directions therefore remain in software. Admission and
actual binding each check the field; unrelated non-PON flows keep their existing
behavior. The test fixture explicitly sets the field true to exercise the future
qualified path, and checks the default false state in both directions.

The qualifier must eventually own hardware ingress-domain and encapsulation
isolation before enabling shared IP FOE keys. Software META/encapsulation checks
and duplicate-candidate rejection apply only to learning; already-bound hardware
hits need the separate ingress classifier.

## Paths exercised with the test qualifier enabled

- Routed IPv4 TCP/UDP (including NAT44) and unencapsulated routed IPv6 TCP/UDP.
- Upstream physical wired or DSA LAN to PON. WLAN to PON uses its physical
  wireless ingress ifindex and the existing NPU-to-PPE learning path.
- Downstream PON to physical wired or DSA LAN, with an unencapsulated ingress
  five-tuple. PON must be running, have carrier and have an open update gate.
  At binding, the actual Ethernet protocol must match the IPv4/IPv6 FOE type
  and no hardware VLAN tag may be present. The gate checks input framing, so
  plain IPv4 input with VLAN/PPPoE output actions remains valid.
- Upstream IPv4 egress VLAN/PPPoE uses the existing action encoder and requires
  one unambiguous GEM/T-CONT mapping. Both admission and binding check that
  the egress selects WAN QDMA and reads HQoS disabled at offset `0x90`, bit 31.
  Enabling WAN HQoS or changing the QDMA between admission and learning skips
  the hardware bind. Restoring the direct encoding allows the next learn to bind.
- DSA learning checks the physical conduit and the RX `METADATA_HW_PORT_MUX`
  port number. Missing metadata, another metadata type, another port and a
  different conduit are rejected. A bare DSA conduit META is rejected.
- The production netfilter path parser resolves PPPoE, VLAN and stacked
  PPPoE/VLAN paths to their final physical netdev. A flow submitted with an
  unresolved upper-device META is rejected.

## Remaining software paths

- PON to WLAN: `airoha_ppe_ct_ifc_covers()` covers LAN1 ingress, while PON
  enters through GDM2. The PON admission gate also requires a physical egress
  GDM, whereas the WLAN action returns a WDMA destination and no egress GDM.
- PON ingress VLAN, CVLAN, PPPoE and tunnel keys: the current FOE tuple match
  does not retain those selectors. VLAN/CVLAN/tunnel keys are rejected at
  admission. This kernel does not emit a PPPoE ingress dissector key; actual
  PPPoE input is rejected at bind by its Ethernet protocol. With the test
  qualifier enabled, a PPPoE candidate can exist in the software cookie table without a hardware bind. The production
  default rejects PON candidates before publication.
- IPv6 VLAN/PPPoE output, NAT66, non-TCP/UDP traffic, native bridge PON flows,
  PON-to-PON flows and per-P-bit split GEM mappings.
- WAN HQoS enabled mode (T-CONT/channel remapping).

Strict ingress validation applies only when the output is PON or the META
ifindex/mask can select a PON netdev; unrelated flows retain their existing
admission. The actual learning packet from PON must also match an entry
explicitly associated with that PON ingress.

Both PON ingress and PON egress entries are withdrawn on a bearer update.
Read/write failures retain the cookie and attempted hardware hash, remove
the entry from the learn list, and permit a later checked retry. Cookie
publication precedes learn-list publication, and a PON-related duplicate
five-tuple is rejected because the hardware lookup has no ingress key.

The generated report records hashes of every extracted source. Hardware
throughput and live optical-line behavior require device validation after the
integrated driver is built.
