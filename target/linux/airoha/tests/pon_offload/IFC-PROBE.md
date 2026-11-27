# RAM optical CPU classifier probe

Patches 976–979 connect the four-row optical owner to the shared classifier
and expose `ct_pon_cpu_probe` only on the explicit RAM native-pair profile.
The probe keeps PON PPE qualification at zero. Hardware validation covers
exact IPv4/IPv6 tuple classification, full service IDs, partial withdrawal
and shared LUT release through GDM2 internal loopback. Full-packet admission
and service-isolated PPE forwarding are the next milestones.

## Ownership and transport

Slot 0 owns rows 56/57 for IPv4/IPv6 and WAN CPU RX ring 2. Slot 1 owns rows
58/59 and ring 4. Each row uses the service ID, Ethernet protocol, source 2,
no VLAN/PPPoE and a negative short-packet LUT predicate. Existing short-packet
guards retain priority for undersized packets. Native LAN rows 54/55 and
their ownership remain separate.

Every changed word is read back by the kernel transport. TCAM comparisons
apply the mask; action words require an exact match. Commands are serialized
under `ppe_lock`. After timeout, ordinary, native and optical callers all
wait for the outstanding command before writing data or control registers.
An unresolved timeout keeps the saved rows and schedules recovery after
closing forwarding admission. Route changes restore the GDM2 default
destination to CPU5 before modifying rows. Other active CPU consumers retain
their ring selection until their own slot is withdrawn.

The EN7581 `get_sport` callback maps GDM2 NBQ0 to SPORT2. The first board
attempt exposed the previously missing case: the callback returned `-EINVAL`
and the probe stopped before acquiring rows. Patch 979 adds the mapping and
tests the production callback directly, including invalid NBQs and the
existing GDM3/GDM4 mappings.

## Interface

Path: `/sys/bus/platform/devices/1fb50000.ethernet/ct_pon_cpu_probe`.

```text
set 0 0x2134
set 1 0x3579
clear 0
clear 1
off
```

`set` replaces only its selected slot. Two active slots must use different
nonzero 16-bit service IDs. `clear` restores that slot's original disabled
rows. Clearing the final slot releases the optical scope and reservation;
`off` restores both slots. `routed=0` records the default destination, while
`active` records consumers that can still select a CPU receive ring.
Status includes saved/dirty/active masks, pending
I/O, scope, readiness, service IDs, PON PPE qualification and error count.

`verify_ifc_probe_board.py` checks the pinned boot and empty MTD list before
every operation. Without `--run` it performs preflight only. With `--run` it
executes three publish/replace/withdraw cycles, rejects duplicate services,
tests full withdrawal and compares the initial/final PPE register report.
The script always requests `off` during cleanup after entering the test.

```sh
python3 target/linux/airoha/tests/pon_offload/verify_ifc_probe_board.py \
  --pin /absolute/path/to/known-hosts \
  --boot BOOT_UUID --output /absolute/path/to/new-evidence-directory --run
```

## Verified board run — 2026-11-27

Host source: `636e43a`. Boot UUID:
`ef9c550f-527a-446c-af48-490cef2d3ffd`.

FIT SHA-256:
`66a83bd12a402db83669f8834d7930b6ae4651c8eaf6dbc44fd57b4c0d7ee7ef`.
Kernel SHA-256:
`f0aeb11c0364782e7813f412613112a94d64662133996e0f104ab030591f420f`.

The FIT retained all 1,101 baseline initramfs entries, its existing wireless
modules, and the verified NPU firmware. The DTB kept NAND and the optical
controller disabled, with optical TX_DISABLE held high. No NAND write took
place.

Two board runs passed: first with native policy disabled, then with the
audited LAN1/WLAN native policy enabled. Each run performed three cycles and
one full two-slot withdrawal. During two-slot publication:

```text
saved=1 dirty=0f active=0f pending=0 scope=01000004 ready=1 service0=8500 service1=13689 ppe=0 errors=0
```

After withdrawal:

```text
saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0 service0=0 service1=0 ppe=0 errors=0
```

The final native policy was `generation=41 allowed=1 failed=0`. WED reported
`state=3 irq_ready=1 error=0`. WAN routing was restored through 192.168.6.1;
direct HTTPS through the Mac Wi-Fi interface returned HTTP 200.

Evidence is under `build/pon-cpu-probe-979.pj9r6h27/` in the enclosing
workspace: `sealed.json`, `board-validation/`, `board-native-coexistence/`,
`wifi-verification/`, and `native-enable/`.

## Host validation

- Owner: 2,110 cases, 2,100 transport faults, 4,690 failed drain checks,
  20 runtime mutations caught.
- Probe with production scope and SPORT callbacks: 1,418 cases, 1,080
  command timeouts, 2,160 retries with no writes, 156 readback faults,
  22 runtime mutations caught.
- Shared command transport: 32 caller/read/write/late-effect combinations,
  96 blocked retries, three runtime mutations caught.
- Native suite: 1,164 cases, 131,072 selector combinations,
  19 runtime mutations caught.
- Shared IFC: 2,485 lifecycle and 130 scope cases, 538,624 classifier cases;
  native ingress: 3,287 cases. The ingress mutation suite caught 28 runtime
  mutations and rejected two source-order mutations.

These host runs used ASan/UBSan. AArch64 Ethernet and PPE objects and the full
RAM kernel built successfully. Current remaining work is real optical
ingress generation/observation, service-qualified PPE lookup and egress,
then same-source recovery/sysupgrade validation and reversible flashing.

## Next ingress and tuple work

### Standalone command drain recovery

Patch986 fixes completion accounting when optical recovery only drains an
outstanding IFC read and has no dirty row left to restore. Previously the
optical owner cleared its local pending flag, but the shared command flag
remained set until another command arrived. The shared drain helper now
clears that flag after observing DONE and retains it on timeout. Optical
recovery and the ordinary command path use the same helper under `ppe_lock`.

Four direct drain cases cover reads/writes and late write effects, including
three blocked retries without new I/O. The new assertion fails on kernel984
and passes with patch986. The probe suite now requires recovery to clear
both pending flags without issuing a compensating read.

On 2026-11-27, validation passed 32 command combinations, 96 blocked command
retries and the four standalone drain cases under ASan/UBSan. All three
command mutants were caught. The complete probe suite passed 6,915 cases
in plain and ASan/UBSan builds, including 1,080 transport faults, 2,160
blocked retries, 56 caught runtime mutations and the stuck-route case.
AArch64 `airoha_eth.o` and `airoha_ppe.o` compiled against the matching
kernel984 configuration without diagnostics.

Evidence directories in the enclosing workspace are
`build/pon-ifc-drain-986-before`, `build/pon-ifc-drain-986-command`,
`build/pon-ifc-drain-986-probe-final` and `build/pon-ifc-drain-986-source`.
The subsequent kernel987 RAM image includes patch986; its board acceptance
is recorded below.

### Tuple consumers

Patch987 adds `tuple 0 SERVICE` to the RAM probe. Install `cover 1` first,
then the tuple consumer, then `route`. Slot0 must be clear before installation
or replacement. The fixed UDP endpoints are `192.0.2.1:49152` to
`192.0.2.2:49153` and `[2001:db8::1]:49152` to `[2001:db8::2]:49153`.
Matching service and tuple select RX2; typed PON cover selects RX4 for misses.
PON PPE qualification remains zero.

The two fixed-address leases share identical port predicates. Their 14 unique
LUT rows plus the two dynamic short guards use 16 of the 32 slots. A combined
capacity check runs before allocation. Publication preserves full SPORT2,
service, EtherType, type0 and encapsulation masks. Route opening audits both
leases, every predicate, consumer pages, typed cover and short dependencies.

`clear 0` and `off` restore consumers before recovering or releasing LUT
ownership. A timeout retains ownership for the repair worker, including when
consumer restoration has already finished. Legacy slot0 `set`, `cover` and
source probes return `-EBUSY` while tuple ownership remains. Status appends
`tuple`, `pool`, `pool_pending` and `leases`; all return to zero after cleanup.
The board runner's `--exact-tuple --tuple-variants --cover-slot 1 --special-tag`
matrix requires two packets on RX2 and eighteen on RX4.

The 2026-11-27 host run passed 6,915 existing cases and 2,226 tuple cases in
both plain and ASan/UBSan builds, with all 78 runtime mutants caught (22 use
the tuple entry point). The tuple matrix includes 1,605 command faults,
3,210 blocked retries, 63 partial second-family acquisitions, 196 failed
releases, 301 additional recovery failures and 98 retries after consumer
restoration has cleared `saved_valid`. Twelve cases apply a delayed hardware
write while drain still times out; four execute the production repair worker
without RTNL and check rescheduling and shutdown. Evidence:
`build/pon-ifc-tuple-987-test-final/report.json` in the enclosing workspace.

### Exact tuple board acceptance — 2026-11-27

Kernel source includes patch987 from commit `6b8696d`. The board runner is
commit `07abb9b`. Boot UUID: `1280c03a-f093-459c-aa1c-05524a5920e6`.

FIT SHA-256:
`1efc5d3058c3f0b3fc2703f97c1887c19679f875ab76a83a97b69aafb3522feb`.
Kernel SHA-256:
`d404f04c69eeee9ed88f21266030997f081687b350c2be5122ee189b67bc3746`.
Loopback module SHA-256:
`904ca8f531cb354d5f1c94f93078c11b216c1f3a9786873467bf61caeb14b313`.
NPU code SHA-256:
`76ed9c882c5bc7dc501be32d5408fe6bf5de8fd49919ab610ad0657254eadb7a`.

The 28-packet exact tuple and withdrawal matrix passed with native policy
enabled. The first 20 packets returned exactly two matches on RX2 and
18 misses on RX4. Removing slot0 released both leases and sent its baseline
packet to cover RX4. Reinstalling slot0 reacquired 14 predicates and sent
the next baseline packet to RX2.

Removing cover slot1 retained slot0 and its two leases: matching IPv4/IPv6
packets still selected RX2, while a different service and a changed IPv6
address selected default RX0. Removing slot0 then released the entire pool
and returned both baseline families to RX0. The initial 24-packet run
exposed a runner assumption that `routed=0` disabled retained consumers;
the revised fixture and matrix exercise the independent consumer and
default-route states. All 18 runner self-tests passed, including wrong-ring
injections at each of the eight withdrawal/reinstall observations.

The seven-type wide-service regression also passed all 14 packets: IPv4,
IPv6, ARP, VLAN, PPPoE, fragment and short IPv4 with both service IDs.
Both runs preserved packet identity, complete service and SPORT2; restored
all ten saved registers; unloaded the loopback module; and left the tuple
pool empty. Final state was `generation=49 allowed=1 failed=0`, PON `ppe=0`,
CPU fallback zero and WED `state=3 irq_ready=1 error=0`. Direct HTTPS over
Wi-Fi returned HTTP 200. NAND remained disabled and `/proc/mtd` empty.

Evidence in the enclosing workspace:
`build/pon-tuple-987-board/{sealed.json,exact-native-withdraw-v2/report.json,wide-native-packet-matrix/report.json,final-wifi/result.json,final-state.txt}`.
The initial failed expectation and its successful cleanup remain in
`build/pon-tuple-987-board/exact-native-withdraw/`.

The stock investigation identified GDM2 loopback and special-tag configuration
as the next no-fiber ingress experiment. Relevant stock FE symbols are
`fe_api_set_loopback_enable` at `0x7df8`, `fe_api_set_loopback_mode` at `0x7e68`,
`fe_set_gdm2_sptag_for_loopback` at `0x2620`, and its command-0x87 wrapper at
`0x9b18`. `fe_show_gdm_sptag_info` at `0x2278` names its selector source
`pkt flow idx`. The open connection is TX GEM/LLID through that special tag
to the GDM2 RX parser. The ordinary Ethernet WAN loopback currently disables
GDM2 IFC and redirects to GDM3/4; a dedicated RAM experiment must explicitly
preserve SPORT2 scope and restore every changed route/tag/loopback register.

For tuple admission, use independent shared LUT predicates with the type0
service row. Its page4 key is the required tuple hit mask `T`; the mask is
`T | BIT(short_lut)`. Basic IPv4 address/protocol/port matching requires five
LUT entries and IPv6 requires eleven. There are 32 entries, including the
two existing short guards. Validity, fragmentation, extension headers and
other owners must be accounted for before allocation. Withdraw consumer
actions before releasing their last LUT references.

The next offline check should execute the stock full-packet parser, then
the LUT parser and combined type0 hit mask. Cover incorrect service,
individual tuple fields, undersized packets, IPv4 fragmentation and IPv6
extension headers before enabling PPE forwarding. Stock `ifc_set_lut1_rules`
is at `0x1261c`; `ifc_lut1_rule_parser` is at `0x1da84` in the existing
`build/private-ram-trials/ct230-ipv6/ifc.dis` investigation. Cross-type chains
remain a separate path because the SINF branch at `0x2b34..0x2bc4` changes
the parser's type and stop selection.

## Service-aware loopback and recovery update

The RAM loopback experiment now returns numbered packets from SPORT2 with
the complete service ID. Default special-tag configuration returns service
zero; independently reconstructed selectors 16..31 plus RX/TX mode1 return
`2134/a134/2134` for three corresponding packets. Both control and tagged
runs restore all ten observed GDM2 registers and unload the temporary module.
Details and the reproducible runner are in `ram_loopback/README.md`.

Default CPU routing still sends these packets to WAN RX0. A direct PPE2
route experiment exposed the remaining unmatched-ingress problem: native
firmware stopped its FE owner and the host entered sticky CPU fallback.
The retained evidence is `build/pon-loopback-board.i9nyacd5/run-classifier/`
in the enclosing workspace. Before repeating a classifier route experiment,
publish all-source2 CPU protection and measure rule priority with CPU-only
actions; native firmware currently expects its established source24 path.

That fallback also exposed a cleanup bug: the sysfs dispatcher rejected
`off` once `ct_stopping` was set. Patch 981 permits withdrawal in that state
while continuing to reject set/clear. Its extracted production dispatcher,
stop and pending-command recovery pass 1,462 cases in normal/ASan/UBSan runs
and catch 28 runtime mutations. This includes six stopping-state withdrawal
cases and six outstanding-command retry cases.

Patch 981 was built into the new RAM FIT:
`b9b52b1e557fc5513f0ade9633284d2221ee2c988f8520d2357b209310e0d0e2`.
Kernel SHA256:
`cfc6ebd5a600ce1ba30f8d0ef0d81e90c5f3a350c2996a39b2d5e34f2536b82d`.
It preserves the baseline DTB and all 1,101 initramfs entries. Current boot
`7c1b2f70-6b0e-438b-8286-7009343efdd9` passed three normal board classifier
cycles and full withdrawal, Wi-Fi HTTPS 200, and native policy restoration
to `generation=49 allowed=1 failed=0`. The stopping-state fault is covered
by the extracted production tests; this board run checked the normal path.
Evidence: `build/pon-cpu-probe-981.t_mqn98y/`.

## Covered route experiment, 2026-11-27

Patch 982 adds `cover SLOT` and `route` to the RAM probe. A cover occupies
the slot's two owned rows, with explicit type0/type1 SPORT2 predicates and
WAN CPU ring2 for slot0 or ring4 for slot1. `route` reads back all cover
TCAM/action words, checks source-to-CPU mapping and receiver readiness,
then changes GDM2 forwarding to PPE2 under the route lock. `set`, `cover`,
`clear` and `off` first restore and acknowledge CPU forwarding. A failed
CPU-route write retains classifier ownership and coverage for retry.
The shared route-change and fallback paths preserve coverage until that
acknowledgement, including persistent route-write failure.

First board FIT SHA256:
`a6fef919244975876b180438ce3a69c8c76adfac28d47911817e9f158d4d987f`.
Boot UUID: `2d6c0192-8ca0-46bc-9eaf-1f93730f4f64`.
Its initramfs matches all 1101 baseline entries. NAND and the optical
controller remain disabled. Evidence: `build/pon-cover-982-board/`.

With native policy disabled, numbered 128-byte IPv4/UDP packets produce:

| Configuration | Service A (2134) | Service B (a134) |
|---|---|---|
| Cover rows56/57, A rows58/59 | RX2 | RX2 |
| A rows56/57, cover rows58/59 | RX2 | RX4 |
| A withdrawn, cover retained | RX4 | RX4 |
| A republished, cover retained | RX2 | RX4 |
| Cover withdrawn, CPU route restored | ordinary CPU RX0 | ordinary CPU RX0 |

All three initial A/B/A packets in each slot arrangement and all eight
withdrawal-cycle packets returned with the exact full service and SPORT2.
The overlapping type0 rows select the lower numerical row. Ten GDM2
registers were restored, the probe unloaded, and native failure remained
clear in these runs. Logs: `cover-slot0`, `cover-slot1`, `withdraw-slot1`.

Enabling native policy exposed a separate coexistence fault: the first
PON packet did not return, and nativeFE health op6 reported EIO with
sticky CPU fallback. The probe still withdrew and unloaded. Wi-Fi HTTPS
returned 200 afterward. Logs: `withdraw-native-active` and
`wifi-after-native-fallback`. The next experiment must resolve the actual
SIF matching/routing interaction with active native rows54/55. PON PPE
qualification remains closed. The covered CPU experiment currently
establishes service selection and withdrawal with native policy disabled.

The persistent route-write fault fix was added after this first FIT and
is covered by the host/VM fault suite; it requires a subsequent RAM build.

## Exclusive source masks and native coexistence

Patch 983 supplied three bounded source diagnostics with native policy
disabled and slot1 CPU coverage retained. Each publishes typed slot0
rows selecting RX2, and the retained cover selects RX4. Numbered optical
packets retain SPORT2 and service2134 throughout all 96 trials:

| Command, N=0..31 | SIF key/mask | Observed RX2 |
|---|---|---|
| `source N` | `BIT(N)/BIT(N)` | all 32 values |
| `absent N` | `0/BIT(N)` | every value except N=2 |
| `only N` | `BIT(N)/U32_MAX` | only N=2 |

Evidence: `build/pon-sif-983-board/sif-sweep` and
`build/pon-sif-983-v2-board/{sif-only,sif-absent}`. The hardware indexes
the SIF key/mask with SPORT; an unset mask bit admits that source. This
explains both the native54/55 interception and the LAN CPU guard
interception of PON ARP/VLAN/PPPoE packets. Patch 984 uses full source
masks in optical service/cover rows, native LAN1 rows and LAN CPU guards.

Final RAM FIT SHA256:
`f43bdab3548a7c6f17098821df3b80368cb55d7b838840828ca531f636bd7f9d`.
Boot UUID: `986bed54-e67d-4baa-ac06-0627f74789a2`.
Kernel source: `/workdir/pon-sif-984`; all 1101 initramfs entries match
the verified baseline. This build includes the persistent-write recovery
fix, the source diagnostics and the exclusive masks. Loopback module SHA:
`daad09ad304b9daca545f130e6394a7d4ef82c68e3f68684c2f6b6782654c1e8`.

Native policy stayed `generation=49 allowed=1 failed=0` during the full
14-packet matrix and eight-packet withdrawal cycle:

| Packet kind | Service2134 | Servicea134 |
|---|---|---|
| IPv4, IPv6, IPv4 first fragment | RX2 service row | RX4 optical cover |
| ARP, VLAN, PPPoE, short IPv4 | RX4 optical cover | RX4 optical cover |

Every packet returned with its sequence, kind, cookie and full service ID.
Deleting the service rows sent both services to RX4; republishing restored
RX2 selection for service2134. Deleting the cover restored default CPU
RX0 before retiring the rows. All ten saved GDM2 registers were restored,
the module unloaded, and the classifier ended at
`saved=0 dirty=00 active=00 pending=0 scope=01000000 ready=0 cover=00 routed=0`.
Wi-Fi HTTPS returned 200 afterward. Evidence:
`build/pon-sif-984-board/{native-packet-matrix,native-withdraw,final-wifi}`.

Host and VM checks include 6915 probe cases, 6400 cross-source comparisons,
56 runtime mutations, persistent-route recovery, 2110 owner cases and
2100 injected owner faults. The actual native ingress header passed 3287
cases; CPU guards passed 2485 lifecycle, 130 scope and 538624 classifier
checks. Stock setter/readback suites cover both new exclusive source
encodings and rejection of the old partial masks.

PON PPE qualification remains closed. The next dataplane work is shared
tuple allocation, fragment/length admission and service-qualified PPE
lookup/egress. The fragment row above deliberately selects CPU; fragment
admission must be resolved before publishing accelerated consumers.

The full-packet stock oracle and pure tuple encoder are now separate
reproducible artifacts. See `IFC-TUPLE-PACKET.md`, `IFC-TUPLE.md` and
`IFC-FIELD-LAYOUT.md`. The field-layout audit corrected an invalid type0/
type1 combination: type0 page7 bits9:8 are DMAC_TYPE, whereas the L4-valid
flags at that position belong to type1. Packet-length/fragment guards and
shared LUT lifetime still need implementation before tuple consumers become
eligible for hardware publication.
