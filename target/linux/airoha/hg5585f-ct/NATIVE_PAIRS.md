# Connac2 native WLAN and LAN1 pair RAM trial

Patches 951 through 957 add the source-built NPU loader, explicit native MAC
pair policy, bidirectional WLAN/LAN1 forwarding, and CPU fallback with station
reconnection after native faults. They apply after 950 and
retain 948's flow-admission diagnostics. The native trial requires the RAM-only
device-tree properties and a matching firmware bundle; stock image defaults
remain unchanged.

## Source and firmware identity

Build the NPU source with the complete native FE profile:

```sh
make CT_BRIDGE_GUARD=2 CT_SHORT_PAD=1 CT_TDMA_BANK=2 CT_NATIVE_PAIRS=1 \
  CT_FE_GENERIC=1 CT_FE_NATIVE=1 CT_FE_SOURCE_PORT=24 CT_FE_MAX_FRAME=1518 \
  all ram-payload
```

Use the compiler pinned by the NPU repository and verify `build/ram-payload.json`.
The loader introduced in 951, with its digest updated by 956, checks these
WLAN CPU gate and host RX backpressure payloads and reads the loaded bytes back:

| Image destination | SHA256 |
| --- | --- |
| `/lib/firmware/airoha/hg5585f-ct/npu_rebuilt_rv32.bin` | `0c22adc3cdb81c9fc28831dfe55f5dcb10bbac8e5390e648022353237abedb11` |
| `/lib/firmware/airoha/hg5585f-ct/npu_rebuilt_data.bin` | `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119` |

These are the generated `ram-npu_rv32.bin` and `ram-npu_data.bin`, respectively.
Code occupies 27,760 bytes at NPU address `0x84000000`; data occupies four bytes
at NPU address `0x3e900000` (host `0x1e900000`). The native mailbox uses ABI 3,
capability mask 63, a 64-byte payload and a 72-byte message. FE QUIESCE and ARM
are operations 5 and 6. LAN1 uses endpoint selector 2, port ID 24 and BSS 0.
Firmware changes require a corresponding update to the loader digest table
and a rebuilt kernel.

Prepare the overlay with independently verified stock firmware and the generated
native payload directory. The third argument enables the separate rebuilt
firmware package; the two-argument stock invocation remains available.

```sh
bash target/linux/airoha/hg5585f-ct/prepare-overlay.sh \
  /path/to/stock-userfs /path/to/new-overlay /path/to/npu/build
```

The stock `SHA256SUMS` keeps its two original entries. `SHA256SUMS.rebuilt`
verifies the separately named native files; the overlay also records the digest
of every copied file and `local.config`. It contains the complete Connac2 patch
sequence through 960, native tests, firmware inputs and this guide. Apply its
`tree/` to the matching OpenWrt revision and merge `local.config` before building.

Generate the NAND-disabled native trial DTS using the live factory digest:

```sh
python3 target/linux/airoha/hg5585f-ct/ram-dts.py \
  /path/to/factory.bin LIVE_FACTORY_SHA256 \
  --connac2 --connac2-rx --connac2-host-ppe --wed-slot1 \
  --firmware-dir /path/to/overlay/tree/package/firmware/hg5585f-ct-npu-firmware/files \
  --native-pairs \
  --rebuilt-firmware-dir /path/to/overlay/tree/package/firmware/hg5585f-ct-npu-firmware/files
```

The native flag verifies both rebuilt files, then emits
`airoha,connac2-rebuilt-ram-lab` on the NPU node and
`airoha,connac2-ram-native-pairs` on Ethernet. Policy starts off on every boot;
Ethernet checks the native mailbox capabilities before selecting the bank layout.

## Kernel and module bundle

Rebuild the kernel and its modules together. Include `kmod-nft-core` and
`kmod-nft-bridge`; the existing package definitions install and autoload
`nf_tables.ko`, `nft_meta_bridge.ko` and `nf_conntrack_bridge.ko`. Use modules
from this kernel build in the initramfs.

The bridge meta companion is required when `CONFIG_NFT_BRIDGE_META=m`:
the rebuilt generic meta selector delegates bridge expressions to that module.
The rebuilt conntrack bridge module tags its three hooks with the newly
appended `NF_HOOK_OP_BRIDGE_CT=4`. Existing hook type numbers, public NPU
operation offsets, structures and prototypes remain unchanged. The fail-close
retry state is private to the Ethernet driver.

For an existing RAM initramfs, replace `nf_tables.ko` and
`nf_conntrack_bridge.ko`, add `nft_meta_bridge.ko`, and ensure the meta companion
loads before firewall rule installation. A normal OpenWrt build with the
packages above generates those dependencies. The private FIT repacker is a
separate lab convenience; it is not part of this source contract.

The supported lifecycle uses fixed device tree nodes, `CONFIG_NET_AIROHA=y`
and `CONFIG_NET_AIROHA_NPU=y`, with device tree overlays disabled. Both providers
suppress sysfs bind/unbind. Native state is published only after all Ethernet
netdevs register. Teardown first closes WLAN production; an unsuccessful stop
retains NPU references and DMA resources for retry. Dynamic provider removal
requires its own complete DMA/reset protocol.

The supported policy configuration excludes `CONFIG_BRIDGE_NETFILTER`,
`CONFIG_NETFILTER_XTABLES` and `CONFIG_NET_CLS_ACT`. Existing XDP/TCX attachments
also reject authorization; their installation is blocked during a native RAM
session. The three tagged bridge conntrack hooks are accepted only at their
correct bridge heads and priorities. Unknown hooks remain rejected.

## Authorization and learning

Find `ct_native_pair_policy` under the Ethernet platform device in sysfs. It
reports `generation`, `allowed` and `failed`. Capture the generation before
collecting `nft -j list ruleset`, then run the offline auditor:

```sh
python3 target/linux/airoha/tests/native_pair/audit_policy.py ruleset.json
```

The accepted contract permits the complete unicast IPv4/IPv6 MAC pair through
the bridge; it has no per-flow state, set/map, quota or time-dependent decision.
Before enabling, verify that WLAN stations are authorized, FDB entries point
to the expected ports, ports are forwarding, the bridge has no VLAN filtering,
and isolated/locked flags are clear. Same-port peers require hairpin mode.
LAN1 admission also checks the physical port identity, link/carrier, bridge
membership, MTU and FDB destination. Recheck the boot identifier and captured
generation before writing `whole-mac-ip GENERATION` to sysfs. A stale generation
returns `ESTALE`.

Authorization performs the FE QUIESCE/ARM handshake before installing the LAN1
ingress rules. The first successful software bridge forwarding event creates
the directed pair; reverse traffic creates the reverse pair. Admission checks
current MACs, station/WCID/BSS, FDB placement, bridge generation and endpoint
epochs. True LAN1 QDMA ingress uses `peer=NULL` and validates its wired source
directly. The subsequent learned bank0 L2B row becomes BND after those identities
match. Up to four row hashes are retained for each directed pair. The FE mailbox
uses `br_flow_offload_generation()`; this bridge generation is separate from the
nft policy generation reported by sysfs.

The frame notifier runs in the bridge's RCU read-side section, including when
called from NAPI. Both FDB admission passes use `br_switchdev_fdb_find_port()`
within that section; this helper also excludes entries that the bridge does
not publish to switchdev. The packet path does not acquire RTNL.

PPE bank0 uses FLOW `0xb200` for native L2B traffic; bank1 uses `0x3200` for
route-format flows. Ordinary GDM ingress selects bank1. Saved/restored IFC rows
54/55 steer LAN1 IPv4/IPv6 into FE channel 7 while retaining guard rows 62/63
and the existing global/UDF/LUT configuration. LAN1 output uses PSE 9, channel 4,
NBQ 0; WLAN output uses PSE 3, channel 9, NBQ 3. Native rows preserve TTL/hop
limit, DSCP/ECN and IPv6 flow labels. The firmware handles simple IPv4/IPv6 TCP
and UDP, including short frames using padding; fragments, IP options, IPv6
extension headers and TCP FIN/RST use the host path.

## LAN1 ingress classification

Patch 960 restricts native IFC rows 54/55 to source port 24, type 0,
plain IPv4/IPv6, with neither VLAN-present bit nor PPPoE set. The existing
short-frame guards 62/63 keep precedence over those rows. CPU rows 32–50
cover the three encapsulation bits and the exact complement of the two IP
EtherTypes. CPU and native eligibility are disjoint; overlapping CPU rules
share the same action. VID 0 is classified as tagged traffic.

The CPU action selects ring 1 and uses the source port's QDMA CPU mapping.
IFC activation verifies that port 24 maps to CDM1 or CDM2 according to its
actual QDMA. Both CPU-map writers and QDMA reassignment close IFC and read
the gate back before publishing a new mapping. Failure retains the old map
and schedules sticky CPU recovery. Rule installation and restoration share
the existing IFC ownership, snapshots and dirty-state retry handling.
GDM4 retains its ordinary forwarding configuration: a default CPU override
would bypass IFC and prevent native LAN1 forwarding.

Run the ingress checks against a Linux tree prepared through patch 960:

```sh
python3 target/linux/airoha/tests/native_pair/verify_ifc_cpu.py \
  --host /path/to/linux/drivers/net/ethernet/airoha --output /path/to/ifc-results
python3 target/linux/airoha/tests/native_pair/verify_ingress_native.py \
  --kernel /path/to/linux --output /path/to/native-ingress-results
python3 target/linux/airoha/tests/native_pair/verify_ingress_mutations.py \
  --kernel /path/to/linux --output /path/to/new/ingress-mutation-results
```

The extracted driver checks pass 2,485 IFC lifecycle cases, 538,624 classifier
combinations and 3,277 native cases under ASan/UBSan, and reject 16 deliberate
mutations. The patch applies with zero fuzz and reproduces all 47 driver files
of the tested candidate. The matched kernel builds with zero warnings/errors.

The 2026-11-26 NAND-disabled RAM trial passed all 26 classification templates
in 1,040 frames. Plain IP and short-boundary native frames bypassed CPU and
arrived intact; VLAN, QinQ, PPPoE, short and non-IP frames reached CPU as
expected. All plain controls arrived, with zero socket/capture drops,
duplicates or modified exact matches. Exact Wi-Fi delivery was 984/1,040:
the remaining 56 are VID 0 frames, whose forwarding/tag handling is under
separate investigation.

Ordinary native TCP passed in four directions with stable rows and zero FE
faults/drops: LAN1→Mac Wi-Fi 1,278.229 Mbps, reverse 939.507 Mbps,
Mac Wi-Fi→CMCC 321.362 Mbps, reverse 583.714 Mbps. Router CPU was
3.574%, 1.375%, 2.783% and 2.084%, respectively. FIT SHA256:
`a280833362721af081124c6212221db30444800e21a3bf2b4f568fb2abe52071`.
The NPU payload remains the `hostbusy1` image listed above. PON qualification
stays disabled while its service identity and bank1 lifecycle are rebuilt.

## Revocation and fault handling

Writing `off` closes admission. nft changes close authorization before their new
policy publishes. Station teardown, FDB moves, bridge changes, and LAN1 link/MTU
changes use the same retirement path:

1. Restore the LAN1 IFC rules and complete FE QUIESCE, retaining the same epoch
   and generation across retries.
2. Receive the global native FLUSH acknowledgement, retiring both wired and
   WLAN pair producers and their firmware references.
3. Set bank0 SEARCH_MISS to 2 and FLOW to 0 while keeping the bank enabled, then
   wait for PPE BUSY to clear.
4. Invalidate all owned native FOE rows, complete any required WLAN operation 4,
   and restore/read back bank0 TB/FLOW configuration. Subsequent authorized
   traffic can rearm and relearn.

FE RXMBI completion covers PSE packet assembly; PPE BUSY covers the next bank0
processing boundary. The mt76/WED station teardown lifecycle covers already
submitted WLAN TX before WCID reuse. Firmware publishes FE command fields with
`fence iorw,iorw` before ringing the doorbell.

The FE WAIT watchdog expires after 1,000 ms (100 ticks of 10 ms), records one
fault and requests a stop. Completion at the deadline wins over timeout.
Outstanding inflight, pair and token ownership remain reserved. A 100 ms host
health worker issues idempotent ARM checks, which return `EIO` after the fault.

Host failure handling sets `allowed=0` and `failed=1`, closes native admission,
routes each GDM through its actual QDMA CPU port, and disables IFC. It then sends
fault-only FLUSH with flags bit 0 and waits for the WLAN gate ACK before stopping
both PPE banks. Capability bit 32 covers this gate. The ACK follows the last
WLAN TDMA doorbell, including gateway traffic; the NPU then sends new frames to
the original host RX queue with RXD/BA metadata. A disabled destination PPE bank
also uses host RX during startup/teardown.

During sticky CPU fallback, a full host RX ring returns BUSY before DMA.
The firmware retains the queued frame and its buffer ownership until the
host recycles a descriptor. Fragment chains remain contiguous on each
selector; other selectors and TDMA completions continue to progress.

The firmware gate is sticky until a fresh boot. PUT and FE ARM return `EIO`
afterward. Existing frame owners, pair references and completion state remain
reserved until completion. Ordinary flags=0 FLUSH retains the reversible
revocation semantics above. The 100 ms health worker retries gate, route,
retirement and FE quiescence failures independently of `ct_stopping`.

After all CPU routes and producer gates are ready and both PPE banks have
stopped, station flush permits CPU-only registration. mt76 still clears the
station's BA state before WCID reuse and runs its existing MCU/TX cleanup.
Native epoch queries remain zero; old native epochs and owners stay retained.
Actual driver teardown continues to return `ESHUTDOWN` for station registration.
A fresh boot restores native offload after a fault.

During active fault-cutover traffic, sample configuration, firmware counters,
and the fixed runtime/fault readers. Capture `ppe/entries` and `ppe/bind`
after the traffic ends: each stopped-bank SRAM read waits for its ACK
timeout, so the two full scans occupy about 3.5 seconds of kernel time.

The `hostbusy1` full-load wireless fault trial retained traffic in every
one-second interval across the cutover (233.96 Mbps
overall; 190.66 Mbps minimum after the settling
window). Both CPU software directions on LAN1 and WLAN, IPv4/IPv6
management, established SSH heartbeats and LAN1 reopen passed. FE faults,
inflight owners and the first-fault latch remained zero. Evidence is in
workspace `build/private-ram-trials/native-lan1-source-abi3-hostbusy1/fault-wireless-light1/`.

## Repeatable host checks

From the OpenWrt repository root, point the runner at its prepared Linux tree:

```sh
python3 target/linux/airoha/tests/native_pair/run.py \
  --kernel-tree /path/to/prepared/linux-6.18.60 \
  --output /path/to/new/native-host-results
```

Python 3 and Clang with AddressSanitizer/UndefinedBehaviorSanitizer are required.
The runner extracts the current kernel functions into a separate results
directory and hashes their source. It runs 1,063 ASan/UBSan cases, 131,072 CPU
selector combinations, and catches 19 deliberate mutations at runtime. Groups
cover pair admission/binding 199, CPU fallback 19, policy serialization 11,
bank/revoke lifecycle 224, mailbox wrapper 71, XDP/TCX 16, shutdown 7, teardown 10,
station fallback 40, FDB movement 6, bridge hook classification 298, nft JSON
audit 20, wired identity/MTU 130, wired notifier 8, and radio ownership 4.
Transport and MMIO are mocked while the tested driver functions are extracted
from the prepared source.

The station checks exercise both bands, WCID bounds, retained ownership,
completed and incomplete fault cutovers, actual teardown, and normal epoch
advancement. Supplemental extracted mt7915 add/clear/authorize/revoke/BA checks
pass 10 cases. Actual RV32 execution verifies that DELETE_STA flushes held BA
frames to host RX, resets all eight BA windows and permits BA reconfiguration
while retaining old native owners and rejecting new PUTs.

The isolated 951–957 patch sequence applies with zero fuzz and reproduces the
final production source. The matched wlangate3 kernel build has zero
warnings/errors; its NPU code, device tree and modules match wlangate2.
The private RAM image includes a fault injection entry; production patches keep
only read-only state and first-failure diagnostics.

## Native station RX activity

mac80211 patch 602 records driver-reported RX activity separately from software
RX and successful TX ACK timestamps. CT mt7915 patch 142 samples per-station
WTBL RX airtime once per second across WCIDs 1 through 150. Only a new valid
counter value refreshes activity; first samples, epoch changes, counter clears
and failed reads rebuild the baseline. Authorization, station replacement and
radio reset reset the sampler. Shared WTBL bank selection and register access
use `sta_poll_lock` across all six callers.

This keeps `inactive time` current while native traffic bypasses host RX.
Packet/byte/rate/signal statistics and the hostapd inactivity configuration keep
their existing semantics. Rebuild mac80211 and all dependent mt76 modules
together for the added helper and private station fields.

The activity regression can reconstruct its source entirely from the repository
and the two source archives pinned in the package Makefiles. Fetch the normal
OpenWrt package archives into `dl/`, then run with Python 3, GNU tar with zstd,
GNU patch, and a C compiler supporting ASan/UBSan and pthreads:

```sh
python3 target/linux/airoha/tests/station_activity/prepare.py \
  --downloads dl --output /path/to/new/activity-source
python3 target/linux/airoha/tests/station_activity/verify.py \
  --mac80211-tree /path/to/new/activity-source/mac80211 \
  --mt76-tree /path/to/new/activity-source/mt76 \
  --output /path/to/new/activity-results
```

`prepare.py` verifies archive hashes and applies the package patch order,
including CT WED. Existing patches use the OpenWrt context tolerance; new
activity patches require zero fuzz. On macOS, set `PATCH=gpatch` for GNU patch.
`verify.py` also accepts already prepared source trees. It extracts the actual
functions and runs 789 assertions, seven runtime negative controls, and checks
all six WTBL bank callers. Coverage includes both bands, WCIDs 127/128/150,
authorization and epoch changes, WCID reuse, counter clear/wrap, radio reset,
jiffies wrap, link selection, and threaded bank contention. Results record the
source hashes and require no private trial files.

The `rxactivity1` RAM image passed two 35-second native TCP directions at
296.38 / 471.31 Mbps with station activity near the one-second sample interval,
stable conntrack, low CPU, and zero FE faults/drops. Evidence is in workspace
`build/private-ram-trials/native-lan1-source-abi3-rxactivity1/normal-en0/`.

Separate 31-sample cache observations passed during bulk traffic and after it
stopped. Active traffic kept inactivity at or below 1,000 ms. The stopped-flow
station received 213 background packets, and 29 RX-airtime changes refreshed
hardware activity. In the fixed-cache interval, the hardware timestamp stayed
unchanged while inactivity rose from 40 to 510 ms; both fixed-cache intervals
in the active run also retained their timestamp. Evidence is in workspace
`build/private-ram-trials/native-lan1-source-abi3-rxactivity1/cache-diag1/`,
including `active1-review.json` and `idle1-review.json`.

The `hostbusy1` RAM image passed 660 seconds of LAN1-to-Mac-Wi-Fi native TCP
at 1,262.203 Mbps with 3.767% aggregate router CPU. All 72,930,454 submitted FE
packets completed, with zero faults/drops and no inflight owner after the flow.
All 22 adjacent sample intervals showed continued FE/NPU progress; station
inactivity stayed at or below 900 ms, with stable native rows, association and
software conntrack state. Evidence is in workspace
`build/private-ram-trials/native-lan1-source-abi3-hostbusy1/mac-long1/`,
including `result.json` and `long-native-review.json`.
The boot ID is `d4b0e484-ddee-4f77-aecd-cbd84c0bac02`; the NAND-disabled FIT
SHA256 is `53cc785179f21fa9a6f854de10303dc61f43c3853462dbb9e059512d18cb2edd`.

## Previous fence1 RAM acceptance

The matched FIT SHA256 is
`dc6f44415dc9af8780a015c219ae08c4b8ce94cd528ca0c6168ada78f5adee6c`,
with NAND disabled and NPU code SHA256
`a9b95290d4f6382b281b232d21357c01ed1fdabdba06c23104f98044cb37e172`
(27,104 bytes). Evidence is retained under
workspace `build/private-ram-trials/native-lan1-source-abi3-fence1/`; boot ID is
`dc3b8722-c31f-4733-b314-3713aa2113b2`.

| Check | Result | Evidence subdirectory |
| --- | --- | --- |
| Bidirectional WLAN/LAN1 TCP, 25 seconds each | Passed: 939.775 / 1265.491 Mbps, router CPU 1.481% / 3.196%, native BND rows in both directions | `smoke-dual` |
| LAN1→WLAN UDP delivery | Passed: 2,888 packets; IPv4/IPv6, 16-byte/full-MTU payloads, DS 187/3, bursts 1/8/32/64/256; exact payload/sequence/TTL 64/DS/interface and no reordering | `udp-delivery` |
| Baseline, two link cycles, MTU 1500→1400→1500, off/reauthorize | Passed: ten 90-second flows; WLAN→LAN1 928.096–944.982 Mbps and LAN1→WLAN 1128.806–1236.199 Mbps; CPU 1.189–1.500% / 3.393–3.838% | `lifecycle-long` |
| Exact LAN1 FDB deletion and relearning | Passed: rows retired, both directions relearned, 938.807 / 1243.217 Mbps | `fdb-relearn` |
| Explicit off and nft mutation during LAN1→WLAN TCP | Passed: native references drained, software forwarding continued through each 40-second flow, then audited reauthorization and bidirectional recovery | `live-revoke-v3` |
| WLAN station disconnect/reconnect | Passed: station and native rows retired, new association relearned both directions with WCID 3 reused; post-reconnect 722.102 / 568.737 Mbps | `station-reconnect-v3` |
| WLAN↔WLAN with device 192.168.1.215, P1 | Passed: 35 seconds each direction, 486.610 / 505.639 Mbps, router CPU 4.454% / 4.361%; full data-phase rows/conntrack stable and NPU progress in every sample interval | `wifi-p1-v2` |
| WLAN↔WLAN with device 192.168.1.215, P4 | Passed: 35 seconds each direction, 582.983 / 641.078 Mbps, router CPU 4.519% / 4.847%, channel busy 78.805% / 75.425%; full data-phase rows/conntrack stable and NPU progress in every sample interval | `wifi-p4` |

The completed native throughput runs retained steady software conntrack counters
or bypassed conntrack for fresh flows while hardware counters advanced. FE fault
and drop counts stayed zero; the UDP run added exactly 2,888 completions. Long
lifecycle runs finished with submitted/completed counts equal and zero inflight
references. The eight post-baseline long flows were sampled through 85 seconds;
the baseline late interval was additionally reviewed in
`lifecycle-long/late-audit/offline-baseline-review.json`. The live revoke suite
finished restored at policy generation 41, `allowed=1`, `failed=0`.

Station reassociation changed its association timestamp from 33.967 to 2198.451
seconds, with teardown confirmed before the numeric WCID was reused. Its final
policy remained generation 41, `allowed=1`, `failed=0`. One initial read retried
after an SSH banner timeout. The P1/P4 WiFi suites used a verified, dedicated SSH
ControlMaster over LAN1 for one-second sampling and closed it during cleanup.
All four runs retained 35 positive full data intervals and final data sample
coverage within one second of the data-phase end. Whole-radio NPU RX drop
counter deltas were 0/1 for P1 and 0/6 for P4 (forward/reverse); the accepted
native data flows retained continuous NPU progress and stable rows/conntrack.

## Generic IPv4 management fallback correction

The fence1 native suites above passed. Repeated SSH connections then exposed a
deterministic LAN1-to-router IPv4 fallback failure. The initial comparison
completed 40/40 SSH connections with policy
off and 39/40 with policy on. A fixed-tuple off/on/off/on comparison then isolated
`192.168.1.120:50119 -> 192.168.1.1:22`: both off phases completed its SSH banner,
both on phases stalled after TCP connect, while adjacent source ports 50118 and
50120 succeeded in all four phases.

The failing 88-byte PSH/ACK was captured while the client socket remained open.
FE completed its generic PSE8 reinjection with submitted/completed equal,
inflight zero, and fault/drop zero; the router connection remained SYN_RECV with
one original packet. Its prefix word 5 was `63f00000 -> 80f00000`, retaining bits
22:20 from ingress. The same tuple reused PPE2 row `02630`, previously occupied
by IPv6 `fe80::495:2837:3ede:12a6:5219 -> fe80::879:6566:e00b:97ac:62341`.
Both tuples calculate to the same four-way SRAM hash0 bucket `02630`; a second
failure at `031a8` likewise followed an IPv6 occupant. Old IPv6 tail bytes remained
in these subsequent IPv4 UNB rows.

The fixed read-only host probe found LRO disabled in all netdevs and in both CDM
LRO enable registers. All 64 QDMA RX ring bases and indices were populated and
within range, with a uniform DMA/CPU index distance of three.

The ipv4meta1 firmware clears prefix word 5 bits 22:20 only for generic PSE8
IPv4 reinjection. Native destinations and generic IPv6 retain their metadata.
The host change since fence1 is the loader's 32-byte expected NPU code digest;
the remaining 27 source files in the matched FIT manifest are unchanged.

The deterministic comparison first created the exact IPv6 UNB row at `02630`,
recorded its state over a four-second quiet window, then let IPv4 source port
50119 reuse that same row. The old IPv6 row remained visible until replacement.
On fence1 this reproduced the banner timeout with RX `63f00000` and TX
`80f00000`; on ipv4meta1 the same trigger produced RX `63f00000` and TX
`80800000`, and all three test ports received complete SSH KEXINIT application
packets. The independent verifier checked exact tuples, row reuse, all eight
descriptor words, matching binary captures, policy/firmware identity, drained
FE ownership, and zero FE faults/drops. Six evidence mutations were rejected.
The first ipv4meta1 attempt delivered all three responses but captured a later
IPv6 neighbor solicitation; the second attempt supplied the matching IPv4
capture and passed the full check.

Original evidence resides under fence1 `management-off-on`, `fixed-tuple-off-on`,
`banner-probe`, `host-rx-observe-review.json`, and `seed-collision-v2`. The prepared
seed and independent verifier are in
`build/private-ram-trials/host-rx-readonly-fence1/`.

## Matched ipv4meta1 RAM regression

The final matched FIT SHA256 is
`b51cb02e5b80bd6c8cfcb121c800658da43afc91497c60965f9fa1a7e3cacde8`,
with NPU code SHA256
`90ca5df9a9bc6849869af08a66c9f81464dce1677af25e67ce7d36205cf581c3` and boot ID
`15e1a578-c302-41ed-a04d-5536b7eb13a6`. NAND remains disabled. Evidence is retained
under `build/private-ram-trials/native-lan1-source-abi3-ipv4meta1/`.

| Check | Result | Evidence subdirectory |
| --- | --- | --- |
| Exact IPv6→IPv4 SRAM collision | Passed: exact seed and replacement at `02630`, RX trigger metadata retained at ingress and cleared only in generic IPv4 TX, all three complete KEXINIT responses | `seed-collision-v2` |
| LAN1→WLAN UDP delivery | Passed: 2,888 packets; IPv4/IPv6, 16-byte/full-MTU payloads, DS 187/3, bursts 1/8/32/64/256; exact delivery | `udp-delivery` |
| Bidirectional WLAN/LAN1 TCP, 90 seconds each | Passed: 947.081 / 1204.344 Mbps, router CPU 1.209% / 3.103%, native rows and software conntrack steady through the sampled data windows; zero FE faults/drops | `dual-long` |
| LAN1 generic IPv4 authenticated SSH and data delivery | Passed: 128 independent connections, including fixed source port 50119; each sent and received 64 KiB with exact SHA256/output checks | `ssh-delivery` |

The SSH suite transferred 8 MiB in each direction across the 128 connections.
The router checked each uploaded block with SHA256; the client checked the
returned digest and all 64 KiB of response data. Every command exited zero.
The suite retained policy generation 31, `allowed=1`, `failed=0`, and finished
with FE submitted/completed equal, no inflight work, and zero FE faults/drops.

The final 951–954 patch chain applied with zero fuzz and reproduced all 28
source hashes in this FIT manifest. The matched kernel build completed with
zero warnings/errors; the kernel modules and device tree matched fence1. Final
patched-source host tests passed 981 ASan/UBSan cases and eight runtime mutation
checks on both macOS and Linux.

### Rearm regression and retained FE fault

The subsequent ipv4meta1 `live-revoke` and `live-revoke-v2` suites stopped during
bidirectional recovery after explicit policy off and reauthorization. In both
off phases, native references drained, FE became quiescent and all 28 sampled
post-revoke TCP intervals delivered data; the minimum interval rates were
661.238 and 666.924 Mbps. The first suite restored authorization after its
recovery assertion; the second reached an FE fault and its cleanup SSH failed.
The scheduled nft mutation stage was not reached.

The serial snapshot retained a 1,514-byte LAN1-to-WLAN IPv6 TCP frame selected
for native PSE4 forwarding, with TX prefix word 5 `0x40f00000`. FE submitted
14,571,918 packets and completed 14,571,917. The raw channel and global command
counters were `0x00de7281`, one beyond their captured start; their packet
counters stayed at the captured start `0x00de598d`. The WAIT watchdog recorded
one fault, zero drops and one inflight packet. The runtime `global_*_delta`
fields retained the preceding completed packet's values, so the fault's
completion status is taken from these raw counters.

Global FLUSH cleared all six active MAC-pair records while retaining pair 1's
single reference and token 16. Both PPE banks read FLOW zero and GLO
`0x0006070e`, with their enable bit cleared by fault handling. The software
owner stayed faulted with stop requested and quiescence incomplete. Raw evidence
is in `serial-runtime/` and `serial-fault-detail/` beside the two revoke suites.
Native rearm and recovery remained outstanding for this historical ipv4meta1
firmware at this stage.

### Fresh-boot recovery and wireless comparison

The same ipv4meta1 FIT was restarted as boot
`3d0d6d48-4ae1-44c8-a871-77d7ac5e1ba7`. The `recovery-live-revoke` suite
completed policy-off recovery: WLAN→LAN1 reached 891.689 Mbps and LAN1→WLAN
1239.311 Mbps, with router CPU 2.728% / 3.342% and zero FE faults/drops.
WLAN→LAN1 retained stable software conntrack counts; the new reverse flow
bypassed conntrack. All 28 post-off intervals delivered data, with a minimum
of 639.131 Mbps.

The nft mutation also revoked admission and delivered data in all 28 subsequent
intervals, with a minimum of 763.312 Mbps. Reauthorization then failed the
strict recovery check, `Software data or ACK counters advanced`. The suite
records `passed=false`, `restored=true`; cleanup ended at policy generation 33,
`allowed=1`, `failed=0`. Evidence is in `recovery-live-revoke/`, including
`off-recovery/` and `nft-recovery/`.

The following IPv6 TCP tests used the Mac's wireless interface and phone
`192.168.1.215` on the same 5 GHz radio. Each direction ran for 35 seconds;
values are ordered Mac→phone / phone→Mac. CPU is the router aggregate, and
channel busy is measured over the corresponding sampled radio window.

| Mode | Receiver Mbps | Router CPU | Channel busy | Evidence subdirectory |
| --- | --- | --- | --- | --- |
| Policy off, four streams | 251.284 / 228.163 | 31.348% / 32.077% | 54.755% / 63.257% | `recovery-wifi-p4-off` |
| Policy on, four streams | 730.422 / 561.473 | 4.818% / 4.250% | 83.951% / 92.341% | `recovery-wifi-p4-on` |
| Policy on, one stream | 698.167 / 613.009 | 5.249% / 5.009% | 75.937% / 84.474% | `recovery-wifi-p1-on` |

With policy off, native rows were absent and both conntrack directions advanced;
the busiest CPU core reached 87.195% / 85.324%. Cleanup restored authorization.
Both policy-on suites retained the two bank0 native BND rows after learning,
with no subsequent row change. Their 31–32-second stable windows showed ongoing
NPU progress, fixed forward-flow conntrack counts and no reverse-flow conntrack
entry. TDMA full/enqueue-failure counters and RX drop deltas were zero in those
windows. The complete one-stream suite recorded an RX drop increase of two
outside its stable windows; the four-stream suite recorded zero throughout.
Both suites finished at generation 33, `allowed=1`, `failed=0`.

This historical ipv4meta1 series ended with the FE WAIT fault and nft
reauthorization counter failure above. The subsequent first-fault diagnostic
and WLAN gate series records the Host error, PPE-stop caller and frozen NPU
state before the first fault. Its current source contract and reproducible
checks are described at the beginning of this document.


## Final hostbusy1 wireless peer check

After the long run, G7715 rejoined HG5585F-5G and the temporary isolation
timer was stopped. The same healthy RAM boot passed two 35-second, four-stream
Mac Wi-Fi/G7715 STA directions: Mac to G7715 304.109 Mbps and
G7715 to Mac 464.063 Mbps, with aggregate router CPU 2.559% / 2.572%.
Native rows, station association and conntrack remained stable; FE faults
and drops were zero. Evidence is
`build/private-ram-trials/native-lan1-source-abi3-hostbusy1/normal-en0-final1/`.
