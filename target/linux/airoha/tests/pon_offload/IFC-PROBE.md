# RAM optical CPU classifier probe

Patches 976–979 connect the four-row optical owner to the shared classifier
and expose `ct_pon_cpu_probe` only on the explicit RAM native-pair profile.
The probe keeps PON PPE qualification at zero. Its current hardware milestone
is publication and restoration of CPU classifier rows for two independent
service IDs. Optical packet acceptance and service-isolated PPE forwarding
are the next milestones.

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
closing forwarding admission. Route changes close the classifier before
changing its CPU receiver.

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
`off` restores both slots. Status includes saved/dirty/active masks, pending
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
