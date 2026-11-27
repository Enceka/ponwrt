# RAM GDM2 service loopback

The NPU runner can extend `--learn` with `--bind-host-ip ADDRESS` and
`--bind-host-mac MAC` to exercise the learned row's LAN1 output. This needs
the ZT RAM diagnostic patch and ZU ownership protection. The receiver opens an ordinary UDP socket on
the supplied local IPv4 address and port 49153 before installing the row.
The entry keeps the original test tuple and translates its destination to
that receiver. Matching packets must arrive with the exact sequence and
previously captured cookie, with no QDMA or ER delivery. Tuple, family and
source-MAC and alternate-GEM mismatches must return through ER while the LAN
socket stays empty. Each close retires both banks and checks CPU return.

`bind-lan1 HASH ADDRESS MAC` accepts only a learned IPv4 UDP tuple in the
active diagnostic session. It closes and drains that session, then installs
one static BND entry into the verified empty row, checks write/read SRAM
acknowledgements and the complete row, republishes AUTH and reopens ingress.
`close` removes the binding; `release` also restores the saved bank settings
and releases the retained interfaces. The owner keeps production bank0/bank1
commit admission closed throughout the experiment.

The current covered-route acceptance is recorded in `../IFC-PROBE.md`.
With kernel patches through 984, the runner supports `--cover-slot 1`
plus either `--packet-matrix` or `--withdraw-cycle`. Add `--require-native`
to require the existing native policy to stay enabled and healthy before,
during and after every packet. The matrix verifies exact optical rings:
IPv4/IPv6/fragment service2134 selects RX2; other tested packets select RX4.
The withdrawal cycle also verifies the return to default WAN CPU RX0.

`--sif-sweep --sif-mode source|absent|only --cover-slot 1` selects the
32-source diagnostic in patch 983. It requires native policy disabled.
Each source replacement returns GDM2 to CPU before changing the owned
rows; the runner then requests the audited classifier route again.

This optional external test module submits bounded numbered packets through
the existing PON mapping and QDMA transmit interfaces. It owns a temporary
controller for an otherwise down `pon0`, enables GDM2 internal loopback, and
captures the returning packets through an RX handler. Its source is included
in the test overlay for reproducible host tests and optional external module
builds. The production image does not install or load the module.

The experiment established a no-fiber service-aware input path:

```text
PON flow mapping -> WAN QDMA TX GEM bits -> GDM2 TX special tag
-> internal loopback -> GDM2 RX special tag -> WAN QDMA RX GEM bits
```

With the existing GDM2 default route to CPU5, returning packets use WAN RX0.
Further IFC routing integration is required before using this path for
classifier-hit and PPE acceptance.

## Guards and lifecycle

The module accepts only the HG5585F-CT EN7581 RAM native profile, PON PPE
qualification closed, no CPU fallback, GDM2 NBQ0 mapped to CPU5, disabled
parallel NAND and optical controller nodes, and the high TX_DISABLE GPIO
hog. Preparation requires a down interface, no existing controller/mapping,
no pending transmit, no optical classifier owner and no active loopback.

`prepare` snapshots ten GDM2 registers and the optical VIP/IFC desired bits,
registers a local controller, opens the interface, and configures the mapping
through `airoha_eth_pon_update_begin/configure/update_end`. The temporary
controller's start callback restores GDM2 CPU forwarding before returning.
The same transaction interface changes GEM for each send. The module sends
one 70..130-byte frame per `send`, waits up to 100 ms for TX completion, and
observes RX for another 20 ms. The handler accepts marked packets during
this send window. Its marker contains magic, sequence, a per-load random
cookie, kind and transmitted frame length, each a big-endian 32-bit word.
Only a marker matching the currently submitted packet is consumed.

`restore` first requires optical classifier withdrawal, stops transmission,
removes mappings through the transaction API, disables loopback, removes
the handler/controller, closes the interface, then restores and reads back
registers. Saved state and a self-reference are retained until successful
restoration, so a failed restore keeps the module available for retry.

Use the command file with a single write, for example `echo prepare >
/sys/kernel/debug/ct_pon_loopback/command`. Splitting the command and newline
across separate writes creates two requests. The runner uses `echo`.

The runner pins SSH identity and boot UUID, verifies empty MTD, records all
outputs and return codes, temporarily disables IPv6 autoconfiguration on
`pon0`, and restores that setting after closing the interface. It configures
two CPU service rows, transmits A/B/A, withdraws both rows, checks restoration,
and unloads the module. A hardware failure retains logs and ownership; use
the pinned RAM boot recovery procedure if restoration cannot finish.

## Special-tag reconstruction

The optional `special_tag=1` configuration independently reproduces the
documented fields of the stock `fe_set_gdm2_sptag_for_loopback` interface:

- GDM2 channel0 registers at FE offsets `0x1740/44/48/4c`.
- Six 5-bit selectors per first two words, four in the third word: select
  packet flow bits 16 through 31, preserving unrelated fields.
- Clear TX bypass bit31 in `0x1748`.
- Set both RX and TX operation mode to 1 in `0x174c`, preserving other bits.

Stock reference: SHA-pinned `fe_core.ko`, function `0x2620`, existing
`pon-fe-service-producer-v5` investigation. The module is independently
written and does not load stock instructions onto the board.

## Build and run

### Prepare the PON NPU payload

`../prepare_npu_ram.py` binds a RAM trial to an accepted RV32 ELF. It checks
the ELF, code and data hashes against `ram-payload.json`, requires ABI3/caps63,
the PON AUTH/GATE/ER feature set and valid local SRAM bounds, and matches the
input kernel's RAM loader digests against the baseline initramfs. The input
acceptance JSON must contain `passed: true` and the matching `elf_sha256`.

```sh
python3 -B target/linux/airoha/tests/pon_offload/prepare_npu_ram.py \
  --payload /absolute/path/to/an7581-npu-firmware/build \
  --acceptance /absolute/path/to/rv32-acceptance.json \
  --archive /absolute/path/to/verified-base.cpio \
  --loader /absolute/path/to/kernel/drivers/net/ethernet/airoha/airoha_npu.c \
  --output /absolute/path/to/new-prepared-directory
```

The new output directory contains `airoha_npu.c`, `pon-npu.cpio` and
`prepared.json`. Copy the generated loader to the RAM kernel build tree and
build `Image` with `CONFIG_INITRAMFS_SOURCE` explicitly pointing to the new
archive. Rebuild any private-structure test module against that kernel.
The preparer preserves archive names, metadata and all contents except the
two rebuilt firmware entries, and rejects duplicate paths, hard-linked
firmware, trailing archives and mismatched loader hashes. It does not modify
the baseline files or the packaged full-image firmware profile.

On 2026-11-27 the accepted PON ELF
`0b74984174d0c09f4f3fa4ede3a7fd1a61021931b363cc94e8081c9e815729d0`
produced code hash
`80af8190975befbda72022896b6cc87e4e17248cfc6820b93fba0bd19be49649`.
The code occupies 39,052 bytes; local SRAM ends at `0x3e9037c4`, leaving
four bytes below its reserved boundary. Preparing the accepted baseline
preserved 1,101 entries and changed only the rebuilt RV32 code entry.
Run the preparer tests with:

```sh
python3 -B -m unittest discover -s target/linux/airoha/tests/pon_offload \
  -p test_prepare_npu_ram.py -v
```

### Build the loopback module

The opt-in `999-zk` diagnostic uses an additional RAM DT marker,
`airoha,connac2-pon-er-diagnostic`, on the Ethernet node. Its
`/sys/kernel/debug/ppe/pon_npu_diag` file accepts `start`, `close` and
`release`, and reports AUTH/GATE/ER capabilities, ownership, bank1 registers,
and the most recent accepted ER descriptor and frame. The session uses an
empty AUTH table and keeps PON qualification closed and bank1 FLOW zero.
Its identity includes the lower interface and its current controller.

Prepare the module, then issue `map 0` before starting the diagnostic.
`send-current ipv4` and `send-current ipv6` transmit numbered packets using
that existing mapping. Mapping changes and ordinary `send` commands require
the NPU owner to be released. `restore` also requires owner release.
`close` drains and unbinds ER; `release` restores the saved bank1 registers
and relinquishes FE/route ownership. Errors retain the session for recovery.

`../pack_npu_ram.py` packs the resulting ARM64 Image into a SHA-pinned
baseline RAM FIT, verifies the embedded prepared archive and loader digests,
adds only the diagnostic DT marker, and checks final resident configuration
and RAM ranges. Supply `--kernel-sha256` from the build environment before
copying the Image; the full-file check catches truncated exports even when
the embedded initramfs remains complete. Its `--image-helper` argument points to the project's FIT
parser (`fctory-op/5585f/tools/image.py`); the report records that helper's hash.

`../run_npu_loopback.py` pins the SSH host key, RAM boot UUID, module and
firmware hashes. Preflight requires optical TX disabled, empty MTD, idle
native policy/classifiers and GATE/AUTH/ER capabilities 15/7/15. With `--run`,
it sends 18 alternating IPv4/IPv6 packets for each of service0 and 0x8000,
checking full GEM, SPORT2, transaction identity and numbered ER payloads.
Each session also checks two CPU returns after close. Cleanup checks all
ten loopback registers, bank1 registers and released ownership before
unloading the module. Run with `--help` for the required artifact arguments.

Build against the exact source/configuration of the running RAM kernel; the
test uses private driver structures. The test directory must have its own
copy of the two module source files when using an external build directory.

```sh
make -C /path/to/matching/kernel ARCH=arm64 CROSS_COMPILE=/path/to/aarch64-prefix- \
  M=/path/to/module-build-directory modules

python3 target/linux/airoha/tests/pon_offload/run_loopback_probe.py \
  --pin /absolute/path/to/known-hosts --boot BOOT_UUID \
  --module /absolute/path/to/ct_pon_loopback.ko --sha256 MODULE_SHA256 \
  --output /absolute/path/to/new-evidence-directory --run --special-tag
```

Omit `--run` for preflight only. Omit `--special-tag` for the control run.
PON PPE qualification stays closed throughout. The module exposes
`prepare`, `map <service>`, `send <decimal-service> [kind [variant]]`,
`send-current <ipv4|ipv6>`, `send-fixed <ipv4|ipv6> <0..4> <rx|tx>` and
`restore`.

## Fixed-MAC packets on the current mapping

```text
send-fixed <ipv4|ipv6> <variant 0..4> <rx|tx>
```

Each command submits one 128-byte Ethernet frame using the current service
mapping. The source MAC is `02:00:00:00:00:01`; the destination is the current
`probe_netdev->dev_addr` of `pon0`. Both families use UDP source port 49152 and
destination port 49153. IPv4 addresses are `192.0.2.1` to `192.0.2.2`; IPv6
addresses are `2001:db8::1` to `2001:db8::2`.

| Variant | Tuple change |
| --- | --- |
| 0 | Baseline tuple |
| 1 | Source address low word +1 |
| 2 | Destination address low word +1 |
| 3 | UDP source port 49153 |
| 4 | UDP destination port 49154 |

For the first RAM `start-auth <service>` diagnostic, map that service before
starting the session. `send-fixed ipv4 0 rx` supplies the exact AUTH tuple;
variants 1 through 4 supply one-field mismatches on the same service, such
as `send-fixed ipv4 1 rx`. `send-fixed ipv6 0 rx` supplies a family mismatch
for an IPv4-only AUTH rule.
Both CPU and ER returns delivered to `pon0` can satisfy `rx`. Inspect the
diagnostic ER counters and QDMA receive counters to distinguish those paths.
Use `tx` when testing an output that does not return through `pon0`.
The sender preserves the diagnostic's FLOW/no_learn settings. AUTH setup,
PSE4/ER routing and bank0 PPE learning remain kernel diagnostic operations.

`rx` waits up to 100 ms for TX completion and then up to 100 ms for the
matching sequence/cookie/kind/length RX marker. `tx` waits up to 100 ms for
TX completion and returns without an RX requirement, for ER or LAN egress
checks. A matching RX that arrives during the TX wait can still be recorded;
RX arriving after the command returns follows the normal receive path.
For example, `send-fixed ipv6 3 tx` sends one IPv6 source-port mismatch.
Inspect egress counters or capture the packet at the LAN endpoint when
testing a LAN route.

The command accepts exactly four tokens, with case-sensitive family/mode
and a single variant digit `0` through `4`. Extra arguments, signed or
multi-digit variants, embedded NULs, and writes of 64 bytes or more return
`-EINVAL`. Whitespace and a trailing newline are accepted. The existing
sequence, per-module cookie and 130-byte maximum frame bound are retained;
current-mapping commands return `-EOVERFLOW` at sequence `0xffffffff`.

The prepared interface must be open and its single-service mapping, carrier
and update state must still match. Drift returns `-ESTALE` before submission.
An existing NPU owner is allowed; no mapping transaction or owner change is
performed. `map`, ordinary `send` and `restore` keep their owner guards.
`send` and `send-current` retain random source MACs, and `send-current`
continues to wait for RX. Status adds `tx_fixed` and `tx_wait_rx`; `tx_variant`
remains the tuple variant 0 through 4.

Run the production-function host tests locally:

```sh
python3 -B /Volumes/Workspace/5585f/build/ponwrt/target/linux/airoha/tests/pon_offload/ram_loopback/verify_commands.py
```

The runner extracts the actual command parser, mapping checks, transmitter
and RX functions from `ct_pon_loopback.c`. Plain and ASan/UBSan runs cover
60 fixed packets across both families, all five variants, both wait modes
and services 0/0x8000/0xffff. Tests verify the emitted MAC/IP/UDP/marker bytes,
mapping preservation under an owner, 13 mapping drift cases for each sender,
strict parsing, allocation/TX failures, separate TX/RX deadlines, sequence
exhaustion and legacy random-MAC behavior. Mutation controls must
fail assertions, including changed MACs, lost variants, skipped TX waits,
unwanted RX waits and relaxed parser/mapping guards. Kernel dependencies,
including checksum helpers and device queues, use local stubs; build the
module against the matching RAM kernel before board testing.

`map-pair <service> <alt_service>` installs two mappings with pbit masks
`0x7f` and `0x80`. Both services must fit 16 bits and differ, and mapping
changes require owner release. `send-fixed-alt ipv4 0 rx` selects the second
mapping using TX VLAN metadata (pbit 7) and submits the untagged fixed frame
directly under the netdev TX lock. The frame retains the original tuple and
MAC addresses. Tests cover stale alternate mappings, malformed commands,
TX busy, and failure/retry at every mapping transaction stage.

## Dual-bank board acceptance — 2026-11-28

The dual-bank RAM FIT (`2f88fe7b548c239073944bb9a517eacd14d96756b88c17fdae584fddcc034fe8`)
passed learning, LAN1 binding and cross-GEM isolation for services 0 and
0x8000. Bank1 stayed closed to lookup/learning; bank0 learned only the
authorized tuple at `0x0458`. Each service passed nine bound samples:
two exact matches reached the LAN1 UDP receiver and seven mismatches
returned through ER. Mismatches include an alternate GEM with the same
tuple and source MAC. QDMA CPU receive counters stayed unchanged during
the bound matrix. Close cleared both banks; release restored both banks'
saved registers. Empty-AUTH and exact-AUTH regressions also passed.

Evidence lives under workspace `build/pon-npu-diag-20261127/` in
`board-dualbank-bound-v1/report.json`, `board-dualbank-empty-reg/report.json`
and `board-dualbank-auth-reg/report.json`. Production integration next needs
dynamic flow publication and bank0 sharing with ordinary/native traffic.

## Packet kinds

Omitting `kind` preserves the existing `send <decimal-service>` command
and selects `ipv4`. Kind names are case-sensitive; unknown kinds and
trailing arguments fail with `-EINVAL`. The decimal service is in the
inclusive range 0..65535. For example, `send 8500 ipv6` selects service
0x2134, and `send 0 ipv6` selects service0. Mapping validity is explicit:
preparation and sends configure a service with `enable=true`; restoration
withdraws it with `enable=false`.

Patch `999-zf` adds matching zero-service CPU diagnostics, including exact
tuple checks and coexistence with typed wildcard covers. The independent
host lifecycle, fault-injection and full transmit tests are documented in
`../service0/README.md`. The board runner defaults to its existing nonzero
matrix; `--service-zero` selects the zero-service matrix below.

## Service0 without fiber

Use a RAM kernel and matching loopback module containing the service0 fix
from commit `af7a05b` (`999-zf`). Keep the optical TX_DISABLE hog high,
MTD empty, PON PPE qualification closed, and the NPU owner released before
starting the CPU diagnostic. The runner retains boot UUID and SSH host-key
pins on every remote command, checks idle classifier state and tuple pool,
and leaves owner arbitration to the existing kernel interfaces. An owner
conflict returns an error; the runner does not release another owner.

`--service-zero` requires `--special-tag --cover-slot 1` and rejects
`--sif-sweep`. It sets A=0 and B=0xa134, installs `cover 1` followed by
`set 0 0`, then enables the audited route. The exact rule selects RX2;
the typed wildcard cover selects RX4. The default zero matrix sends
A/B/A for IPv4, then A/B/A for IPv6: six packets with expected rings
`2,4,2,2,4,2`. A zero service is always a configured key; explicit
`clear` and `off` commands withdraw rules.

Add `--withdraw-cycle` for 18 packets. After the six initial packets,
each row below sends IPv4 followed by IPv6; its commands run once before
the IPv4 packet:

| Transition | Service | Expected ring for both families |
| --- | --- | --- |
| `clear 0`, `route` | 0 | RX4 |
| `set 0 0`, `route` | 0 | RX2 |
| `clear 1` | 0 | RX2 |
| None | 0xa134 | RX0 |
| `clear 0` | 0 | RX0 |
| None | 0xa134 | RX0 |

The runner checks active-row bits, cover bits, the zero service values,
pending/ready state and closed qualification after every transition and
packet. Each packet must return the current sequence, requested kind,
complete 16-bit service, SPORT2 and expected receive ring. A wrong service,
source or ring stops the matrix immediately and enters the existing cleanup
path. `report.json` includes `service_zero`, numeric `service_a`/`service_b`,
each transmitted and returned service, expected/observed ring and transition
commands. Transition readbacks are saved before the next command or packet.

Run from the ponwrt repository with the current RAM boot's pins and module:

```sh
python3 -B target/linux/airoha/tests/pon_offload/run_loopback_probe.py \
  --pin /absolute/path/to/known-hosts --boot CURRENT_RAM_BOOT_UUID \
  --identity /absolute/path/to/ssh-key \
  --module /absolute/path/to/matching/ct_pon_loopback.ko --sha256 MODULE_SHA256 \
  --output /absolute/path/to/new-service0-evidence \
  --special-tag --cover-slot 1 --service-zero --withdraw-cycle --require-native
```

This command performs preflight only. Add `--run` to execute the 18-packet
matrix. Omit `--identity` when the pinned SSH configuration already selects
the key. Each invocation needs a new output directory.

The existing tuple modes also accept `--service-zero`: add
`--tuple-variants --exact-tuple` to run `tuple 0 0` with all five tuple
variants for both services and families. This sends 20 packets, with only
the two A/variant0 packets selecting RX2. Keep `--withdraw-cycle` for the
existing 28-packet tuple withdrawal/reinstall matrix, using service0 for A.
Its lease release, reacquisition and retention checks remain enabled.
`--tuple-variants` without `--exact-tuple` runs 20 wide-service packets;
`--packet-matrix` runs the existing 14 packet-kind cases with A=0. These
two optional matrices replace the basic A/B/A matrix and retain their
existing option restrictions.

Cleanup sends classifier `off`, restores the module's mapping and ten
registers, verifies idle classifier/pool state, unloads the module, and
restores IPv6 configuration. Failed withdrawal or restoration retains
the loaded module and per-command stdout/stderr/status evidence for recovery.

## 2026-11-27 service0 board acceptance

The kernel through `999-zi` booted the rebuilt NPU once after provider binding
and registered its packet pool. RAM FIT SHA-256:
`56c023b9cbb2b637302f901f910b48bb3d806dc428a1d4f85d4a6a89884f5e26`.
The matching external module SHA-256 is
`204bf87c4b97db4f0df7f756089fc95cf473a9858cdcb115b7aed33110dcd1a6`;
its Ethernet/PPE structure layouts matched the kernel's DWARF records.

On boot `ceb1871b-e673-43f5-9cb8-f452aa091ed2`, the service0 dual-stack
withdrawal matrix passed all 18 packets and the exact-tuple withdrawal matrix
passed all 28 packets. Each numbered packet preserved service and SPORT2,
and selected the expected RX2, RX4 or default RX0 ring. Both runs released
tuple leases, restored all ten registers and unloaded the test module.
PON PPE qualification stayed closed and CPU fallback stayed clear.

Native policy remained disabled because the expected wireless station had
joined another network; native coexistence is a separate pending board run.
Evidence is under `/Volumes/Workspace/5585f/build/pon-bound-start-board/`:
`service0-withdraw/report.json`, `service0-exact-withdraw/report.json`,
`sealed.json` and `acceptance.json`. The firmware payload and 1101 initramfs
entries match the previously accepted RAM image. No flash write was performed.
Default runs without `--service-zero` keep A=0x2134, B=0xa134 and their
existing packet sequences and commands.

Host validation on 2026-11-27 passes 28 tests, including both zero-service
families, all existing optional matrices, every wrong destination in the
zero basic/withdrawal/exact-tuple matrices, service/source/sequence/state
corruption, command failures, owner conflicts and failed cleanup retention.
The tests mock SSH locally. The log is in the enclosing workspace at
`build/pon-service0-runner-20261127/unittest-v1.log`; this change prepares
the executable board procedure without running it on a device.

All frames target the local `pon0` MAC and use a locally administered
random source MAC. IPv4 uses documentation addresses 192.0.2.1/192.0.2.2;
IPv6 uses 2001:db8::1/::2. UDP ports are 49152/49153. No neighbor lookup,
external route, socket or external endpoint participates in construction.
The existing internal-loopback and TX_DISABLE prerequisites remain in
force. The module does not add a route-to-PPE command.

Lengths below include the Ethernet header and exclude FCS:

| Kind | Frame bytes | Inner format and length | Marker location |
| --- | ---: | --- | --- |
| `ipv4` | 128 | IPv4 IHL5, total 114, UDP 94 | UDP payload |
| `ipv6` | 128 | Basic IPv6, payload 74, UDP 74 | UDP payload |
| `arp` | 128 | Ethernet/IPv4 ARP request, standard 28-byte ARP body | Private experiment trailer immediately after ARP body |
| `vlan` | 128 | One 802.1Q tag, VID37, IPv4 total 110, UDP 90 | Inner UDP payload |
| `pppoe` | 128 | PPPoE session 1, code 0, length 108; PPP protocol 0x0021; IPv4 total 106, UDP 86 | Inner UDP payload |
| `fragment` | 130 | IPv4 total 116, MF=1/offset=0; 96 bytes of fragment payload, UDP declared 104 | First fragment's UDP payload |
| `short` | 70 | IPv4 total 56, UDP 36 | UDP payload |

Every IPv4 header has a software checksum. IPv4 UDP uses its permitted
zero checksum. IPv6 UDP has a mandatory computed pseudo-header checksum,
with a computed zero encoded as 0xffff. PPPoE session data has no discovery
exchange: its locally fabricated session header is an encapsulation probe.
ARP retains a standard request body; the identifying trailer is private
experiment data, not an additional ARP field.

`fragment` is an intentional first fragment of an incomplete datagram.
Its 96-byte non-final IP payload is eight-byte aligned; UDP declares eight
more bytes than this fragment carries. No tail fragment is sent. `short`
is a complete, well-formed small IPv4/UDP packet: total 56 deliberately
falls inside the existing 20..57 IPv4 short-LUT interval. The RX handler
consumes both before host reassembly or ordinary protocol handling.

The RX handler starts from `skb->protocol` and bounded `skb_copy_bits`
reads. It accepts a single inline VLAN header or a stripped VLAN packet,
checks PPPoE length/protocol, and validates fixed IPv4/IPv6 and UDP header
boundaries before locating the marker. IPv4 options, IPv6 extensions,
non-first fragments, unexpected protocols, truncated headers and mismatched
markers pass to the normal receive path. A frame over 130 RX skb bytes
also passes. A VLAN-kind packet with stripped tags is identified by its
current sequence/cookie/kind marker even if RX presents plain IPv4.

Status retains the original counters and adds `tx_kind`, `tx_length`,
`rx_kind` and `rx_length`. `tx_length` is the complete submitted Ethernet
frame. `rx_length` is `skb->len` at the RX handler, after Ethernet removal
and any VLAN stripping. For an unchanged frame, expect RX length 14 bytes
below TX length; stripped VLAN removes another 4. The existing `sequence`
and `rx_sequence` distinguish a new TX from the last successful marked RX.
All lengths and kinds are diagnostic observations, independent of the
runner's per-packet service/ring/native-health checks.

## Tuple packet variants

For `ipv4` and `ipv6`, an optional decimal variant selects one changed
tuple field. Variant 0 is the baseline; 1 increments the source address,
2 increments the destination address, 3 increments the UDP source port,
and 4 increments the UDP destination port. Address changes affect the low
word only. The remaining tuple fields and frame lengths stay identical.
IPv4 header and IPv6 UDP checksums include the changed fields.

For example, `send 8500 ipv6 3` uses source port 49153. Other packet kinds
accept only variant 0. Invalid variant text, values above 4 and extra
arguments fail with `-EINVAL`. Status reports `tx_variant` for each send.

Use `--tuple-variants --cover-slot 1 --special-tag --require-native` to
exercise both families, all five variants and both service IDs: 20 packets
in total. This retains the wide service classifier regression;
every variant of service 0x2134 selects RX2, while service 0xa134 selects RX4.
The runner checks returned kind, marker, service, source, receive ring and
native policy, then withdraws the classifier and restores the module.

Add `--exact-tuple` for the kernel987 exact classifier. It requires
`--tuple-variants --cover-slot 1 --special-tag` and uses `cover 1`,
`tuple 0 0x2134`, then `route`. Slot0 matches the fixed IPv4/IPv6 UDP
tuples above and the complete service ID; slot1 provides the typed PON
CPU cover. Only service 0x2134 with variant 0 selects RX2: two packets,
one per family. The other 18 packets select RX4, including every changed
address/port and every service 0xa134 packet. The runner records
`exact_tuple` and each packet's `expected_ring` in `report.json`.
PON PPE qualification stays closed. Exact mode uses the existing `off`,
`restore`, ten-register verification and module-unload sequence, including
after a packet mismatch or classifier-command failure. It cannot combine
with `--packet-matrix` or `--sif-sweep`.

Add `--withdraw-cycle` to exact mode for a 28-packet withdrawal/reinstall
matrix. The original 20 packets still require two RX2 and 18 RX4 returns.
Eight packets follow to check removal, reinstallation and partial withdrawal:

| Transition before send | Packet | Expected ring | Tuple pool after transition |
| --- | --- | --- | --- |
| `clear 0`, `route` | IPv4, service 0x2134, variant 0 | RX4 | Entire tuple pool released |
| `tuple 0 0x2134`, `route` | IPv4, service 0x2134, variant 0 | RX2 | 14 occupied slots, two leases, no pending command |
| `clear 1` | IPv4, service 0x2134, variant 0 | RX2 | Same pool mask and two leases retained |
| None | IPv6, service 0x2134, variant 0 | RX2 | Retained |
| None | IPv4, service 0xa134, variant 0 | RX0 | Retained |
| None | IPv6, service 0x2134, variant 1 | RX0 | Retained |
| `clear 0` | IPv4, service 0x2134, variant 0 | RX0 | Entire tuple pool released |
| None | IPv6, service 0x2134, variant 0 | RX0 | Released |

`clear 1` removes only the cover. Slot0's exact tuple consumer and its leases
remain active. `routed=0` records restoration of the GDM2 default destination
to CPU5; enabled IFC consumers still select their CPU ring. Both matching
families therefore use RX2, while service and tuple misses use default RX0.
The final `clear 0` removes the remaining consumer and releases its leases,
after which both baseline families use RX0.

The runner reads back pool ownership after every transition, before the
next command or packet, and checks it again on every packet observation.
Reinstallation may allocate a different mask; that mask must remain
unchanged through cover withdrawal until the final `clear 0`. Transition
readbacks are saved as `send-N-transition-M-state.stdout`; `report.json`
records `withdraw_cycle`, commands and explicit per-case `expected_ring`.
The existing eight-packet wide-service withdrawal run remains available
without `--tuple-variants`; wide-service tuple variants plus withdrawal
are rejected.

```sh
python3 target/linux/airoha/tests/pon_offload/run_loopback_probe.py \
  --pin /absolute/path/to/known-hosts --boot BOOT_UUID \
  --module /absolute/path/to/matching-kernel987/ct_pon_loopback.ko \
  --sha256 MODULE_SHA256 --output /absolute/path/to/new-evidence-directory \
  --run --special-tag --cover-slot 1 --tuple-variants --exact-tuple --require-native
```

Add `--withdraw-cycle` to the invocation above for the 28-packet matrix.

```sh
python3 -B -m unittest discover -s target/linux/airoha/tests/pon_offload \
  -p test_run_loopback_probe.py -v
```

The host self-check simulates SSH responses without contacting a board.
It covers exact and wide ring expectations, rejected option combinations,
preflight-only operation, per-field misses, incorrect baseline/service
routing, the 28-packet exact and eight-packet wide-service withdrawal
matrices, pool release/reacquisition/retention, and cleanup after transition
or observation failures. Failed withdrawal/restoration retains the module
and the per-command evidence for recovery.
Build the external module against the running kernel987 source/configuration
before the board run.

On 2026-11-27, all 20 tuple-variant packets passed on RAM kernel984, boot
`986bed54-e67d-4baa-ac06-0627f74789a2`. Every returned sequence, cookie,
kind, full service and SPORT2 matched; A selected RX2 and B selected RX4.
The ten saved registers were restored, the classifier was cleared and the
module unloaded. Native policy remained `generation=49 allowed=1 failed=0`,
with `ct_cpu_fallback=0`. The final Wi-Fi HTTPS check returned 200.
PON PPE qualification remained closed throughout this CPU-classifier test.

The candidate module SHA256 was
`30ad89ef0a3c07587203404451dce3d5d7c17a2d3248332065190ae4a73a3dd7`,
built against `/workdir/pon-sif-984` in `/workdir/pon-tuple-module.mN4wKd`.
Its updated receive functions also passed 575 ASan/UBSan cases: the existing
545 parser cases plus 30 matching/mismatched-port cases over both families
and all variants. Build, parser, 20-packet and final Wi-Fi evidence is under
`/Volumes/Workspace/5585f/build/pon-tuple-variants-985-board`.

The runner rejects Python `-O` before accessing the device, so preflight,
packet and restoration assertions remain enabled.

The packet-kind candidate is built separately in
`/workdir/pon-cover-module-types` against `/workdir/pon-cover-982`, using
the matching OpenWrt toolchain and original module Makefile. Private
driver structures and controller/mapping lifecycle remain unchanged.

Local validation extracts the actual `marker_offset` and `receive`
functions into a bounded skb harness. Its 545 ASan/UBSan cases cover all
seven formats, truncation before the complete marker, each marker byte,
wrong protocol, oversized input, stripped VLAN, PPPoE length errors,
IPv4 fragment flags/offsets and an unsupported IPv6 extension header.
The harness uses independent packet fixtures; transmit construction is
compiled as part of the real module. Inputs, extracted harness, compiler
logs and `rx-parser-result.json` are in `/workdir/pon-cover-module-types`.
No packet-kind board run is included in this validation.

## Board evidence — 2026-11-27

Kernel source through `636e43a`, FIT SHA256
`66a83bd12a402db83669f8834d7930b6ae4651c8eaf6dbc44fd57b4c0d7ee7ef`.
Final board boot: `b36fb065-cbbb-4b04-8abf-84e2d3275e84`.
Module SHA256:
`5350d71a9a2d51f4df7e3aa875ec80be1a544e559f4c52d9311fb313cfe99e42`.

| Configuration | Sent service IDs | Returned service IDs | Numbered RX | Destination |
| --- | --- | --- | --- | --- |
| Existing tag setup | `2134/a134/2134` | `0000/0000/0000` | 3/3 | SPORT2, WAN RX0 |
| Rebuilt special-tag setup | `2134/a134/2134` | `2134/a134/2134` | 3/3 | SPORT2, WAN RX0 |

With rebuilt tags, RX message0 was `084d0000/284d0000/084d0000` and the
numbered packets' message1 was `285e0000`. Thus `(msg0 >> 14) & 0xffff`
preserves the service high bit, and `(msg1 >> 21) & 31` is 2. Each run
completed all three sends, restored all ten register values and unloaded.
The host runner records command completion, numbered return, service
preservation and register restoration as separate results.

Evidence: enclosing workspace `build/pon-loopback-board.i9nyacd5/`, especially
`final-plain/`, `final-special-tag/`, and `final-wifi/`.

An earlier research-only route-to-PPE2 variant sent its first packet without
an RX return, then NPU native-health command 6 returned `-EIO` and entered
sticky CPU fallback. Later packets returned through that fallback. Its log
is retained in `run-classifier/`; that variant is absent from the final
module. Recovery booted the verified RAM FIT, restored WAN and audited native
policy (`generation=41 allowed=1 failed=0`), and verified Wi-Fi HTTPS 200.
NAND remained disabled. The next classifier experiment needs explicit
unmatched-service CPU protection and owned route transitions before changing
the default GDM2 path.
