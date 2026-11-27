# RAM GDM2 service loopback

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
captures the returning packets through an RX handler. It is not part of the
production image or overlay.

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
PON PPE qualification stays closed throughout. The final module exposes
only `prepare`, `send <decimal-service> [kind [variant]]` and `restore`.

## Packet kinds

Omitting `kind` preserves the existing `send <decimal-service>` command
and selects `ipv4`. Kind names are case-sensitive; unknown kinds and
trailing arguments fail with `-EINVAL`. The decimal service remains a
nonzero 16-bit number. For example, `send 8500 ipv6` selects service 0x2134.

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
with `--withdraw-cycle`, `--packet-matrix` or `--sif-sweep`.

```sh
python3 target/linux/airoha/tests/pon_offload/run_loopback_probe.py \
  --pin /absolute/path/to/known-hosts --boot BOOT_UUID \
  --module /absolute/path/to/matching-kernel987/ct_pon_loopback.ko \
  --sha256 MODULE_SHA256 --output /absolute/path/to/new-evidence-directory \
  --run --special-tag --cover-slot 1 --tuple-variants --exact-tuple --require-native

python3 -B -m unittest discover -s target/linux/airoha/tests/pon_offload \
  -p test_run_loopback_probe.py -v
```

The host self-check simulates SSH responses without contacting a board.
It covers exact and wide ring expectations, rejected option combinations,
preflight-only operation, per-field misses, incorrect baseline/service
routing, and withdrawal/restoration after command or observation failures.
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
