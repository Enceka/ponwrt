# RAM GDM2 service loopback

This optional external test module submits numbered IPv4/UDP packets through
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
one 128-byte frame per `send`, waits up to 100 ms for TX completion, and
observes RX for 20 ms. The packet carries a magic word and monotonically
increasing sequence number; the handler consumes only those packets.

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
only `prepare`, `send <decimal-service>` and `restore`.

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
