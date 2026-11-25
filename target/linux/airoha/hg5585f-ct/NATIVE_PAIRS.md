# Connac2 native WLAN pair RAM trial

Patches 951 and 952 add a source-built NPU loader and an explicit native
wireless pair policy. They apply after 950 and retain 948's flow-admission
diagnostics. The stock image keeps its existing defaults. The native trial
requires the RAM-only device-tree properties and a matching firmware bundle.

## Source and firmware identity

Build the NPU source with all four profile selections:

```sh
make CT_BRIDGE_GUARD=2 CT_SHORT_PAD=1 CT_TDMA_BANK=2 CT_NATIVE_PAIRS=1 all ram-payload
```

Use the compiler pinned by the NPU repository and verify `build/ram-payload.json`.
The loader in 951 checks these payloads and reads the loaded bytes back:

| Image destination | SHA256 |
| --- | --- |
| `/lib/firmware/airoha/hg5585f-ct/npu_rebuilt_rv32.bin` | `22c266541faa7235bef12a36f5e1b08e44d0bb119b7a2d495b3b17ecc57dabe4` |
| `/lib/firmware/airoha/hg5585f-ct/npu_rebuilt_data.bin` | `df3f619804a92fdb4057192dc43dd748ea778adc52bc498ce80524c014b81119` |

These are the generated `ram-npu_rv32.bin` and `ram-npu_data.bin`, respectively.
Code occupies 23,156 bytes at NPU address `0x84000000`; data occupies four bytes
at `0x3e900000`. Firmware changes require a corresponding source update to the
loader digest table and a rebuilt kernel.

Start from the existing `ram-dts.py` Connac2 RX/host-PPE trial DTS with the live
factory EEPROM and the existing WED configuration. Add the following booleans
to its NPU and Ethernet nodes, respectively:

```dts
/* NPU node */
airoha,connac2-rebuilt-ram-lab;

/* Ethernet node, alongside airoha,connac2-host-ppe */
airoha,connac2-ram-native-pairs;
```

Keep the existing RAM trial's NAND-disabled configuration. The native policy
starts off on every boot. The Ethernet driver requests the native mailbox
capability before selecting the native bank layout.

## Kernel and module bundle

Rebuild the kernel and its modules together. Include `kmod-nft-core` and
`kmod-nft-bridge`; the existing package definitions install and autoload
`nf_tables.ko`, `nft_meta_bridge.ko` and `nf_conntrack_bridge.ko`. Use modules
from this kernel build in the initramfs.

The bridge meta companion is required when `CONFIG_NFT_BRIDGE_META=m`:
the rebuilt generic meta selector delegates bridge expressions to that module.
The rebuilt conntrack bridge module tags its three hooks with the newly
appended `NF_HOOK_OP_BRIDGE_CT=4`. Existing hook type numbers and public NPU
operation offsets remain unchanged.

For an existing RAM initramfs, replace `nf_tables.ko` and
`nf_conntrack_bridge.ko`, add `nft_meta_bridge.ko`, and ensure the meta companion
loads before firewall rule installation. A normal OpenWrt build with the
packages above generates those dependencies. The private FIT repacker is a
separate lab convenience; it is not part of this source contract.

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
Before enabling, also verify the two stations are authorized, their FDB entries
point to the expected WLAN ports, the ports are forwarding, the bridge has no
VLAN filtering, and isolated/locked flags are clear. Same-port peers require
hairpin mode. Recheck the boot identifier and captured generation before writing
`whole-mac-ip GENERATION` to sysfs. A stale generation returns `ESTALE`.

Enabling an empty table only sets authorization. The first successful software
bridge forwarding event creates the directed pair. Reverse traffic creates the
reverse pair. Admission checks current MACs, station/WCID/BSS, FDB placement,
bridge generation and endpoint epochs. The subsequent learned bank0 L2B row
becomes BND after those identities match. Up to four row hashes are retained for
each directed pair.

PPE bank0 uses FLOW `0xb200` for native WLAN L2B traffic; bank1 uses `0x3200`
for route-format flows. Physical GDM ingress selects bank1. Native rows preserve
DSCP/ECN and IPv6 flow labels. The firmware handles simple IPv4/IPv6 TCP and UDP,
including short frames using padding; fragments, IP options, IPv6 extension
headers and TCP FIN/RST use the host path.

Writing `off` closes admission, waits for both PPE completion FIFOs, then clears
owned matching bank0 rows. nft changes close authorization before their new
policy publishes. Station teardown, FDB moves and bridge changes revoke affected
pairs through the same completion contract. An uncompleted revoke stops the
native path and sets `failed=1`.

## Repeatable host checks

From the OpenWrt repository root, point the runner at its prepared Linux tree:

```sh
python3 target/linux/airoha/tests/native_pair/run.py \
  --kernel-tree /path/to/prepared/linux-6.18.60 \
  --output /path/to/new/native-host-results
```

Python 3 and Clang with AddressSanitizer/UndefinedBehaviorSanitizer are required.
The runner extracts the current kernel functions into a separate results
directory and hashes their source. It runs 700 checks: pair admission/binding
55, policy serialization 11, bank/revoke lifecycle 223, mailbox wrapper 68,
XDP/TCX 16, shutdown ordering 3, FDB movement 6, bridge hook classification 298,
and nft JSON audit 20. Transport and MMIO are mocked in these host tests.

The source integration was also compiled as eleven ARM64 kernel objects with
zero compiler warnings, including the preserved 948 debugfs implementation.
The RAM bundle uses the same native algorithms with 948 absent from its older
base. Hardware acceptance captures cold policy state, empty enable/off,
authorized pair learning, bank0 L2B BND rows in both directions, fresh IPv4 and
IPv6 traffic, stable host conntrack counters while throughput continues, and
revoke behavior. Save PHY/radio statistics alongside throughput for comparison.

On 2026-11-25 the matched RAM image passed cold boot, audited enable/off,
bidirectional IPv4/IPv6 TCP with default ECN, and 16-byte UDP with DS=3/187.
Both directions bound native bank0 rows; software connection counters stayed
fixed while traffic continued. The four short UDP runs had zero loss and
preserved TTL/hop limit 64 plus the exact DS byte at the Mac receiver. Explicit
off and nft mutation during live TCP cleared native rows synchronously, then
reauthorization successfully relearned them. Mac WLAN disconnect removed its
peer rows; reassociation and fresh default ECN traffic relearned both directions
with host counters fixed. Router mean CPU during these native TCP runs was
2.48% to 3.88%.
