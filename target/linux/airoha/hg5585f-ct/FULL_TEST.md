# HG5585F CT ordinary ABI3 full-image test

Select `fiberhome_hg5585f-ct`, `CONFIG_MT7915_NPU=y` and
`CONFIG_PACKAGE_hg5585f-ct-npu-full-test-firmware=y`. Build without
`HG5585F_CT_RAM_TRIAL=1`. Supply the two files from firmware commit
`c865c358b9bd7c677abddf9e60885d11675464dd` under the installation names
in `package/firmware/hg5585f-ct-npu-firmware/SHA256SUMS.full-test`. The
package and kernel loader verify their hashes. The loader uses separate
filenames from both the stock firmware and the original RAM ABI3 image.

The chosen DTS inherits NAND, UBI `fit`, factory NVMEM, optical MAC, PCS,
BOSA, GDM2 and WED slot 1 from the persistent CT board. Recovery and
squashfs builds use this same DTS. The firmware implements ABI 3 with
capabilities `0x3f`; the ordinary native IFC selector uses GDM4 port 24
(`0x01000000`). Native forwarding policy starts off. Use the stock WED
profile without the full-test package for a comparison.

On a fresh overlay, LAN1 (2.5 GbE), LAN2 and LAN3 belong to the management
bridge; LAN4 provides DHCP WAN and DHCPv6 WAN. The optical `pon0` is available
for a separate line test. `prepare-overlay.sh --full-test` replaces the old
SDK's LAN1-WAN network seed with an empty file so first boot generates these
defaults. An upgrade that retains `/etc/config/network` retains its port roles.

Use this image to test the optical controller and software bearer path.
The rebuilt payload has no optical FE service. The driver routes GDM2 PPE
destinations to the WAN QDMA1 CPU receiver (CDM2), including during bank
changes, and checks the route before starting the PON line. DROP and direct
destinations retain their existing meanings. PON hardware flow admission
stays closed. On an attached line, check controller probe, O5, carrier,
bearer counters and software traffic separately from LAN/WLAN offload.
