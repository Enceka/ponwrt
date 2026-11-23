#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 ]]; then
  echo "usage: bash $0 STOCK_USERFS NEW_OVERLAY_DIRECTORY" >&2
  exit 2
fi
source_dir=$(cd "$1" && pwd)
repo=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
package=package/firmware/hg5585f-ct-npu-firmware
firmware=(npu_rv32.bin npu_data.bin)
(cd "$source_dir" && sha256sum -c "$repo/$package/SHA256SUMS")
mkdir -- "$2"
overlay=$(cd "$2" && pwd)
cd "$repo"
for path in "$package/Makefile" "$package/SHA256SUMS" \
  package/kernel/mt76/{Makefile,patches/111-mt7915-connac2-mailbox.patch,patches/112-mt7915-connac2-counters.patch,patches/113-mt7915-connac2-rx-rings.patch} \
  package/kernel/mt76/patches/{114-mt7915-connac2-host-rx.patch,115-mt7915-connac2-host-dequeue.patch,116-mt7915-connac2-packet-count.patch} \
  package/kernel/mt76/patches/{117-mt7915-connac2-pcie-windows.patch,118-mt7915-connac2-completion-counts.patch} \
  package/kernel/mt76/patches/119-mt7915-keep-shared-hdr-trans.patch \
  package/kernel/mt76/patches/{120-mt7915-connac2-rx-path.patch,121-mt7915-connac2-ba-lifecycle.patch} \
  package/kernel/mt76/patches/122-mt7915-connac2-dma-declaration.patch \
  package/kernel/mt76/patches/123-mt7915-connac2-check-rx-body.patch \
  package/kernel/mt76/patches/124-mt7915-connac2-host-ppe.patch \
  package/kernel/mt76/patches/125-mt7915-connac2-tdma-free-bufid.patch \
  package/kernel/mt76/patches/126-mt7915-connac2-ipv6-host-ppe.patch \
  package/kernel/mt76/ct-wed/{*.h,ct_wed_platform.c,ct_wed_guard_v2.c} \
  package/kernel/mt76/ct-wed/patches/{126-mt7915-prepare-ct-wed-slot1.patch,127-mt76-own-ct-radio-dma-rings.patch,128-mt7915-retain-exposed-ct-wed.patch,129-mt7915-start-ct-wed-slot1.patch,130-mt7915-configure-ct-radio-csr-aliases.patch} \
  package/kernel/mt76/ct-wed/patches/131-mt76-bound-ct-txfree-to-wed-didx.patch \
  package/kernel/mt76/ct-wed/patches/132-mt7915-rearm-ct-irq-before-mcu-init.patch \
  package/kernel/mt76/ct-wed/patches/133-mt7915-use-intx-for-active-ct-wed.patch \
  package/kernel/mt76/ct-wed/patches/134-mt7915-gate-exclusive-ct-primary-irq.patch \
  package/kernel/mt76/ct-wed/patches/135-mt7915-wait-for-ct-ppe-cold-ready.patch \
  package/kernel/mt76/ct-wed/patches/136-mt7915-expose-ct-wed-reclaim-counters.patch \
  package/kernel/mt76/ct-wed/patches/137-mt7915-expose-active-ct-wed-forward-path.patch \
  package/kernel/mt76/ct-wed/patches/138-mt7915-configure-wa-for-ct-wed.patch \
  package/kernel/mt76/ct-wed/patches/139-mt76-skip-host-reorder-for-connac2-queues.patch \
  package/kernel/mt76/ct-wed/patches/140-mt7915-flush-ct-wlan-flows-on-station-revoke.patch \
  package/kernel/mt76/ct-wed/patches/141-mt7915-learn-authorized-ct-wireless-bridge-flows.patch \
  package/kernel/mac80211/{Makefile,patches/subsys/601-mac80211-bridge-ct-ap-unicast-and-isolation-policy.patch} \
  target/linux/airoha/patches-6.18/931-net-airoha-initialize-ct-connac2-packet-pool.patch \
  target/linux/airoha/patches-6.18/932-net-airoha-initialize-ct-connac2-host-ppe.patch \
  target/linux/airoha/patches-6.18/933-net-airoha-quiesce-ct-ppe-on-shutdown.patch \
  target/linux/airoha/patches-6.18/934-net-airoha-drain-ct-sram-before-disabling-ppe.patch \
  target/linux/airoha/patches-6.18/935-net-airoha-report-ct-ppe-cold-ownership.patch \
  target/linux/airoha/patches-6.18/936-net-airoha-prepare-ct-ppe-before-radio-exposure.patch \
  target/linux/airoha/patches-6.18/937-net-airoha-limit-repeated-ct-ppe-cold-diagnostics.patch \
  target/linux/airoha/patches-6.18/938-net-airoha-seed-ct-ppe-at-reset-owned-probe.patch \
  target/linux/airoha/patches-6.18/939-net-airoha-preserve-ppe-enable-during-ct-seed.patch \
  target/linux/airoha/patches-6.18/940-net-airoha-check-ct-ppe-seed-sram-selectors.patch \
  target/linux/airoha/patches-6.18/941-net-airoha-merge-masked-ethernet-flow-mangles.patch \
  target/linux/airoha/patches-6.18/942-net-airoha-encode-ct-wed-wireless-egress.patch \
  target/linux/airoha/patches-6.18/943-net-airoha-bypass-short-ipv4-before-ct-wlan-offload.patch \
  target/linux/airoha/patches-6.18/944-net-airoha-invalidate-ct-wlan-station-flows.patch \
  target/linux/airoha/patches-6.18/945-net-airoha-offload-ct-wireless-ipv6.patch \
  target/linux/airoha/patches-6.18/946-net-airoha-offload-authorized-wireless-bridge-flows.patch \
  target/linux/airoha/patches-6.18/947-net-airoha-guard-ct-npu-wireless-short-frames.patch \
  target/linux/airoha/hg5585f-ct/{ram-dts.py,ram.config} \
  target/linux/airoha/{image/an7581.mk,dts/an7581-fiberhome-hg5585f-ct-connac2.dts}; do
  mkdir -p "$overlay/tree/$(dirname "$path")"
  install -m 644 "$path" "$overlay/tree/$path"
done
mkdir -p "$overlay/tree/$package/files"
for name in "${firmware[@]}"; do
  install -m 644 "$source_dir/$name" "$overlay/tree/$package/files/$name"
done
(cd "$overlay/tree/$package/files" && sha256sum -c ../SHA256SUMS)
printf '%s\n' CONFIG_MT7915_NPU=y CONFIG_PACKAGE_hg5585f-ct-npu-firmware=y \
  CONFIG_PACKAGE_kmod-mt7916-ct-wed-prepare=y > "$overlay/local.config"
