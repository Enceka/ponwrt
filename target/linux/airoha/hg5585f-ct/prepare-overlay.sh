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
  package/kernel/mt76/ct-wed/{ct_wdma_rx.h,ct_wed_bm.h,ct_wed_stop.h,ct_wed_cold.h,ct_wed_platform.c,ct_wed_guard_v2.c,patches/126-mt7915-prepare-ct-wed-slot1.patch} \
  target/linux/airoha/patches-6.18/931-net-airoha-initialize-ct-connac2-packet-pool.patch \
  target/linux/airoha/patches-6.18/932-net-airoha-initialize-ct-connac2-host-ppe.patch \
  target/linux/airoha/patches-6.18/933-net-airoha-quiesce-ct-ppe-on-shutdown.patch \
  target/linux/airoha/patches-6.18/934-net-airoha-drain-ct-sram-before-disabling-ppe.patch \
  target/linux/airoha/hg5585f-ct/ram-dts.py \
  target/linux/airoha/{image/an7581.mk,dts/an7581-fiberhome-hg5585f-ct-connac2.dts}; do
  mkdir -p "$overlay/tree/$(dirname "$path")"
  install -m 644 "$path" "$overlay/tree/$path"
done
mkdir -p "$overlay/tree/$package/files"
for name in "${firmware[@]}"; do
  install -m 644 "$source_dir/$name" "$overlay/tree/$package/files/$name"
done
(cd "$overlay/tree/$package/files" && sha256sum -c ../SHA256SUMS)
printf '%s\n' CONFIG_MT7915_NPU=y CONFIG_PACKAGE_hg5585f-ct-npu-firmware=y > "$overlay/local.config"
