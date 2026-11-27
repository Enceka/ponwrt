#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 && $# != 3 && !( $# == 4 && $3 == --full-test ) ]]; then
  echo "usage: bash $0 STOCK_USERFS NEW_OVERLAY_DIRECTORY [REBUILT_PAYLOAD_DIRECTORY | --full-test PAYLOAD_DIRECTORY]" >&2
  exit 2
fi
source_dir=$(cd "$1" && pwd)
repo=$(cd "$(dirname "$0")/../../../.." && pwd)
rebuilt_dir=
full_dir=
if [[ $# == 3 ]]; then
  rebuilt_dir=$(cd "$3" && pwd)
elif [[ $# == 4 ]]; then
  full_dir=$(cd "$4" && pwd)
fi
package=package/firmware/hg5585f-ct-npu-firmware
firmware=(npu_rv32.bin npu_data.bin)
(cd "$source_dir" && sha256sum -c "$repo/$package/SHA256SUMS")
mkdir -- "$2"
overlay=$(cd "$2" && pwd)
cd "$repo"
for path in "$package/Makefile" "$package/SHA256SUMS" "$package/SHA256SUMS.rebuilt" "$package/SHA256SUMS.full-test" \
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
  package/kernel/mt76/ct-wed/patches/142-mt7915-refresh-ct-native-rx-activity.patch \
  package/kernel/mac80211/{Makefile,patches/subsys/601-mac80211-bridge-ct-ap-unicast-and-isolation-policy.patch} \
  package/kernel/mac80211/patches/subsys/602-mac80211-track-driver-reported-rx-activity.patch \
  target/linux/airoha/patches-6.18/609-05-clk-en7523-fix-reset-values-and-regmap-errors.patch \
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
  target/linux/airoha/patches-6.18/948-net-airoha-report-ct-flow-admission.patch \
  target/linux/airoha/patches-6.18/949-net-airoha-publish-npu-mailbox-status-before-trigger.patch \
  target/linux/airoha/patches-6.18/950-net-airoha-size-coherent-mailboxes-for-wlan-statistics.patch \
  target/linux/airoha/patches-6.18/951-net-airoha-load-verified-rebuilt-ct-ram-firmware.patch \
  target/linux/airoha/patches-6.18/952-net-airoha-add-native-wireless-pair-offload.patch \
  target/linux/airoha/patches-6.18/953-net-airoha-add-native-wlan-lan1-destination.patch \
  target/linux/airoha/patches-6.18/954-net-airoha-add-native-lan1-source-offload.patch \
  target/linux/airoha/patches-6.18/955-net-airoha-preserve-cpu-forwarding-after-native-faults.patch \
  target/linux/airoha/patches-6.18/956-net-airoha-gate-wlan-before-native-ppe-stop.patch \
  target/linux/airoha/patches-6.18/957-net-airoha-allow-station-reconnect-after-native-fault.patch \
  target/linux/airoha/patches-6.18/958-net-airoha-retain-pon-mappings-on-flow-retirement-errors.patch \
  target/linux/airoha/patches-6.18/959-net-airoha-serialize-pon-bearer-updates.patch \
  target/linux/airoha/patches-6.18/960-net-airoha-isolate-native-ingress-with-ifc-cpu-guards.patch \
  target/linux/airoha/patches-6.18/96[1-9]-*.patch \
  target/linux/airoha/patches-6.18/970-net-airoha-keep-optical-ingress-on-wan-cpu-in-full-test.patch \
  target/linux/airoha/patches-6.18/971-net-airoha-check-optical-rx-service-before-ppe-learning.patch \
  target/linux/airoha/patches-6.18/972-net-airoha-stage-checked-gre4-rows-before-foe-publication.patch \
  target/linux/airoha/patches-6.18/973-net-airoha-require-wan-rx-queue-for-optical-learning.patch \
  target/linux/airoha/patches-6.18/974-net-airoha-update-owned-ifc-scope-in-place.patch \
  target/linux/airoha/patches-6.18/975-net-airoha-encode-optical-service-cpu-classifier-rows.patch \
  target/linux/airoha/patches-6.18/976-net-airoha-own-optical-cpu-classifier-row-transactions.patch \
  target/linux/airoha/patches-6.18/977-net-airoha-own-ram-optical-cpu-classifier-probes.patch \
  target/linux/airoha/patches-6.18/978-net-airoha-serialize-shared-ifc-command-recovery.patch \
  target/linux/airoha/patches-6.18/979-net-airoha-map-en7581-optical-gdm2-source-port.patch \
  target/linux/airoha/patches-6.18/980-net-airoha-encode-shared-exact-tuple-lut-predicates.patch \
  target/linux/airoha/patches-6.18/981-net-airoha-allow-optical-probe-off-during-cpu-stop.patch \
  target/linux/airoha/patches-6.18/982-net-airoha-own-covered-optical-cpu-route-probes.patch \
  target/linux/airoha/patches-6.18/983-net-airoha-probe-optical-source-predicates.patch \
  target/linux/airoha/patches-6.18/984-net-airoha-mask-all-ports-for-exclusive-ifc-source-selection.patch \
  target/linux/airoha/patches-6.18/985-net-airoha-share-transactional-ifc-tuple-lut-pool.patch \
  target/linux/airoha/patches-6.18/986-net-airoha-clear-shared-command-state-after-optical-drain.patch \
  target/linux/airoha/patches-6.18/987-net-airoha-probe-exact-optical-tuples-with-shared-lut-leases.patch \
  target/linux/airoha/patches-6.18/988-net-airoha-add-source-aware-npu-transaction-transport.patch \
  target/linux/airoha/patches-6.18/989-net-airoha-add-source-aware-ethernet-return-consumers.patch \
  target/linux/airoha/patches-6.18/990-net-airoha-preserve-npu-lifecycle-transaction-identities.patch \
  target/linux/airoha/patches-6.18/991-net-airoha-own-gdm-default-routes-for-bank1-isolation.patch \
  target/linux/airoha/patches-6.18/992-net-airoha-arbitrate-native-fe-lifecycle-ownership.patch \
  target/linux/airoha/patches-6.18/993-net-airoha-connect-npu-owner-to-pon-update-close.patch \
  target/linux/airoha/patches-6.18/994-net-airoha-own-pon-return-consumer-lifetimes.patch \
  target/linux/airoha/patches-6.18/995-net-airoha-validate-pon-authorization-publication.patch \
  target/linux/airoha/patches-6.18/996-net-airoha-bind-pon-authorization-to-owner.patch \
  target/linux/airoha/patches-6.18/997-net-airoha-arm-fe-through-npu-owner.patch \
  target/linux/airoha/patches-6.18/998-net-airoha-reopen-owned-pon-default-route.patch \
  target/linux/airoha/patches-6.18/999-net-airoha-reopen-pon-hardware-through-owner.patch \
  target/linux/airoha/patches-6.18/999-z-net-airoha-monitor-npu-owner-invalidation.patch \
  target/linux/airoha/patches-6.18/999-za-net-airoha-isolate-ct-flow-learning.patch \
  target/linux/airoha/patches-6.18/999-zb-net-airoha-publish-epon-registration-identity.patch \
  target/linux/airoha/patches-6.18/999-zc-net-airoha-retire-host-bank1-before-npu-reuse.patch \
  target/linux/airoha/patches-6.18/999-zd-net-airoha-prepare-authorized-pon-npu-ingress.patch \
  target/linux/airoha/patches-6.18/999-ze-net-airoha-connect-pon-npu-ingress-lifecycle.patch \
  target/linux/airoha/patches-6.18/999-zf-net-airoha-support-zero-service-cpu-probes.patch \
  target/linux/airoha/patches-6.18/999-zg-net-airoha-track-er-provider-exposure.patch \
  target/linux/airoha/patches-6.18/999-zh-net-airoha-quarantine-ambiguous-mailbox.patch \
  target/linux/airoha/patches-6.18/999-zi-net-airoha-start-rebuilt-npu-after-binding.patch \
  target/linux/airoha/hg5585f-ct/{ram-dts.py,ram.config,NATIVE_PAIRS.md} \
  target/linux/airoha/tests/native_pair/*.{py,c} \
  target/linux/airoha/tests/native_pair/fixtures/*.inc \
  target/linux/airoha/tests/station_activity/*.py \
  target/linux/airoha/tests/pon_offload/*.{py,c,h,inc,md} \
  target/linux/airoha/tests/pon_offload/service0/*.{py,c,md} \
  target/linux/airoha/tests/pon_offload/ram_loopback/{*.c,*.md,Makefile} \
  target/linux/airoha/tests/epon_identity/*.{py,c,md} \
  target/linux/airoha/tests/npu_transaction_transport/*.{py,c,md} \
  target/linux/airoha/tests/npu_transaction_core/*.{py,c,md} \
  target/linux/airoha/tests/npu_er_provider/*.{py,c,md} \
  target/linux/airoha/tests/npu_mailbox/*.{py,c,md} \
  target/linux/airoha/tests/npu_start/*.{py,c,md} \
  target/linux/airoha/tests/npu_resident_config/*.{py,md} \
  target/linux/airoha/tests/npu_resident_config/fixtures/*.{config,dts} \
  target/linux/airoha/tests/bank1_routes/*.{py,c,inc,md} \
  target/linux/airoha/tests/npu_fe_owner/*.{py,c,inc,md} \
  target/linux/airoha/tests/npu_fe_owner_arm/*.{py,c,inc,md} \
  target/linux/airoha/tests/reset_provider/*.{py,c,md} \
  target/linux/airoha/tests/npu_owner/*.{py,c,h,inc,md} \
  target/linux/airoha/tests/npu_bank1/*.{py,c,h,inc,md} \
  target/linux/airoha/tests/npu_ingress/{*.py,*.c,*.md,Makefile} \
  target/linux/airoha/tests/npu_ingress_owner/*.{py,c,md} \
  target/linux/airoha/tests/npu_owner_events/*.{py,c,md} \
  target/linux/airoha/tests/npu_auth_publish/*.{py,c,md} \
  target/linux/airoha/tests/eth_return/*.{py,c,h,md} \
  target/linux/airoha/tests/tunnel/*.{py,c,sh,md} \
  target/linux/airoha/{image/an7581.mk,dts/an7581-fiberhome-hg5585f-ct-connac2.dts,dts/an7581-fiberhome-hg5585f-ct-connac2-wed.dts,dts/an7581-fiberhome-hg5585f-ct-connac2-wed-full-test.dts}; do
  mkdir -p "$overlay/tree/$(dirname "$path")"
  install -m 644 "$path" "$overlay/tree/$path"
done
mkdir -p "$overlay/tree/$package/files"
for name in "${firmware[@]}"; do
  install -m 644 "$source_dir/$name" "$overlay/tree/$package/files/$name"
done
(cd "$overlay/tree/$package/files" && sha256sum -c ../SHA256SUMS)
if [[ -n "$rebuilt_dir" ]]; then
  for kind in rv32 data; do
    install -m 644 "$rebuilt_dir/ram-npu_$kind.bin" "$overlay/tree/$package/files/npu_rebuilt_$kind.bin"
  done
  (cd "$overlay/tree/$package/files" && sha256sum -c ../SHA256SUMS.rebuilt)
fi
printf '%s\n' CONFIG_MT7915_NPU=y CONFIG_PACKAGE_hg5585f-ct-npu-firmware=y \
  CONFIG_PACKAGE_kmod-mt7916-ct-wed-prepare=y > "$overlay/local.config"
if [[ -n "$rebuilt_dir" ]]; then
  printf '%s\n' CONFIG_PACKAGE_hg5585f-ct-npu-rebuilt-firmware=y \
    CONFIG_PACKAGE_kmod-nft-core=y CONFIG_PACKAGE_kmod-nft-bridge=y >> "$overlay/local.config"
fi
if [[ -n "$full_dir" ]]; then
  board_network=target/linux/airoha/an7581/base-files/etc/board.d/02_network
  mkdir -p "$overlay/tree/$(dirname "$board_network")" "$overlay/tree/files/etc/config"
  install -m 755 "$board_network" "$overlay/tree/$board_network"
  # config_generate skips nonempty network files, including the old LAN1-WAN seed.
  : > "$overlay/tree/files/etc/config/network"
  for kind in rv32 data; do
    install -m 644 "$full_dir/ram-npu_$kind.bin" "$overlay/tree/$package/files/npu_full_test_$kind.bin"
  done
  (cd "$overlay/tree/$package/files" && sha256sum -c ../SHA256SUMS.full-test)
  printf '%s\n' CONFIG_PACKAGE_hg5585f-ct-npu-full-test-firmware=y \
    CONFIG_PACKAGE_kmod-nft-core=y CONFIG_PACKAGE_kmod-nft-bridge=y >> "$overlay/local.config"
fi
python3 - "$overlay" <<'PY_MANIFEST'
from pathlib import Path
import hashlib
import sys
root = Path(sys.argv[1])
files = sorted(path for path in root.rglob('*') if path.is_file())
(root / 'SHA256SUMS').write_text(''.join(
    f'{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(root)}\n'
    for path in files))
PY_MANIFEST
