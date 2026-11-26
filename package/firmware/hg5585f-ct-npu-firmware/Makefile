include $(TOPDIR)/rules.mk

PKG_NAME:=hg5585f-ct-npu-firmware
PKG_VERSION:=6.6.23
PKG_RELEASE:=4
PKGARCH:=all
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk

define Package/hg5585f-ct-npu-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=FiberHome HG5585F CT Connac2 NPU firmware
  DEPENDS:=@TARGET_airoha_an7581
endef

define Package/hg5585f-ct-npu-rebuilt-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=FiberHome HG5585F rebuilt native NPU firmware
  DEPENDS:=@TARGET_airoha_an7581 +hg5585f-ct-npu-firmware
endef

define Build/Compile
endef

define Package/hg5585f-ct-npu-full-test-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=HG5585F CT ordinary ABI3 full-image test firmware
  DEPENDS:=@TARGET_airoha_an7581_DEVICE_fiberhome_hg5585f-ct @MT7915_NPU +kmod-mt7916-ct-wed-prepare +hg5585f-ct-npu-firmware
endef

define Package/hg5585f-ct-npu-firmware/install
	cd $(CURDIR)/files && sha256sum -c ../SHA256SUMS
	$(INSTALL_DIR) $(1)/lib/firmware/airoha/hg5585f-ct
	$(INSTALL_DATA) $(CURDIR)/files/npu_rv32.bin $(CURDIR)/files/npu_data.bin $(1)/lib/firmware/airoha/hg5585f-ct/
endef

define Package/hg5585f-ct-npu-rebuilt-firmware/install
	cd $(CURDIR)/files && sha256sum -c ../SHA256SUMS.rebuilt
	$(INSTALL_DIR) $(1)/lib/firmware/airoha/hg5585f-ct
	$(INSTALL_DATA) $(CURDIR)/files/npu_rebuilt_rv32.bin $(CURDIR)/files/npu_rebuilt_data.bin $(1)/lib/firmware/airoha/hg5585f-ct/
endef

$(eval $(call BuildPackage,hg5585f-ct-npu-firmware))
$(eval $(call BuildPackage,hg5585f-ct-npu-rebuilt-firmware))

define Package/hg5585f-ct-npu-full-test-firmware/install
	cd $(CURDIR)/files && sha256sum -c ../SHA256SUMS.full-test
	$(INSTALL_DIR) $(1)/lib/firmware/airoha/hg5585f-ct
	$(INSTALL_DATA) $(CURDIR)/files/npu_full_test_rv32.bin $(CURDIR)/files/npu_full_test_data.bin $(1)/lib/firmware/airoha/hg5585f-ct/
endef

$(eval $(call BuildPackage,hg5585f-ct-npu-full-test-firmware))
