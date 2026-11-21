include $(TOPDIR)/rules.mk

PKG_NAME:=hg5585f-ct-npu-firmware
PKG_VERSION:=6.6.23
PKG_RELEASE:=1
PKGARCH:=all
PKG_LICENSE:=Proprietary

include $(INCLUDE_DIR)/package.mk

define Package/hg5585f-ct-npu-firmware
  SECTION:=firmware
  CATEGORY:=Firmware
  TITLE:=FiberHome HG5585F CT Connac2 NPU firmware
  DEPENDS:=@TARGET_airoha_an7581
endef

define Build/Compile
endef

define Package/hg5585f-ct-npu-firmware/install
	cd $(CURDIR)/files && sha256sum -c ../SHA256SUMS
	$(INSTALL_DIR) $(1)/lib/firmware/airoha/hg5585f-ct
	$(INSTALL_DATA) $(CURDIR)/files/npu_rv32.bin $(CURDIR)/files/npu_data.bin $(1)/lib/firmware/airoha/hg5585f-ct/
endef

$(eval $(call BuildPackage,hg5585f-ct-npu-firmware))
