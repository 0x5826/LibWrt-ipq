include $(TOPDIR)/rules.mk

PKG_NAME:=ecmtop
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_BUILD_DIR:=$(BUILD_DIR)/$(PKG_NAME)-$(PKG_VERSION)

include $(INCLUDE_DIR)/package.mk

define Package/ecmtop
  SECTION:=utils
  CATEGORY:=Utilities
  SUBMENU:=Network Monitoring
  TITLE:=Real-time NSS ECM Hardware Accelerated Traffic Monitor
  DEPENDS:=@TARGET_qualcommax +kmod-qca-nss-ecm
  DEFAULT:=y if TARGET_qualcommax
endef

define Package/ecmtop/description
  ecmtop is an interactive TUI network traffic monitor for Qualcomm NSS ECM
  hardware-accelerated flows, providing real-time WAN throughput and per-client speed rankings.
  Written in pure C99 with zero dynamic memory allocation.
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(TARGET_CC) $(TARGET_CFLAGS) $(TARGET_CPPFLAGS) $(TARGET_LDFLAGS) \
		-std=c99 -Wall -Wextra -O2 \
		-o $(PKG_BUILD_DIR)/ecmtop $(PKG_BUILD_DIR)/main.c -lm
endef

define Package/ecmtop/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ecmtop $(1)/usr/bin/ecmtop
endef

$(eval $(call BuildPackage,ecmtop))
