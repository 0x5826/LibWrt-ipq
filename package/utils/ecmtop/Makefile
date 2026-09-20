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
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)/
endef

ifeq ($(ARCH),aarch64)
  GO_ARCH:=arm64
else ifeq ($(ARCH),x86_64)
  GO_ARCH:=amd64
else
  GO_ARCH:=$(ARCH)
endif

define Build/Compile
	( cd $(PKG_BUILD_DIR) && \
		GOOS=linux \
		GOARCH=$(GO_ARCH) \
		CGO_ENABLED=0 \
		go build -trimpath -ldflags "-s -w" -o $(PKG_BUILD_DIR)/ecmtop . \
	)
endef

define Package/ecmtop/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/ecmtop $(1)/usr/bin/ecmtop
endef

$(eval $(call BuildPackage,ecmtop))
