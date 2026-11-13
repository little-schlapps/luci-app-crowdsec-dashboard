# SPDX-License-Identifier: Apache-2.0
#
# LuCI dashboard for the CrowdSec security engine.

include $(TOPDIR)/rules.mk

LUCI_TITLE:=LuCI dashboard for CrowdSec
LUCI_DESCRIPTION:=Status dashboard for CrowdSec: engine and bouncer health, \
	blocklist sizes and firewall drops, alerts, decisions with unblock/ban, \
	and log-processing metrics.
LUCI_DEPENDS:=+luci-base +rpcd-mod-ucode +crowdsec
LUCI_PKGARCH:=all

# Explicit version for standalone releases; luci.mk would otherwise derive
# one from the git history of the LuCI feed.
PKG_VERSION:=1.0.0
PKG_RELEASE:=1

PKG_LICENSE:=Apache-2.0
PKG_MAINTAINER:=little-schlapps <little-schlapps@users.noreply.github.com>
# luci.mk writes these into the package metadata (it ignores PKG_MAINTAINER)
LUCI_MAINTAINER:=$(PKG_MAINTAINER)
LUCI_URL:=https://github.com/little-schlapps/luci-app-crowdsec-dashboard

include ../../luci.mk

# call BuildPackage - OpenWrt buildroot signature
