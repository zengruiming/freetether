THEOS_PACKAGE_SCHEME ?= rootless
ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FreeTether
FreeTether_FILES = $(wildcard Tweak/*.x)
FreeTether_FRAMEWORKS = CoreTelephony SystemConfiguration CoreFoundation Foundation
FreeTether_CFLAGS = -fobjc-arc -Wno-availability
FreeTether_LIBRARIES = root

TOOL_NAME = freetether-cli
freetether-cli_FILES = Tools/freetether-cli.m
freetether-cli_INSTALL_PATH = /usr/bin
freetether-cli_CFLAGS = -fobjc-arc
freetether-cli_FRAMEWORKS = CoreFoundation Foundation
freetether-cli_LIBRARIES = root

BUNDLE_NAME = FreeTetherPrefs
FreeTetherPrefs_FILES = $(wildcard Preferences/*.m)
FreeTetherPrefs_FRAMEWORKS = UIKit Foundation
FreeTetherPrefs_PRIVATE_FRAMEWORKS = Preferences
FreeTetherPrefs_INSTALL_PATH = /Library/PreferenceBundles
FreeTetherPrefs_CFLAGS = -fobjc-arc
FreeTetherPrefs_RESOURCE_DIRS = Preferences/Resources

BUNDLE_NAME += FreeTetherCC
FreeTetherCC_FILES = $(wildcard CCModule/*.m)
FreeTetherCC_FRAMEWORKS = UIKit
FreeTetherCC_PRIVATE_FRAMEWORKS = ControlCenterUIKit
FreeTetherCC_INSTALL_PATH = /Library/ControlCenter/Bundles
FreeTetherCC_CFLAGS = -fobjc-arc
FreeTetherCC_RESOURCE_DIRS = CCModule/Resources

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk
include $(THEOS_MAKE_PATH)/tool.mk

SUBPROJECTS += Probe
include $(THEOS_MAKE_PATH)/aggregate.mk

after-install::
	install.exec "killall -9 CommCenter MobileInternetSharing 2>/dev/null || true"
