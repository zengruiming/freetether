THEOS_PACKAGE_SCHEME ?= rootless
ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:15.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FTProbe
FTProbe_FILES = FTProbe.x
FTProbe_CFLAGS = -fobjc-arc
FTProbe_FRAMEWORKS = Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
