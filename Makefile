ARCHS = arm64 arm64e
TARGET = iphone:clang:16.5:17.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = CarBridgeReborn
CarBridgeReborn_FILES   = src/Tweak.xm
CarBridgeReborn_CFLAGS  = -fobjc-arc -fexceptions -Wno-error -Wno-error=strict-prototypes
CarBridgeReborn_CFLAGS += -Wno-unused-variable -Wno-deprecated-declarations
CarBridgeReborn_FRAMEWORKS         = UIKit Foundation CoreGraphics
CarBridgeReborn_PRIVATE_FRAMEWORKS = FrontBoardServices SpringBoardServices

BUNDLE_NAME = CarBridgeRebornPrefs
CarBridgeRebornPrefs_FILES         = prefs/CBRPrefsController.xm
CarBridgeRebornPrefs_INSTALL_PATH  = /Library/PreferenceBundles
CarBridgeRebornPrefs_FRAMEWORKS    = UIKit Foundation CoreFoundation
CarBridgeRebornPrefs_CFLAGS        = -fobjc-arc -Wno-error -Wno-unused-variable
CarBridgeRebornPrefs_RESOURCE_DIRS = prefs/Resources

include $(THEOS_MAKE_PATH)/tweak.mk
include $(THEOS_MAKE_PATH)/bundle.mk

after-package::
	@ls -1t packages/*.deb 2>/dev/null | head -1 | xargs -I{} echo "OK Package: {}"
