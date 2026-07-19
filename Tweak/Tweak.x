// Tweak/Tweak.x
// FreeTether main entry — preferences caching and process detection

#import <Foundation/Foundation.h>

// libroot.h provides ROOT_PATH() / JBROOT_PATH_CSTRING() macros for rootless path resolution.
// When building with Theos rootless, libroot is linked via FreeTether_LIBRARIES = root.
// For local development without Theos, we provide fallback macros.
#if __has_include(<libroot/libroot.h>)
#import <libroot/libroot.h>
#else
// Fallback for environments without libroot headers
#define JBROOT_PATH_NSSTRING(path) @ path
#endif

#define FT_LOG(fmt, ...) NSLog(@"[FreeTether] " fmt, ##__VA_ARGS__)
#define FT_ERR(fmt, ...) NSLog(@"[FreeTether][ERROR] " fmt, ##__VA_ARGS__)
#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG] " fmt, ##__VA_ARGS__); } while(0)

#define FT_PREFS_DOMAIN  CFSTR("com.freetether")
#define FT_NOTIFY_KEY    CFSTR("com.freetether.prefschanged")

// --- Global prefs cache ---
BOOL gEnabled        = YES;
BOOL gDebugLog       = NO;
BOOL gForceHotspot   = YES;
BOOL gBypassEntitlement = YES;
BOOL gMaskTraffic    = YES;
NSString *gCustomAPN = nil;

// FTNetworkRouting.x provides routing prefs loader
extern void FTLoadRoutingPrefs(NSDictionary *prefs);

// #3 fix: helper to read a single pref from CFPreferences domain (consistent with PSListController)
static id FTReadPref(CFStringRef key) {
    return (__bridge_transfer id)CFPreferencesCopyAppValue(key, FT_PREFS_DOMAIN);
}

void FTReloadPrefs() {
    // #3 fix: synchronize first to ensure pending CFPreferences writes are flushed
    CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);

    id val;
    val = FTReadPref(CFSTR("enabled"));
    gEnabled           = (val == nil) || [val boolValue];
    gDebugLog          = [FTReadPref(CFSTR("debugLog")) boolValue];
    val = FTReadPref(CFSTR("forceHotspot"));
    gForceHotspot      = (val == nil) || [val boolValue];
    val = FTReadPref(CFSTR("bypassEntitlement"));
    gBypassEntitlement = (val == nil) || [val boolValue];
    val = FTReadPref(CFSTR("maskTraffic"));
    gMaskTraffic       = (val == nil) || [val boolValue];

    NSString *apn = FTReadPref(CFSTR("customAPN"));
    gCustomAPN = (apn.length > 0) ? [apn copy] : nil;

    // Build a dictionary for FTLoadRoutingPrefs
    NSDictionary *prefs = @{
        @"vpnSharing":  FTReadPref(CFSTR("vpnSharing"))  ?: @NO,
        @"wifiSharing": FTReadPref(CFSTR("wifiSharing")) ?: @NO,
    };
    FTLoadRoutingPrefs(prefs);

    FT_LOG(@"Prefs reloaded: enabled=%d forceHotspot=%d bypass=%d mask=%d debug=%d apn=%@",
           gEnabled, gForceHotspot, gBypassEntitlement, gMaskTraffic, gDebugLog,
           gCustomAPN ?: @"(default)");
}

BOOL FTIsEnabled() {
    return gEnabled;
}

// --- Process detection ---
static NSString *currentProcessName() {
    return [[NSProcessInfo processInfo] processName];
}

// W8 fix: proper CFNotificationCallback wrapper to avoid UB from mismatched signatures
static void prefsChangedCallback(CFNotificationCenterRef center, void *observer,
    CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    FTReloadPrefs();
}

%ctor {
    FT_LOG(@"Loaded in process: %@", currentProcessName());
    FTReloadPrefs();

    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        prefsChangedCallback,
        FT_NOTIFY_KEY, NULL,
        CFNotificationSuspensionBehaviorCoalesce);
}
