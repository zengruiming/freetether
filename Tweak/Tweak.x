// Tweak/Tweak.x
// FreeTether main entry — preferences caching and process detection

#import <Foundation/Foundation.h>
#import <stdatomic.h>

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
#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG] " fmt, ##__VA_ARGS__); } while(0)

#define FT_NOTIFY_KEY    CFSTR("com.freetether.prefschanged")

// Read preferences directly from mobile user's plist file instead of
// CFPreferences domain. System daemons (CommCenter, MobileInternetSharing)
// run as root (UID 0), so CFPreferencesCopyAppValue reads from root's
// domain and never sees values written by Settings.app (mobile, UID 501).
#define FT_PREFS_PATH @"/var/mobile/Library/Preferences/com.freetether.plist"

// --- Global prefs cache ---
// Use C11 atomics: these are written on the main queue (FTReloadPrefs) but read
// from sysctl-hook threads and sRouteQueue in FTNetworkRouting.x.
_Atomic BOOL gEnabled        = YES;
_Atomic BOOL gDebugLog       = NO;

// FTNetworkRouting.x provides routing prefs loader
extern void FTLoadRoutingPrefs(NSDictionary *prefs);

// Read prefs from mobile user's plist file on disk. This works regardless
// of the calling process's UID, unlike CFPreferences which is per-user.
static NSDictionary *FTReadPrefsDict() {
    return [NSDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: @{};
}

void FTReloadPrefs() {
    NSDictionary *dict = FTReadPrefsDict();

    id val;
    val = dict[@"enabled"];
    gEnabled  = (val == nil) || [val boolValue];
    gDebugLog = [dict[@"debugLog"] boolValue];

    // Build a dictionary for FTLoadRoutingPrefs
    NSDictionary *prefs = @{
        @"vpnSharing":  dict[@"vpnSharing"]  ?: @NO,
        @"wifiSharing": dict[@"wifiSharing"] ?: @NO,
    };
    FTLoadRoutingPrefs(prefs);

    FT_LOG(@"Prefs reloaded: enabled=%d debug=%d", gEnabled, gDebugLog);
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

    // Register for prefs-changed notifications BEFORE initial load,
    // so we don't miss a notification that fires between load and register.
    CFNotificationCenterAddObserver(
        CFNotificationCenterGetDarwinNotifyCenter(), NULL,
        prefsChangedCallback,
        FT_NOTIFY_KEY, NULL,
        CFNotificationSuspensionBehaviorCoalesce);

    // Delay initial prefs load slightly — in CommCenter/MIS, FTNetworkRouting.x's
    // %ctor initializes sRouteQueue. Logos %ctor order across files is undefined,
    // so we dispatch async to ensure all %ctors have run before we load prefs
    // and trigger FTApplyRouteOverrideImpl.
    dispatch_async(dispatch_get_main_queue(), ^{
        FTReloadPrefs();
    });
}
