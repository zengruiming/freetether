// Tweak/Tweak.x
// FreeTether main entry — preferences caching, process detection, and tether bypass

#import <Foundation/Foundation.h>
#import <stdatomic.h>
#import <dlfcn.h>
#import <substrate.h>

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

// --- Tether bypass: carrier capability hooks (CommCenter only) ---
// iOS determines hotspot availability via carrier bundle settings queried through
// CoreTelephony private APIs in CommCenter. Without a SIM card (or with a carrier
// that disables tethering), the system hides or greys out the Personal Hotspot menu.
//
// These are private symbols with no public headers, so we resolve them at runtime
// via dlsym and hook with MSHookFunction directly (not %hookf/%group, which would
// try to reference the symbols at compile time and fail).

// --- Hook: CTCarrierSpaceGetSetting ---
typedef CFTypeRef (*CTCarrierSpaceGetSetting_t)(CFAllocatorRef, CFStringRef, CFStringRef);
static CTCarrierSpaceGetSetting_t orig_CTCarrierSpaceGetSetting = NULL;

static CFTypeRef hook_CTCarrierSpaceGetSetting(CFAllocatorRef alloc, CFStringRef carrierSpace, CFStringRef setting) {
    CFTypeRef result = orig_CTCarrierSpaceGetSetting(alloc, carrierSpace, setting);
    if (!FTIsEnabled() || !setting) return result;

    NSString *key = (__bridge NSString *)setting;
    // Match known tethering capability keys (case-insensitive partial match
    // to cover variants across iOS versions: "AllowsPersonalHotspot",
    // "personalHotspot", "TetheringAllowed", etc.)
    if ([key rangeOfString:@"ersonalHotspot" options:NSCaseInsensitiveSearch].location != NSNotFound ||
        [key rangeOfString:@"ethering" options:NSCaseInsensitiveSearch].location != NSNotFound) {
        FT_DBG(@"Intercepted carrier setting: %@ (was %@) → forcing YES", key, result);
        return (__bridge CFTypeRef)@YES;
    }
    return result;
}

// --- Hook: CTServerConnectionSetTetheredModeEnabled ---
typedef int (*CTServerConnectionSetTetheredModeEnabled_t)(void *, BOOL);
static CTServerConnectionSetTetheredModeEnabled_t orig_CTServerConnectionSetTetheredModeEnabled = NULL;

static int hook_CTServerConnectionSetTetheredModeEnabled(void *conn, BOOL enabled) {
    if (FTIsEnabled()) {
        FT_LOG(@"Tethering mode set to %d (entitlement check bypassed)", enabled);
        return 0;  // 0 = success
    }
    return orig_CTServerConnectionSetTetheredModeEnabled(conn, enabled);
}

// --- Hook: CTServerConnectionGetTetheredModeEnabled ---
typedef int (*CTServerConnectionGetTetheredModeEnabled_t)(void *, BOOL *);
static CTServerConnectionGetTetheredModeEnabled_t orig_CTServerConnectionGetTetheredModeEnabled = NULL;

static int hook_CTServerConnectionGetTetheredModeEnabled(void *conn, BOOL *outEnabled) {
    if (FTIsEnabled()) {
        if (outEnabled) *outEnabled = YES;
        FT_DBG(@"Tethering entitlement query → returning YES");
        return 0;
    }
    return orig_CTServerConnectionGetTetheredModeEnabled(conn, outEnabled);
}

// Resolve symbols via dlsym and install hooks with MSHookFunction.
// If a symbol doesn't exist on this iOS version, the hook is silently skipped.
static void FTInstallTetherBypassHooks() {
    void *ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY | RTLD_NOLOAD);
    if (!ct) {
        // Try loading it explicitly
        ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    }
    if (!ct) {
        FT_LOG(@"Failed to dlopen CoreTelephony — tether bypass hooks not installed");
        return;
    }

    int hooked = 0;

    void *sym1 = dlsym(ct, "CTCarrierSpaceGetSetting");
    if (sym1) {
        MSHookFunction(sym1, (void *)&hook_CTCarrierSpaceGetSetting, (void **)&orig_CTCarrierSpaceGetSetting);
        hooked++;
        FT_DBG(@"Hooked CTCarrierSpaceGetSetting @ %p", sym1);
    }

    void *sym2 = dlsym(ct, "CTServerConnectionSetTetheredModeEnabled");
    if (sym2) {
        MSHookFunction(sym2, (void *)&hook_CTServerConnectionSetTetheredModeEnabled, (void **)&orig_CTServerConnectionSetTetheredModeEnabled);
        hooked++;
        FT_DBG(@"Hooked CTServerConnectionSetTetheredModeEnabled @ %p", sym2);
    }

    void *sym3 = dlsym(ct, "CTServerConnectionGetTetheredModeEnabled");
    if (sym3) {
        MSHookFunction(sym3, (void *)&hook_CTServerConnectionGetTetheredModeEnabled, (void **)&orig_CTServerConnectionGetTetheredModeEnabled);
        hooked++;
        FT_DBG(@"Hooked CTServerConnectionGetTetheredModeEnabled @ %p", sym3);
    }

    FT_LOG(@"Tether bypass: %d/3 hooks installed", hooked);
    if (hooked == 0) {
        FT_LOG(@"WARNING: No tether bypass symbols found — run FTProbe to discover available symbols on this iOS version");
    }
}

%ctor {
    NSString *proc = currentProcessName();
    FT_LOG(@"Loaded in process: %@", proc);

    // Initialize tether bypass hooks in CommCenter — this is the process that
    // queries carrier capabilities and controls hotspot availability.
    if ([proc isEqualToString:@"CommCenter"]) {
        FTInstallTetherBypassHooks();
    }

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
