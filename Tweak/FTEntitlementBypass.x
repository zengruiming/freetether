// Tweak/FTEntitlementBypass.x
// Bypass carrier signature verification and online entitlement checks

#import <Foundation/Foundation.h>
#import <dlfcn.h>
#import <substrate.h>

extern BOOL FTIsEnabled();
extern BOOL gBypassEntitlement;
extern BOOL gDebugLog;

#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG][Entitlement] " fmt, ##__VA_ARGS__); } while(0)

// --- CoreTelephony function pointer types ---
typedef void *CTServerConnectionRef;

// Helper: try multiple symbol names via dlsym, return the first one that resolves
static void *tryResolveSymbol(void *handle, const char *names[], int count, const char **matchedName) {
    for (int i = 0; i < count; i++) {
        void *sym = dlsym(handle, names[i]);
        if (sym) {
            if (matchedName) *matchedName = names[i];
            return sym;
        }
    }
    if (matchedName) *matchedName = NULL;
    return NULL;
}

// Function pointers for originals — tethering mode
static int (*orig_CTServerConnectionSetTetheredMode)(CTServerConnectionRef, BOOL);
static int (*orig_CTServerConnectionGetTetheredMode)(CTServerConnectionRef, BOOL *);

// Function pointers for originals — tethering APN
static int (*orig_CTServerConnectionSetPersistentTetheringAPN)(CTServerConnectionRef, CFStringRef);
static int (*orig_CTServerConnectionGetPersistentTetheringAPN)(CTServerConnectionRef, CFStringRef *);

// --- Replacement functions — tethering mode ---

// #2 fix: always force enabled=YES when bypass is active, preventing system from disabling tethering
static int new_CTServerConnectionSetTetheredMode(CTServerConnectionRef conn, BOOL enabled) {
    if (FTIsEnabled() && gBypassEntitlement) {
        FT_DBG(@"SetTetheredMode: forcing enabled=YES (was %d)", enabled);
        return orig_CTServerConnectionSetTetheredMode(conn, YES);
    }
    return orig_CTServerConnectionSetTetheredMode(conn, enabled);
}

static int new_CTServerConnectionGetTetheredMode(CTServerConnectionRef conn, BOOL *outEnabled) {
    int result = orig_CTServerConnectionGetTetheredMode(conn, outEnabled);
    if (FTIsEnabled() && gBypassEntitlement && outEnabled) {
        FT_DBG(@"GetTetheredMode: forcing YES (was %d)", *outEnabled);
        *outEnabled = YES;
    }
    return result;
}

// --- Replacement functions — tethering APN ---
// These hooks are debug-only (they log but don't modify behavior).
// Installed unconditionally because %ctor runs before prefs are loaded (Tweak.x
// ctor runs last due to alphabetical file ordering), so gDebugLog would always
// be NO at hook time. Instead we check gDebugLog at call time.

static int new_CTServerConnectionSetPersistentTetheringAPN(CTServerConnectionRef conn, CFStringRef apn) {
    if (gDebugLog) {
        FT_DBG(@"SetPersistentTetheringAPN: apn=%@", (__bridge NSString *)apn);
    }
    return orig_CTServerConnectionSetPersistentTetheringAPN(conn, apn);
}

static int new_CTServerConnectionGetPersistentTetheringAPN(CTServerConnectionRef conn, CFStringRef *outAPN) {
    int result = orig_CTServerConnectionGetPersistentTetheringAPN(conn, outAPN);
    if (gDebugLog) {
        FT_DBG(@"GetPersistentTetheringAPN: apn=%@",
                outAPN && *outAPN ? (__bridge NSString *)*outAPN : @"(null)");
    }
    return result;
}

// --- Hook C-level entitlement check functions ---

// CTCarrierSpaceCopyBooleanValue has a well-known signature from reverse engineering
static Boolean (*orig_CTCarrierSpaceCopyBooleanValue)(void *space, CFStringRef key);

// C1 fix: only override tethering-related keys, not all carrier booleans.
// Overriding all keys risks enabling international roaming or other unintended features.
static Boolean new_CTCarrierSpaceCopyBooleanValue(void *space, CFStringRef key) {
    if (FTIsEnabled() && gBypassEntitlement && key) {
        NSString *keyStr = [(__bridge NSString *)key lowercaseString];
        // W4 fix: match specific tethering-related substrings instead of broad "sharing"
        // Note: "tether" already matches "tethering"/"tetheringentitlement" etc.
        // Bare "entitlement" was too broad and could match VoLTEEntitlement,
        // RoamingEntitlement etc. — removed to avoid side effects.
        if ([keyStr containsString:@"tether"] ||
            [keyStr containsString:@"hotspot"] ||
            [keyStr containsString:@"internetsharing"]) {
            FT_DBG(@"CTCarrierSpaceCopyBooleanValue: forcing YES for key=%@",
                    (__bridge NSString *)key);
            return true;
        }
    }
    return orig_CTCarrierSpaceCopyBooleanValue(space, key);
}

// C2 fix: removed fallback entitlement hook with guessed signatures.
// CTServerConnectionCopyCarrierEntitlements/CopyEntitlements likely return CFDictionaryRef (Copy
// semantics), and CTServerConnectionSetEntitlementCheck is likely a callback setter — neither
// matches the (CTServerConnectionRef, CFStringRef, BOOL*) signature assumed here. Hooking with
// a wrong signature causes stack corruption → CommCenter crash → cellular network loss.
// The primary CTCarrierSpaceCopyBooleanValue hook above is the reliable path.

%ctor {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    if (![proc isEqualToString:@"CommCenter"]) return;

    NSLog(@"[FreeTether][Entitlement] Setting up entitlement bypass hooks in CommCenter");

    // Load CoreTelephony and hook C functions
    void *ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
    if (!ct) {
        NSLog(@"[FreeTether][ERROR][Entitlement] Failed to load CoreTelephony");
        return;
    }

    int hookCount = 0;
    const char *matched = NULL;

    // Hook tethering mode SET — try known symbol name variants
    const char *setTetherNames[] = {
        "CTServerConnectionSetTetheredModeIsEnabled",
        "CTServerConnectionSetTetheredModeEnabled",
    };
    void *setTether = tryResolveSymbol(ct, setTetherNames, 2, &matched);
    if (setTether) {
        MSHookFunction(setTether,
                       (void *)new_CTServerConnectionSetTetheredMode,
                       (void **)&orig_CTServerConnectionSetTetheredMode);
        hookCount++;
        FT_DBG(@"Hooked %s @ %p", matched, setTether);
    } else {
        NSLog(@"[FreeTether][WARN][Entitlement] SetTetheredMode: no matching symbol found");
    }

    // Hook tethering mode GET — try known symbol name variants
    const char *getTetherNames[] = {
        "CTServerConnectionGetTetheredModeIsEnabled",
        "CTServerConnectionGetTetheredModeEnabled",
    };
    void *getTether = tryResolveSymbol(ct, getTetherNames, 2, &matched);
    if (getTether) {
        MSHookFunction(getTether,
                       (void *)new_CTServerConnectionGetTetheredMode,
                       (void **)&orig_CTServerConnectionGetTetheredMode);
        hookCount++;
        FT_DBG(@"Hooked %s @ %p", matched, getTether);
    } else {
        NSLog(@"[FreeTether][WARN][Entitlement] GetTetheredMode: no matching symbol found");
    }

    // Tethering APN hooks — installed unconditionally (debug check is at call time,
    // not install time, because gDebugLog is not yet loaded when this ctor runs).
    void *setAPN = dlsym(ct, "CTServerConnectionSetPersistentTetheringAPN");
    if (setAPN) {
        MSHookFunction(setAPN,
                       (void *)new_CTServerConnectionSetPersistentTetheringAPN,
                       (void **)&orig_CTServerConnectionSetPersistentTetheringAPN);
        hookCount++;
        FT_DBG(@"Hooked CTServerConnectionSetPersistentTetheringAPN @ %p", setAPN);
    }

    void *getAPN = dlsym(ct, "CTServerConnectionGetPersistentTetheringAPN");
    if (getAPN) {
        MSHookFunction(getAPN,
                       (void *)new_CTServerConnectionGetPersistentTetheringAPN,
                       (void **)&orig_CTServerConnectionGetPersistentTetheringAPN);
        hookCount++;
        FT_DBG(@"Hooked CTServerConnectionGetPersistentTetheringAPN @ %p", getAPN);
    }

    // Hook entitlement check — prefer CTCarrierSpaceCopyBooleanValue (well-known signature),
    // fall back to CTServerConnection-style entitlement symbols
    void *carrierBool = dlsym(ct, "CTCarrierSpaceCopyBooleanValue");
    if (carrierBool) {
        MSHookFunction(carrierBool,
                       (void *)new_CTCarrierSpaceCopyBooleanValue,
                       (void **)&orig_CTCarrierSpaceCopyBooleanValue);
        hookCount++;
        FT_DBG(@"Hooked CTCarrierSpaceCopyBooleanValue @ %p", carrierBool);
    } else {
        // C2 fix: do NOT fall back to CTServerConnection entitlement symbols — their signatures
        // are unverified and hooking with wrong signatures causes CommCenter crashes.
        NSLog(@"[FreeTether][WARN][Entitlement] CTCarrierSpaceCopyBooleanValue not found — "
              "entitlement bypass will rely on tethering mode and carrier override hooks only");
    }

    if (hookCount == 0) {
        NSLog(@"[FreeTether][ERROR][Entitlement] 0 entitlement bypass hooks installed — bypassing will NOT work");
    } else {
        NSLog(@"[FreeTether][Entitlement] %d entitlement bypass hooks installed", hookCount);
    }
}
