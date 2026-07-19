// Tweak/FTAPNManager.x
// Redirect tethering APN to use data APN, making hotspot traffic invisible to carrier

#import <Foundation/Foundation.h>

extern BOOL FTIsEnabled();
extern BOOL gMaskTraffic;
extern NSString *gCustomAPN;
extern BOOL gDebugLog;

#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG][APN] " fmt, ##__VA_ARGS__); } while(0)

// #6 fix: pre-built set of exact APN TypeMask keys to avoid overly broad containsString match
static NSSet *sAPNTypeMaskKeys;

// --- Shared interception logic for APN type mask and tethering APN ---

static BOOL FTInterceptAPNSet(id anObject, NSString *strKey, void (^applyOrig)(id obj, id key)) {
    // If setting a tethering-specific APN, replace with custom APN
    if ([strKey isEqualToString:@"TetheringAPN"] ||
        [strKey isEqualToString:@"tethering-apn"]) {
        NSString *apn = gCustomAPN;  // W2 fix: local capture to avoid TOCTOU race
        if (apn) {
            FT_DBG(@"Redirecting tethering APN to custom: %@", apn);
            applyOrig(apn, strKey);
            return YES;
        }
        FT_DBG(@"Tethering APN set detected, key=%@ — no custom APN configured, passing through", strKey);
    }

    // #6 fix: use exact key set instead of containsString
    //
    // APN TypeMask bit layout (carrier-dependent, common convention):
    //   bit 0 (0x01): Data APN (internet/default)
    //   bit 1 (0x02): MMS
    //   bit 2 (0x04): Supl (GPS assistance)
    //   bit 3 (0x08): WAP / admin
    //   bit 4 (0x10): Tethering / DUN
    //   bit 5 (0x20): Tethering alternate flag
    //   Higher bits vary by carrier.
    //
    // M4 fix: relaxed matching — we now add tethering flags (0x30) to ANY APN
    // that doesn't already have them, not just data APNs (bit 0). Some carriers
    // use dedicated tethering APNs without the data bit set.
    if ([sAPNTypeMaskKeys containsObject:strKey]) {
        if ([anObject isKindOfClass:[NSNumber class]]) {
            int mask = [anObject intValue];
            if ((mask & 0x30) == 0) {
                // No tethering flags present — add them
                int newMask = mask | 0x30;
                FT_DBG(@"APN TypeMask: %d → %d (added tethering flag)", mask, newMask);
                applyOrig(@(newMask), strKey);
                return YES;
            }
            // Tethering flags already set — no action needed
        }
    }

    return NO;  // Not intercepted
}

// --- Hook NSMutableDictionary for APN type mask manipulation ---
//
// Performance note (S4): This hooks NSMutableDictionary globally within CommCenter.
// APN configuration is written through standard NSMutableDictionary APIs, and
// CommCenter does not expose a more specific class for APN dict mutations.
// The sAPNTypeMaskKeys set provides O(1) lookup, so the overhead for non-matching
// keys is a single hash probe + two boolean checks — negligible in practice.

%group CommCenterAPNHooks

%hook NSMutableDictionary

- (void)setObject:(id)anObject forKey:(id)aKey {
    if (!FTIsEnabled() || !gMaskTraffic) {
        %orig;
        return;
    }

    @try {
        if ([aKey isKindOfClass:[NSString class]]) {
            // W1 safety note: %orig expands to a static function pointer (_logos_orig$...)
            // which is safe to capture in this block — it does not reference stack locals.
            if (FTInterceptAPNSet(anObject, (NSString *)aKey, ^(id obj, id key) {
                %orig(obj, key);
            })) return;
        }
    } @catch (NSException *e) {
        NSLog(@"[FreeTether][ERROR][APN] setObject:forKey: exception: %@", e);
    }

    %orig;
}

// W9 fix: also hook subscript setter (dict[@"key"] = value)
- (void)setObject:(id)anObject forKeyedSubscript:(id)aKey {
    if (!FTIsEnabled() || !gMaskTraffic) {
        %orig;
        return;
    }

    @try {
        if ([aKey isKindOfClass:[NSString class]]) {
            // W1 safety note: %orig capture is safe here — see comment in setObject:forKey: above.
            if (FTInterceptAPNSet(anObject, (NSString *)aKey, ^(id obj, id key) {
                %orig(obj, key);
            })) return;
        }
    } @catch (NSException *e) {
        NSLog(@"[FreeTether][ERROR][APN] setObject:forKeyedSubscript: exception: %@", e);
    }

    %orig;
}

%end

%end  // group CommCenterAPNHooks

%ctor {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    if ([proc isEqualToString:@"CommCenter"]) {
        // #6 fix: exact key set for APN TypeMask interception
        sAPNTypeMaskKeys = [NSSet setWithArray:@[
            @"TypeMask", @"typemask",
            @"APNTypeMask", @"apnTypeMask"
        ]];
        NSLog(@"[FreeTether][APN] Activating APN manager hooks in CommCenter");
        %init(CommCenterAPNHooks);
    }
}
