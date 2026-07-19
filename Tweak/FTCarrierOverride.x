// Tweak/FTCarrierOverride.x
// Intercept carrier.plist dictionary reads to inject tethering config

#import <Foundation/Foundation.h>

extern BOOL FTIsEnabled();
extern BOOL gForceHotspot;
extern BOOL gDebugLog;

#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG][Carrier] " fmt, ##__VA_ARGS__); } while(0)

// Fast-path: pre-built set of keys we intercept (W4 performance fix)
static NSSet *sInterceptedKeys;

// --- Interception logic (shared between objectForKey: and objectForKeyedSubscript:) ---

static id FTInterceptCarrierKey(NSString *strKey, id origValue) {
    // Note: caller already verifies strKey is in sInterceptedKeys before calling us.

    // Intercept tethering-related keys
    if ([strKey isEqualToString:@"AllowedTethering"]) {
        FT_DBG(@"Intercepted AllowedTethering → injecting [wifi, usb, bluetooth]");
        return @[@"wifi", @"usb", @"bluetooth"];
    }

    if ([strKey isEqualToString:@"TetheringEntitlement"] ||
        [strKey isEqualToString:@"EntitlementsTethering"] ||
        [strKey isEqualToString:@"kEntitlementsTethering"]) {
        FT_DBG(@"Intercepted %@ → returning NO (skip entitlement check)", strKey);
        return @NO;
    }

    // S8: EnableTethering / TetheringAllowed — boolean gates some carriers use
    if ([strKey isEqualToString:@"EnableTethering"] ||
        [strKey isEqualToString:@"TetheringAllowed"]) {
        FT_DBG(@"Intercepted %@ → returning YES", strKey);
        return @YES;
    }

    // S8: services/Tethering — service descriptor dict used by some carrier bundles
    if ([strKey isEqualToString:@"services/Tethering"]) {
        FT_DBG(@"Intercepted services/Tethering → returning enabled dict");
        return @{@"enabled": @YES};
    }

    // C2 fix: Intercept PersonalHotspot.Enabled — some carriers hide hotspot UI via this key
    if ([strKey isEqualToString:@"PersonalHotspot"]) {
        FT_DBG(@"Intercepted PersonalHotspot → injecting dict with Enabled=YES");
        // Return a mutable dict so sub-key lookups also see our override
        NSMutableDictionary *hotspotDict = [origValue isKindOfClass:[NSDictionary class]]
            ? [origValue mutableCopy]
            : [NSMutableDictionary dictionary];
        hotspotDict[@"Enabled"] = @YES;
        return [hotspotDict copy];
    }

    // Handle the case where "Enabled" is looked up as a flat key
    // (some carrier bundles use flat keys instead of nested dicts)
    if ([strKey isEqualToString:@"PersonalHotspot.Enabled"]) {
        FT_DBG(@"Intercepted PersonalHotspot.Enabled → returning YES");
        return @YES;
    }

    return origValue;
}

// --- Hook NSDictionary to intercept carrier.plist key lookups ---
// #5 fix: narrowed scope — only intercept when key is in sInterceptedKeys
// #15 fix: eliminated double %orig call — store origValue and return it on non-intercepted path
//
// Performance note (S5): This hooks NSDictionary globally within CommCenter.
// carrier.plist values are read through standard NSDictionary APIs, and CommCenter
// does not expose a more specific hook point (no dedicated carrier-plist class).
// The sInterceptedKeys set provides O(1) lookup, so the overhead for non-matching
// keys is a single hash probe + two boolean checks — negligible in practice.

%group CommCenterHooks

%hook NSDictionary

- (id)objectForKey:(id)key {
    if (!FTIsEnabled() || !gForceHotspot) return %orig;

    @try {
        if ([key isKindOfClass:[NSString class]] && [sInterceptedKeys containsObject:key]) {
            id origValue = %orig;
            id intercepted = FTInterceptCarrierKey((NSString *)key, origValue);
            return intercepted;  // Always return — intercepted or origValue
        }
    } @catch (NSException *e) {
        NSLog(@"[FreeTether][ERROR][Carrier] objectForKey exception: %@", e);
    }

    return %orig;
}

- (id)objectForKeyedSubscript:(id)key {
    if (!FTIsEnabled() || !gForceHotspot) return %orig;

    @try {
        if ([key isKindOfClass:[NSString class]] && [sInterceptedKeys containsObject:key]) {
            id origValue = %orig;
            id intercepted = FTInterceptCarrierKey((NSString *)key, origValue);
            return intercepted;
        }
    } @catch (NSException *e) {
        NSLog(@"[FreeTether][ERROR][Carrier] objectForKeyedSubscript exception: %@", e);
    }

    return %orig;
}

%end

%end  // group CommCenterHooks

%ctor {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    if ([proc isEqualToString:@"CommCenter"]) {
        // Build fast-lookup set for intercepted keys (W4 performance optimization)
        // S8: expanded set covers keys used by various carrier bundles worldwide
        sInterceptedKeys = [NSSet setWithArray:@[
            @"AllowedTethering",
            @"TetheringEntitlement",
            @"EntitlementsTethering",
            @"kEntitlementsTethering",   // S8: alternate entitlement key
            @"EnableTethering",          // S8: boolean gate (some carriers)
            @"TetheringAllowed",         // S8: boolean gate (some carriers)
            @"services/Tethering",       // S8: service descriptor dict
            @"PersonalHotspot",
            @"PersonalHotspot.Enabled"
            // Note: SignedPLists intentionally NOT intercepted — altering signed
            // plist validation could break carrier provisioning and other features.
        ]];

        NSLog(@"[FreeTether][Carrier] Activating carrier override hooks in CommCenter");
        %init(CommCenterHooks);
    }
}
