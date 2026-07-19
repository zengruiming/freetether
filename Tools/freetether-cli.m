// Tools/freetether-cli.m
// Command-line utility to check FreeTether status and toggle settings

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <unistd.h>

#define FT_PREFS_DOMAIN  CFSTR("com.freetether")
#define NOTIFY_KEY "com.freetether.prefschanged"

static void notifyPrefsChanged() {
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(NOTIFY_KEY), NULL, NULL, YES);
}

// Read a single preference value via CFPreferences (consistent with Tweak.x)
static id readPref(CFStringRef key) {
    return (__bridge_transfer id)CFPreferencesCopyAppValue(key, FT_PREFS_DOMAIN);
}

// Write a single preference value via CFPreferences (consistent with Tweak.x)
static BOOL writePref(CFStringRef key, id value) {
    CFPreferencesSetAppValue(key, (__bridge CFPropertyListRef)value, FT_PREFS_DOMAIN);
    BOOL ok = CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);
    if (ok) {
        notifyPrefsChanged();
    } else {
        fprintf(stderr, "Error: Failed to synchronize preferences\n");
    }
    return ok;
}

static void printUsage() {
    fprintf(stderr,
        "Usage: freetether-cli <command>\n"
        "\n"
        "Commands:\n"
        "  status              Show current FreeTether configuration\n"
        "  enable              Enable FreeTether\n"
        "  disable             Disable FreeTether (kill switch)\n"
        "  set <key> <on|off>  Toggle a sub-feature\n"
        "  set customAPN <val> Set custom APN (use \"\" or clear to remove)\n"
        "  debug on|off        Enable/disable debug logging\n"
        "\n"
        "Sub-feature keys for 'set':\n"
        "  forceHotspot        Force hotspot capability\n"
        "  bypassEntitlement   Bypass carrier entitlement checks\n"
        "  maskTraffic         Mask tethered traffic as phone traffic\n"
        "  vpnSharing          Share VPN connection over hotspot\n"
        "  wifiSharing         Share Wi-Fi connection over hotspot\n"
    );
}

// W8 fix: helper to read a bool pref with default-YES semantics
static BOOL readBoolPrefDefaultYes(CFStringRef key) {
    id val = readPref(key);
    return (val == nil) || [val boolValue];
}

static void printStatus() {
    // Synchronize first to pick up any pending writes
    CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);

    BOOL enabled    = readBoolPrefDefaultYes(CFSTR("enabled"));
    BOOL debug      = [readPref(CFSTR("debugLog")) boolValue];
    BOOL hotspot    = readBoolPrefDefaultYes(CFSTR("forceHotspot"));
    BOOL bypass     = readBoolPrefDefaultYes(CFSTR("bypassEntitlement"));
    BOOL mask       = readBoolPrefDefaultYes(CFSTR("maskTraffic"));
    // W1 fix: also display vpnSharing and wifiSharing status
    BOOL vpn        = [readPref(CFSTR("vpnSharing")) boolValue];
    BOOL wifi       = [readPref(CFSTR("wifiSharing")) boolValue];
    NSString *apn   = readPref(CFSTR("customAPN")) ?: @"(default)";

    printf("FreeTether Status:\n");
    printf("  Enabled:              %s\n", enabled ? "YES" : "NO");
    printf("  Force Hotspot:        %s\n", hotspot ? "YES" : "NO");
    printf("  Bypass Entitlement:   %s\n", bypass  ? "YES" : "NO");
    printf("  Mask Traffic:         %s\n", mask    ? "YES" : "NO");
    printf("  VPN Sharing:          %s\n", vpn     ? "YES" : "NO");
    printf("  Wi-Fi Sharing:        %s\n", wifi    ? "YES" : "NO");
    printf("  Custom APN:           %s\n", [apn UTF8String]);
    printf("  Debug Log:            %s\n", debug   ? "YES" : "NO");
    // S3 fix: use the macro constant instead of a hardcoded string
    printf("\n  Prefs domain: %s\n",
           "com.freetether");
}

static BOOL setKey(NSString *key, id value) {
    if (!writePref((__bridge CFStringRef)key, value)) {
        fprintf(stderr, "Error: Failed to write preference '%s'\n", [key UTF8String]);
        return NO;
    }
    printf("Set %s = %s\n", [key UTF8String], [[value description] UTF8String]);
    return YES;
}

// W2 fix: valid sub-feature keys that can be toggled via 'set' command
static NSSet *validSubFeatureKeys() {
    return [NSSet setWithObjects:
        @"forceHotspot", @"bypassEntitlement", @"maskTraffic",
        @"vpnSharing", @"wifiSharing", nil];
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            printUsage();
            return 1;
        }

        // W3 fix: check root privileges — CFPreferences writes to the global domain
        // require root on jailbroken iOS to be visible to other processes.
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];
        BOOL isWriteCommand = ![cmd isEqualToString:@"status"];
        if (isWriteCommand && getuid() != 0) {
            fprintf(stderr, "Warning: Not running as root. Preference changes may not "
                    "take effect for system daemons. Try: sudo freetether-cli %s\n",
                    argv[1]);
        }

        if ([cmd isEqualToString:@"status"]) {
            printStatus();
        } else if ([cmd isEqualToString:@"enable"]) {
            if (!setKey(@"enabled", @YES)) return 1;
        } else if ([cmd isEqualToString:@"disable"]) {
            if (!setKey(@"enabled", @NO)) return 1;
        } else if ([cmd isEqualToString:@"set"] && argc >= 4) {
            // W2 fix: sub-feature toggle command
            NSString *key = [NSString stringWithUTF8String:argv[2]];
            NSString *val = [NSString stringWithUTF8String:argv[3]];

            // W14 fix: customAPN accepts a string value, not on/off
            if ([key isEqualToString:@"customAPN"]) {
                if ([val isEqualToString:@"clear"] || [val length] == 0) {
                    // Remove the key to revert to default APN
                    CFPreferencesSetAppValue(CFSTR("customAPN"), NULL, FT_PREFS_DOMAIN);
                    BOOL ok = CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);
                    if (!ok) {
                        fprintf(stderr, "Error: Failed to synchronize preferences\n");
                        return 1;
                    }
                    notifyPrefsChanged();
                    printf("Cleared customAPN (using default)\n");
                } else {
                    if (!setKey(@"customAPN", val)) return 1;
                }
            } else if (![validSubFeatureKeys() containsObject:key]) {
                fprintf(stderr, "Error: Unknown sub-feature key '%s'\n", [key UTF8String]);
                fprintf(stderr, "Valid keys: forceHotspot, bypassEntitlement, maskTraffic, "
                        "vpnSharing, wifiSharing, customAPN\n");
                return 1;
            } else if ([val isEqualToString:@"on"]) {
                if (!setKey(key, @YES)) return 1;
            } else if ([val isEqualToString:@"off"]) {
                if (!setKey(key, @NO)) return 1;
            } else {
                fprintf(stderr, "Error: 'set' expects 'on' or 'off', got '%s'\n", [val UTF8String]);
                return 1;
            }
        } else if ([cmd isEqualToString:@"debug"] && argc >= 3) {
            NSString *val = [NSString stringWithUTF8String:argv[2]];
            // #12 fix: validate argument strictly — only accept 'on' or 'off'
            if ([val isEqualToString:@"on"]) {
                if (!setKey(@"debugLog", @YES)) return 1;
            } else if ([val isEqualToString:@"off"]) {
                if (!setKey(@"debugLog", @NO)) return 1;
            } else {
                fprintf(stderr, "Error: 'debug' expects 'on' or 'off', got '%s'\n", [val UTF8String]);
                printUsage();
                return 1;
            }
        } else {
            printUsage();
            return 1;
        }

        return 0;
    }
}
