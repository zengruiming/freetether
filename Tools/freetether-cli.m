// Tools/freetether-cli.m
// Command-line utility to check FreeTether status and toggle settings

#import <Foundation/Foundation.h>
#import <CoreFoundation/CoreFoundation.h>
#import <unistd.h>
#import <sys/stat.h>
#import <errno.h>

// All components share the same on-disk plist so root daemons can read
// what mobile-user Settings.app writes.
#define FT_PREFS_PATH @"/var/mobile/Library/Preferences/com.freetether.plist"
#define NOTIFY_KEY "com.freetether.prefschanged"

static void notifyPrefsChanged() {
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        CFSTR(NOTIFY_KEY), NULL, NULL, YES);
}

// Read the entire prefs dictionary from the shared plist file
static NSDictionary *readPrefsDict() {
    return [NSDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: @{};
}

// Write a single preference key and notify
static BOOL writePref(NSString *key, id value) {
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: [NSMutableDictionary dictionary];
    dict[key] = value;
    BOOL ok = [dict writeToFile:FT_PREFS_PATH atomically:YES];
    if (ok) {
        // Restore mobile ownership so Settings.app (UID 501) can still write
        if (chown([FT_PREFS_PATH fileSystemRepresentation], 501, 501) != 0) {
            fprintf(stderr, "Warning: Failed to restore ownership on %s: %s\n",
                    [FT_PREFS_PATH UTF8String], strerror(errno));
        }
        notifyPrefsChanged();
    } else {
        fprintf(stderr, "Error: Failed to write preferences to %s\n", [FT_PREFS_PATH UTF8String]);
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
        "  debug on|off        Enable/disable debug logging\n"
        "\n"
        "Sub-feature keys for 'set':\n"
        "  vpnSharing          Share VPN connection over hotspot\n"
        "  wifiSharing         Share Wi-Fi connection over hotspot\n"
    );
}

static void printStatus() {
    NSDictionary *dict = readPrefsDict();

    BOOL enabled    = (dict[@"enabled"] == nil) || [dict[@"enabled"] boolValue];
    BOOL debug      = [dict[@"debugLog"] boolValue];
    BOOL vpn        = [dict[@"vpnSharing"] boolValue];
    BOOL wifi       = [dict[@"wifiSharing"] boolValue];

    printf("FreeTether Status:\n");
    printf("  Enabled:              %s\n", enabled ? "YES" : "NO");
    printf("  VPN Sharing:          %s\n", vpn     ? "YES" : "NO");
    printf("  Wi-Fi Sharing:        %s\n", wifi    ? "YES" : "NO");
    printf("  Debug Log:            %s\n", debug   ? "YES" : "NO");
    printf("\n  Prefs file: %s\n",
           [FT_PREFS_PATH UTF8String]);
}

static BOOL setKey(NSString *key, id value) {
    if (!writePref(key, value)) {
        return NO;
    }
    printf("Set %s = %s\n", [key UTF8String], [[value description] UTF8String]);
    return YES;
}

// Valid sub-feature keys that can be toggled via 'set' command
static NSSet *validSubFeatureKeys() {
    return [NSSet setWithObjects:
        @"vpnSharing", @"wifiSharing", nil];
}

int main(int argc, char *argv[]) {
    @autoreleasepool {
        if (argc < 2) {
            printUsage();
            return 1;
        }

        // Check write permissions — the plist is owned by mobile (UID 501).
        // Running as root ensures file ownership is preserved correctly and
        // avoids potential permission issues in restricted environments.
        NSString *cmd = [NSString stringWithUTF8String:argv[1]];
        BOOL isWriteCommand = [cmd isEqualToString:@"enable"] ||
                              [cmd isEqualToString:@"disable"] ||
                              [cmd isEqualToString:@"set"] ||
                              [cmd isEqualToString:@"debug"];
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
        } else if ([cmd isEqualToString:@"set"]) {
            if (argc < 4) {
                fprintf(stderr, "Error: 'set' requires <key> <on|off>\n");
                fprintf(stderr, "Example: freetether-cli set vpnSharing on\n");
                return 1;
            }
            NSString *key = [NSString stringWithUTF8String:argv[2]];
            NSString *val = [NSString stringWithUTF8String:argv[3]];

            if (!key || !val) {
                fprintf(stderr, "Error: Invalid argument encoding\n");
                return 1;
            }

            if (![validSubFeatureKeys() containsObject:key]) {
                fprintf(stderr, "Error: Unknown sub-feature key '%s'\n", [key UTF8String]);
                fprintf(stderr, "Valid keys: vpnSharing, wifiSharing\n");
                return 1;
            }

            if ([val isEqualToString:@"on"]) {
                if (!setKey(key, @YES)) return 1;
            } else if ([val isEqualToString:@"off"]) {
                if (!setKey(key, @NO)) return 1;
            } else {
                fprintf(stderr, "Error: 'set' expects 'on' or 'off', got '%s'\n", [val UTF8String]);
                return 1;
            }
        } else if ([cmd isEqualToString:@"debug"]) {
            if (argc < 3) {
                fprintf(stderr, "Error: 'debug' requires on|off\n");
                fprintf(stderr, "Example: freetether-cli debug on\n");
                return 1;
            }
            NSString *val = [NSString stringWithUTF8String:argv[2]];
            if (!val) {
                fprintf(stderr, "Error: Invalid argument encoding\n");
                return 1;
            }
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
