// Preferences/FTRootListController.m

#import "FTRootListController.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>
#import <ifaddrs.h>
#import <net/if.h>

#define FT_NOTIFY_PREFS  "com.freetether.prefschanged"

// NSLocalizedString uses [NSBundle mainBundle] which is Settings.app in a
// PreferenceBundle context — it would never find our strings.  Use our own
// bundle (resolved from our class) and the "Root" strings table instead.
#define FTLocalize(key) [[NSBundle bundleForClass:[self class]] localizedStringForKey:(key) value:(key) table:@"Root"]
// Write prefs to mobile's domain file — system daemons (root) read this
// same file via NSDictionary, bypassing CFPreferences' per-UID isolation.
#define FT_PREFS_PATH @"/var/mobile/Library/Preferences/com.freetether.plist"

@implementation FTRootListController

// --- Network interface detection (simplified from FTNetworkRouting.x) ---

// Check for an active VPN tunnel interface (utun* with IFF_UP).
// Uses the same heuristic as FTNetworkRouting.x: look for utun interfaces
// that are UP and have either an IPv4 address or the IFF_POINTOPOINT flag.
+ (BOOL)hasActiveVPNInterface {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return NO;

    BOOL found = NO;
    for (struct ifaddrs *ifp = interfaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL || ifp->ifa_name == NULL) continue;
        NSString *name = [NSString stringWithUTF8String:ifp->ifa_name];
        if ([name hasPrefix:@"utun"] && (ifp->ifa_flags & IFF_UP)) {
            BOOL hasIPv4 = (ifp->ifa_addr->sa_family == AF_INET);
            if (hasIPv4 || (ifp->ifa_flags & IFF_POINTOPOINT)) {
                found = YES;
                break;
            }
        }
    }
    freeifaddrs(interfaces);
    return found;
}

// Check whether Wi-Fi (en0) is UP.
+ (BOOL)hasActiveWiFiInterface {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return NO;

    BOOL found = NO;
    for (struct ifaddrs *ifp = interfaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL || ifp->ifa_name == NULL) continue;
        NSString *name = [NSString stringWithUTF8String:ifp->ifa_name];
        if ([name isEqualToString:@"en0"] && (ifp->ifa_flags & IFF_UP)) {
            found = YES;
            break;
        }
    }
    freeifaddrs(interfaces);
    return found;
}

// --- PSListController overrides ---

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];
    }
    return _specifiers;
}

// F1 fix: refresh specifier values when returning to the settings pane.
// If the user toggled FreeTether via CC while Settings was in the background,
// the switches would show stale state without this.
- (void)viewWillAppear:(BOOL)animated {
    [super viewWillAppear:animated];
    [self reloadSpecifiers];
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return [super readPreferenceValue:specifier];

    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH];
    id value = dict[key];
    if (value) return value;

    // Fall back to default value from specifier
    return [specifier propertyForKey:@"default"];
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) {
        [super setPreferenceValue:value specifier:specifier];
        return;
    }

    // --- Pre-flight validation for sharing toggles ---
    if ([value boolValue]) {
        if ([key isEqualToString:@"vpnSharing"]) {
            if (![[self class] hasActiveVPNInterface]) {
                [self showValidationAlert:
                    FTLocalize(@"VPN_NOT_CONNECTED")
                    message:FTLocalize(@"VPN_NOT_CONNECTED_MSG")];
                [self reloadSpecifier:specifier animated:YES];
                return;
            }
        } else if ([key isEqualToString:@"wifiSharing"]) {
            if (![[self class] hasActiveWiFiInterface]) {
                [self showValidationAlert:
                    FTLocalize(@"WIFI_NOT_CONNECTED")
                    message:FTLocalize(@"WIFI_NOT_CONNECTED_MSG")];
                [self reloadSpecifier:specifier animated:YES];
                return;
            }
        }
    }

    // Read existing prefs, merge new value, write back atomically
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: [NSMutableDictionary dictionary];
    dict[key] = value;

    // Mutual exclusion: vpnSharing and wifiSharing cannot both be on
    if ([value boolValue]) {
        NSString *oppositeKey = nil;
        if ([key isEqualToString:@"vpnSharing"]) {
            oppositeKey = @"wifiSharing";
        } else if ([key isEqualToString:@"wifiSharing"]) {
            oppositeKey = @"vpnSharing";
        }
        if (oppositeKey && [dict[oppositeKey] boolValue]) {
            dict[oppositeKey] = @NO;
        }
    }

    if (![dict writeToFile:FT_PREFS_PATH atomically:YES]) {
        NSLog(@"[FreeTether][ERROR][Prefs] Failed to write preferences");
        // Reload this specifier to rollback the UI to the actual persisted value
        [self reloadSpecifier:specifier animated:YES];
        return;  // Don't notify on failure — avoids UI/tweak desync
    }

    // Reload all specifiers to reflect mutual-exclusion changes
    if ([key isEqualToString:@"vpnSharing"] || [key isEqualToString:@"wifiSharing"]) {
        [self reloadSpecifiers];
    }

    // Post Darwin notification if specifier declares one
    NSString *notification = [specifier propertyForKey:@"PostNotification"];
    if (notification) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, YES);
    }
}

- (void)showValidationAlert:(NSString *)title message:(NSString *)message {
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:title
        message:message
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
        style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openPersonalHotspot {
    // Try multiple URL schemes — behaviour varies across iOS versions and
    // jailbreak environments. In particular, Settings.app may ignore its own
    // App-Prefs: scheme when the bundle is hosted inside the same process.
    NSArray *schemes = @[
        @"App-Prefs:root=INTERNET_TETHERING",
        @"prefs:root=INTERNET_TETHERING",
        @"App-Prefs:root=INTERNET_TETHERING&path=Personal%20Hotspot",
    ];

    UIApplication *app = [UIApplication sharedApplication];
    for (NSString *scheme in schemes) {
        NSURL *url = [NSURL URLWithString:scheme];
        if (url && [app canOpenURL:url]) {
            [app openURL:url options:@{} completionHandler:^(BOOL success) {
                if (!success) {
                    NSLog(@"[FreeTether][Prefs] openURL %@ returned NO", scheme);
                }
            }];
            return;
        }
    }

    // All schemes failed — show an alert so the user knows something went wrong
    UIAlertController *alert = [UIAlertController
        alertControllerWithTitle:FTLocalize(@"HOTSPOT_OPEN_FAILED_TITLE")
        message:FTLocalize(@"HOTSPOT_OPEN_FAILED_MSG")
        preferredStyle:UIAlertControllerStyleAlert];
    [alert addAction:[UIAlertAction actionWithTitle:@"OK"
        style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:alert animated:YES completion:nil];
}

- (void)openGitHub {
    [[UIApplication sharedApplication]
        openURL:[NSURL URLWithString:@"https://github.com/anthropics/FreeTether"]
        options:@{}
        completionHandler:nil];
}

@end
