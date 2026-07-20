// Preferences/FTRootListController.m

#import "FTRootListController.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>

#define FT_NOTIFY_PREFS  "com.freetether.prefschanged"
// Write prefs to mobile's domain file — system daemons (root) read this
// same file via NSDictionary, bypassing CFPreferences' per-UID isolation.
#define FT_PREFS_PATH @"/var/mobile/Library/Preferences/com.freetether.plist"

@implementation FTRootListController

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

    // Read existing prefs, merge new value, write back atomically
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: [NSMutableDictionary dictionary];
    dict[key] = value;
    if (![dict writeToFile:FT_PREFS_PATH atomically:YES]) {
        NSLog(@"[FreeTether][ERROR][Prefs] Failed to write preferences");
        // Reload this specifier to rollback the UI to the actual persisted value
        [self reloadSpecifier:specifier animated:YES];
        return;  // Don't notify on failure — avoids UI/tweak desync
    }

    // Post Darwin notification if specifier declares one
    NSString *notification = [specifier propertyForKey:@"PostNotification"];
    if (notification) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, YES);
    }
}

- (void)openPersonalHotspot {
    // Open system Personal Hotspot settings page
    // App-Prefs: URL scheme works on jailbroken iOS to open specific Settings panes
    NSURL *url = [NSURL URLWithString:@"App-Prefs:root=INTERNET_TETHERING"];
    [[UIApplication sharedApplication] openURL:url options:@{} completionHandler:nil];
}

- (void)openGitHub {
    [[UIApplication sharedApplication]
        openURL:[NSURL URLWithString:@"https://github.com/anthropics/FreeTether"]
        options:@{}
        completionHandler:nil];
}

@end
