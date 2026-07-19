// Preferences/FTRootListController.m

#import "FTRootListController.h"
#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <Preferences/PSSpecifier.h>

#define FT_PREFS_DOMAIN  CFSTR("com.freetether")
#define FT_NOTIFY_PREFS  "com.freetether.prefschanged"

@implementation FTRootListController

- (NSArray *)specifiers {
    if (!_specifiers) {
        _specifiers = [self loadSpecifiersFromPlistName:@"Root" target:self];

        // W10 fix: manually localize placeholder for PSEditTextCell
        // (PSListController does not auto-localize the placeholder property)
        for (PSSpecifier *spec in _specifiers) {
            if ([[spec propertyForKey:@"key"] isEqualToString:@"customAPN"]) {
                NSString *placeholder = [spec propertyForKey:@"placeholder"];
                if (placeholder) {
                    NSBundle *bundle = [NSBundle bundleForClass:[self class]];
                    NSString *localized = [bundle localizedStringForKey:placeholder value:placeholder table:@"Root"];
                    [spec setProperty:localized forKey:@"placeholder"];
                }
                break;
            }
        }
    }
    return _specifiers;
}

// W9 fix: use CFPreferences API for cross-user compatibility,
// consistent with Tweak.x preference reads
- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) return [super readPreferenceValue:specifier];

    CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);
    id value = (__bridge_transfer id)CFPreferencesCopyAppValue((__bridge CFStringRef)key, FT_PREFS_DOMAIN);
    if (value) return value;

    // Fall back to default value from specifier
    id defaultValue = [specifier propertyForKey:@"default"];
    return defaultValue;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    if (!key) {
        [super setPreferenceValue:value specifier:specifier];
        return;
    }

    CFPreferencesSetAppValue((__bridge CFStringRef)key,
                             (__bridge CFPropertyListRef)value,
                             FT_PREFS_DOMAIN);
    CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);

    // Post Darwin notification if specifier declares one
    NSString *notification = [specifier propertyForKey:@"PostNotification"];
    if (notification) {
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge CFStringRef)notification, NULL, NULL, YES);
    }
}

- (void)openGitHub {
    // TODO: update to actual repository URL once published
    [[UIApplication sharedApplication]
        openURL:[NSURL URLWithString:@"https://github.com/user/freetether"]
        options:@{}
        completionHandler:nil];
}

@end
