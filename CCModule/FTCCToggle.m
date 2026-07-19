// CCModule/FTCCToggle.m

#import "FTCCToggle.h"
#import <UIKit/UIKit.h>
#import <stdatomic.h>

#define FT_PREFS_DOMAIN  CFSTR("com.freetether")
#define FT_NOTIFY_PREFS  CFSTR("com.freetether.prefschanged")

// Cached state to avoid CFPreferences calls on every isSelected
static BOOL sCachedEnabled = YES;
static BOOL sCacheLoaded   = NO;

// C3 fix: prevent self-trigger when setSelected: posts notification
// Use atomic flag to avoid race between main thread and notification callback
static _Atomic BOOL sIgnoreNextNotification = NO;

// Read a single preference via CFPreferences (consistent with Tweak.x)
static id readPref(CFStringRef key) {
    return (__bridge_transfer id)CFPreferencesCopyAppValue(key, FT_PREFS_DOMAIN);
}

static void reloadCachedState() {
    CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);
    id val = readPref(CFSTR("enabled"));
    sCachedEnabled = (val == nil) || [val boolValue];
    sCacheLoaded = YES;
}

// Weak reference for notification callback — safe if CC reclaims the instance
static __weak FTCCToggle *sSharedToggle = nil;

static void prefsChangedCallback(CFNotificationCenterRef center, void *observer,
    CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    // C3 fix: skip if this notification was posted by our own setSelected:
    if (sIgnoreNextNotification) {
        sIgnoreNextNotification = NO;
        return;
    }
    reloadCachedState();
    FTCCToggle *toggle = sSharedToggle;
    if (toggle) {
        dispatch_async(dispatch_get_main_queue(), ^{
            // C4 fix: CCUIToggleModule does not have a public refreshState method.
            // Calling it would cause an unrecognized selector crash.
            // Use setSelected: to update the toggle UI state instead.
            [toggle setSelected:sCachedEnabled];
        });
    }
}

@implementation FTCCToggle

- (instancetype)init {
    self = [super init];
    if (self) {
        sSharedToggle = self;
        reloadCachedState();
        CFNotificationCenterAddObserver(
            CFNotificationCenterGetDarwinNotifyCenter(),
            (__bridge void *)self,
            prefsChangedCallback,
            FT_NOTIFY_PREFS, NULL,
            CFNotificationSuspensionBehaviorCoalesce);
    }
    return self;
}

- (void)dealloc {
    sSharedToggle = nil;
    CFNotificationCenterRemoveObserver(
        CFNotificationCenterGetDarwinNotifyCenter(),
        (__bridge void *)self, FT_NOTIFY_PREFS, NULL);
}

- (UIImage *)iconGlyph {
    // systemImageNamed: requires iOS 13+; rootless jailbreaks target iOS 

    return [UIImage systemImageNamed:@"personalhotspot"];
}

- (UIColor *)selectedColor {
    return [UIColor systemBlueColor];
}

- (BOOL)isSelected {
    if (!sCacheLoaded) reloadCachedState();
    return sCachedEnabled;
}

- (void)setSelected:(BOOL)selected {
    [super setSelected:selected];

    // Write via CFPreferences (consistent with Tweak.x)
    CFPreferencesSetAppValue(CFSTR("enabled"), (__bridge CFPropertyListRef)@(selected), FT_PREFS_DOMAIN);
    BOOL ok = CFPreferencesAppSynchronize(FT_PREFS_DOMAIN);

    if (ok) {
        sCachedEnabled = selected;
    } else {
        NSLog(@"[FreeTether][ERROR][CC] Failed to write prefs, reverting toggle state");
        reloadCachedState();
        [super setSelected:sCachedEnabled];
        return;  // Don't notify on failure
    }

    // C3 fix: mark to ignore the notification we are about to post
    sIgnoreNextNotification = YES;

    // Notify tweak of config change
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        FT_NOTIFY_PREFS, NULL, NULL, YES);
}

@end
