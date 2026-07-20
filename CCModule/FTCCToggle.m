// CCModule/FTCCToggle.m

#import "FTCCToggle.h"
#import <UIKit/UIKit.h>

#define FT_NOTIFY_PREFS  CFSTR("com.freetether.prefschanged")
// CC module runs as mobile user — same path, consistent with Settings and Tweak
#define FT_PREFS_PATH @"/var/mobile/Library/Preferences/com.freetether.plist"

// Cached state to avoid CFPreferences calls on every isSelected
static BOOL sCachedEnabled = YES;
static BOOL sCacheLoaded   = NO;

// When YES, setSelected: only updates UI (skip plist write + notification).
// Set by the notification callback to avoid re-entering the write+notify path.
static BOOL sUpdatingFromNotification = NO;

// Read a single preference from the shared plist file
static id readPref(NSString *key) {
    NSDictionary *dict = [NSDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH];
    return dict[key];
}

static void reloadCachedState() {
    id val = readPref(@"enabled");
    sCachedEnabled = (val == nil) || [val boolValue];
    sCacheLoaded = YES;
}

// Weak reference for notification callback — safe if CC reclaims the instance
static __weak FTCCToggle *sSharedToggle = nil;

static void prefsChangedCallback(CFNotificationCenterRef center, void *observer,
    CFNotificationName name, const void *object, CFDictionaryRef userInfo) {
    BOOL oldValue = sCachedEnabled;
    reloadCachedState();
    // Only update UI if the value actually changed
    if (oldValue != sCachedEnabled) {
        FTCCToggle *toggle = sSharedToggle;
        if (toggle) {
            dispatch_async(dispatch_get_main_queue(), ^{
                sUpdatingFromNotification = YES;
                @try {
                    [toggle setSelected:sCachedEnabled];
                } @finally {
                    sUpdatingFromNotification = NO;
                }
            });
        }
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
    // Don't nil sSharedToggle — if a new instance was already created,
    // its init set sSharedToggle. __weak zeroing handles the normal case.
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

    // When called from notification callback, just update UI — don't re-write
    // the plist or re-post the notification (avoids reentrant write+notify cycle).
    if (sUpdatingFromNotification) {
        sCachedEnabled = selected;
        return;
    }

    // Write via plist file (consistent with Settings and Tweak)
    NSMutableDictionary *dict = [NSMutableDictionary dictionaryWithContentsOfFile:FT_PREFS_PATH] ?: [NSMutableDictionary dictionary];
    dict[@"enabled"] = @(selected);
    BOOL ok = [dict writeToFile:FT_PREFS_PATH atomically:YES];

    if (ok) {
        sCachedEnabled = selected;
    } else {
        NSLog(@"[FreeTether][ERROR][CC] Failed to write prefs, reverting toggle state");
        reloadCachedState();
        [super setSelected:sCachedEnabled];
        return;  // Don't notify on failure
    }

    // Notify tweak of config change
    CFNotificationCenterPostNotification(
        CFNotificationCenterGetDarwinNotifyCenter(),
        FT_NOTIFY_PREFS, NULL, NULL, YES);
}

@end
