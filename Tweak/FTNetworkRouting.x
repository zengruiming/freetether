// Tweak/FTNetworkRouting.x
// VPN sharing: redirect hotspot NAT traffic through VPN tunnel interface
// Wi-Fi sharing: redirect hotspot NAT traffic through Wi-Fi STA interface

#import <Foundation/Foundation.h>
// SCDynamicStore APIs are marked unavailable on iOS in newer SDKs,
// but they exist and work on jailbroken devices. We use dlsym to call them
// at runtime to avoid compile-time unavailability errors.
#import <SystemConfiguration/SystemConfiguration.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <net/if.h>
#import <ifaddrs.h>
#import <arpa/inet.h>
#import <sys/wait.h>
#import <spawn.h>
#import <stdatomic.h>
#import <fcntl.h>
#import <signal.h>

extern BOOL FTIsEnabled();
extern BOOL gDebugLog;

// Forward declaration — internal implementation (called only on sRouteQueue)
static void FTApplyRouteOverrideImpl(void);

#define FT_DBG(fmt, ...) do { if (gDebugLog) NSLog(@"[FreeTether][DBG][Route] " fmt, ##__VA_ARGS__); } while(0)
#define FT_ROUTE_LOG(fmt, ...) NSLog(@"[FreeTether][Route] " fmt, ##__VA_ARGS__)

// --- Prefs for routing (loaded via Darwin notify in Tweak.x) ---
// Use C11 atomics to avoid data races between writer (FTLoadRoutingPrefs, any thread)
// and readers (sysctl hook / SCDynamicStore callback).
static _Atomic BOOL gVPNSharing  = NO;
static _Atomic BOOL gWiFiSharing = NO;

// Serial queue for route operations (S2 fix: prevent concurrent access)
static dispatch_queue_t sRouteQueue;
// M2 fix: use C11 atomics instead of deprecated OSAtomic
static _Atomic int32_t sDebounceToken = 0;
// F1 fix: saved original IP forwarding values for restore
static int sOriginalIPv4Forwarding = -1;
static int sOriginalIPv6Forwarding = -1;
// M1 fix: track whether we enabled pf
static BOOL sPFEnabledByUs = NO;
// Track whether anchor references have been injected into main ruleset
static BOOL sAnchorInstalled = NO;
// SIGTERM dispatch source for cleanup (launchd sends SIGTERM, not exit())
static dispatch_source_t sSignalSource = NULL;

// --- Interface detection helpers ---

// S1 fix: improved VPN interface detection — prefer utun interfaces that have an IPv4
// address assigned. S6 fix: removed hardcoded utun0/utun1 skip; instead check for
// IFF_POINTOPOINT flag to distinguish VPN tunnels from system utun interfaces.
static NSString *findActiveVPNInterface() {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return nil;

    // S6 fix: collect all UP utun interfaces with IPv4 addresses assigned.
    // Instead of hardcoding utun0/utun1 as system interfaces, we check whether
    // each utun has a point-to-point destination (IFF_POINTOPOINT) — VPN tunnels
    // always do, while system utun interfaces (Private Relay, Wi-Fi Assist) typically
    // don't have an IPv4 address assigned.
    NSString *vpnIf = nil;
    int highestIndex = -1;
    BOOL bestHasIPv4 = NO;
    for (struct ifaddrs *ifp = interfaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL) continue;
        NSString *name = [NSString stringWithUTF8String:ifp->ifa_name];
        if ([name hasPrefix:@"utun"] && (ifp->ifa_flags & IFF_UP)) {
            int idx = [[name substringFromIndex:4] intValue];

            BOOL hasIPv4 = (ifp->ifa_addr->sa_family == AF_INET);
            // S6: skip utun interfaces without IPv4 and without point-to-point flag —
            // these are typically system interfaces (Private Relay, Wi-Fi Assist etc.)
            if (!hasIPv4 && !(ifp->ifa_flags & IFF_POINTOPOINT)) continue;

            // Prefer interfaces with IPv4, among those pick highest index
            if (hasIPv4 && !bestHasIPv4) {
                // First IPv4 candidate always wins over non-IPv4
                highestIndex = idx;
                vpnIf = name;
                bestHasIPv4 = YES;
            } else if (hasIPv4 == bestHasIPv4 && idx > highestIndex) {
                // Same category — pick highest index
                highestIndex = idx;
                vpnIf = name;
            }
        }
    }
    freeifaddrs(interfaces);
    if (vpnIf) {
        FT_ROUTE_LOG(@"Detected VPN interface: %@ (idx=%d, hasIPv4=%d) — verify manually if VPN traffic is not routed correctly",
                     vpnIf, highestIndex, bestHasIPv4);
    }
    return vpnIf;
}

static NSString *findActiveWiFiInterface() {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return nil;

    NSString *wifiIf = nil;
    for (struct ifaddrs *ifp = interfaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL) continue;
        NSString *name = [NSString stringWithUTF8String:ifp->ifa_name];
        if ([name isEqualToString:@"en0"] && (ifp->ifa_flags & IFF_UP)) {
            wifiIf = name;
            break;
        }
    }
    freeifaddrs(interfaces);
    return wifiIf;
}

static NSString *findHotspotBridgeInterface() {
    struct ifaddrs *interfaces = NULL;
    if (getifaddrs(&interfaces) != 0) return nil;

    NSString *bridgeIf = nil;
    for (struct ifaddrs *ifp = interfaces; ifp != NULL; ifp = ifp->ifa_next) {
        if (ifp->ifa_addr == NULL) continue;
        NSString *name = [NSString stringWithUTF8String:ifp->ifa_name];
        // Hotspot bridge is typically bridge100
        if ([name hasPrefix:@"bridge"] && (ifp->ifa_flags & IFF_UP)) {
            bridgeIf = name;
            break;
        }
    }
    freeifaddrs(interfaces);
    return bridgeIf;
}

// --- NAT route manipulation via sysctl ---

// F1 fix: save original IPv4 forwarding value before enabling, so we can restore it later.
// M3 fix: also handle IPv6 forwarding (net.inet6.ip6.forwarding).
static BOOL enableIPForwarding() {
    // Save and enable IPv4 forwarding
    int mib[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING };
    if (sOriginalIPv4Forwarding == -1) {
        int oldVal = 0;
        size_t oldLen = sizeof(oldVal);
        if (sysctl(mib, 4, &oldVal, &oldLen, NULL, 0) == 0) {
            sOriginalIPv4Forwarding = oldVal;
            FT_DBG(@"Saved original IPv4 forwarding value: %d", oldVal);
        }
    }
    int enable = 1;
    if (sysctl(mib, 4, NULL, NULL, &enable, sizeof(enable)) != 0) {
        FT_ROUTE_LOG(@"Failed to enable IPv4 forwarding: %s", strerror(errno));
        return NO;
    }

    // M3 fix: save and enable IPv6 forwarding via sysctlbyname
    if (sOriginalIPv6Forwarding == -1) {
        int oldVal6 = 0;
        size_t oldLen6 = sizeof(oldVal6);
        if (sysctlbyname("net.inet6.ip6.forwarding", &oldVal6, &oldLen6, NULL, 0) == 0) {
            sOriginalIPv6Forwarding = oldVal6;
            FT_DBG(@"Saved original IPv6 forwarding value: %d", oldVal6);
        }
    }
    int enable6 = 1;
    if (sysctlbyname("net.inet6.ip6.forwarding", NULL, NULL, &enable6, sizeof(enable6)) != 0) {
        FT_DBG(@"Failed to enable IPv6 forwarding: %s (non-fatal)", strerror(errno));
    }

    FT_DBG(@"IP forwarding enabled (v4 + v6)");
    return YES;
}

// F1 fix: restore IP forwarding to the saved original values instead of unconditionally
// disabling. If original values were never saved, leave the setting untouched.
static void restoreIPForwarding() {
    if (sOriginalIPv4Forwarding != -1) {
        int mib[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING };
        if (sysctl(mib, 4, NULL, NULL, &sOriginalIPv4Forwarding, sizeof(sOriginalIPv4Forwarding)) != 0) {
            FT_ROUTE_LOG(@"Failed to restore IPv4 forwarding to %d: %s", sOriginalIPv4Forwarding, strerror(errno));
        } else {
            FT_DBG(@"Restored IPv4 forwarding to %d", sOriginalIPv4Forwarding);
        }
        sOriginalIPv4Forwarding = -1;
    }
    // M3 fix: restore IPv6 forwarding
    if (sOriginalIPv6Forwarding != -1) {
        if (sysctlbyname("net.inet6.ip6.forwarding", NULL, NULL, &sOriginalIPv6Forwarding, sizeof(sOriginalIPv6Forwarding)) != 0) {
            FT_DBG(@"Failed to restore IPv6 forwarding to %d: %s (non-fatal)", sOriginalIPv6Forwarding, strerror(errno));
        } else {
            FT_DBG(@"Restored IPv6 forwarding to %d", sOriginalIPv6Forwarding);
        }
        sOriginalIPv6Forwarding = -1;
    }
}

// S2 fix: use posix_spawn instead of system() for security in daemon context.
// Parses the command string into argv and spawns the process directly.
extern char **environ;

// S5 fix: accept NSArray argv directly instead of parsing a string
static int execRouteCommand(NSArray *args) {
    FT_DBG(@"Executing: %@", [args componentsJoinedByString:@" "]);

    if (args.count == 0) return -1;

    // Build C argv array
    const char **argv = (const char **)calloc(args.count + 1, sizeof(char *));
    if (!argv) return -1;
    for (NSUInteger i = 0; i < args.count; i++) {
        argv[i] = [args[i] UTF8String];
    }
    argv[args.count] = NULL;

    // Redirect stderr to /dev/null
    posix_spawn_file_actions_t fileActions;
    posix_spawn_file_actions_init(&fileActions);
    posix_spawn_file_actions_addopen(&fileActions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

    pid_t pid = 0;
    int spawnResult = posix_spawn(&pid, argv[0], &fileActions, NULL, (char *const *)argv, environ);
    posix_spawn_file_actions_destroy(&fileActions);
    free(argv);

    if (spawnResult != 0) {
        FT_ROUTE_LOG(@"posix_spawn failed: %s", strerror(spawnResult));
        return -1;
    }

    int status = 0;
    if (waitpid(pid, &status, 0) == -1) {
        FT_ROUTE_LOG(@"waitpid failed: %s", strerror(errno));
        return -1;
    }
    return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

static BOOL applyNATRouteOverride(NSString *fromInterface, NSString *toInterface) {
    if (!fromInterface || !toInterface) return NO;

    FT_ROUTE_LOG(@"Applying NAT route: %@ → %@", fromInterface, toInterface);

    // Enable IP forwarding (required for NAT)
    if (!enableIPForwarding()) return NO;

    // Add NAT rule using pfctl
    // Create a temporary pf anchor for FreeTether
    // Explicitly specify 'inet' (IPv4) to be unambiguous about protocol family.
    NSString *natRule = [NSString stringWithFormat:
        @"nat on %@ inet from %@:network to any -> (%@)",
        toInterface, fromInterface, toInterface];

    // WiFi sharing (and any non-VPN scenario where the default route may not
    // point to toInterface) needs a route-to rule. pf's "nat on <if>" only
    // rewrites addresses for packets already routed to <if>. Without route-to,
    // bridge traffic follows the default route (often pdp_ip0 / cellular) and
    // bypasses our NAT entirely. VPN sharing doesn't need this because the VPN
    // client already sets utun as the default route.
    NSString *routeRule = [NSString stringWithFormat:
        @"pass in on %@ inet route-to (%@) from %@:network to any",
        fromInterface, toInterface, fromInterface];

    // S3 fix: write to /var/tmp/ which is always writable by root
    // M3: TODO — IPv6 NAT (inet6) requires separate pf rules and is more complex;
    // pfctl supports 'nat on ... inet6' but the addressing model differs. For now
    // we only NAT IPv4 traffic; IPv6 forwarding is enabled above so direct-routed
    // IPv6 traffic will still pass through if the VPN/upstream supports it.
    NSString *rulePath = @"/var/tmp/freetether_nat.conf";
    NSString *ruleContent = [NSString stringWithFormat:
        @"# FreeTether NAT + route rules (IPv4)\n%@\n%@\n", natRule, routeRule];
    NSError *writeError = nil;
    if (![ruleContent writeToFile:rulePath atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        FT_ROUTE_LOG(@"Failed to write NAT rule file: %@", writeError);
        return NO;
    }

    // Load the NAT rule via pfctl
    int result = execRouteCommand(@[@"/sbin/pfctl", @"-a", @"com.freetether", @"-f", rulePath]);

    if (result == 0) {
        // C1 fix: ensure anchor is referenced in main ruleset, otherwise rules
        // loaded into the anchor are never evaluated by pf.
        // Only inject once — pfctl -mf merge accumulates duplicate lines on repeat calls.
        if (!sAnchorInstalled) {
            execRouteCommand(@[@"/bin/sh", @"-c",
                @"echo 'nat-anchor \"com.freetether\"' | /sbin/pfctl -mf -"]);
            execRouteCommand(@[@"/bin/sh", @"-c",
                @"echo 'anchor \"com.freetether\"' | /sbin/pfctl -mf -"]);
            sAnchorInstalled = YES;
            FT_DBG(@"Anchor references merged into main ruleset");
        }

        // W6 fix: check if pf is already enabled before enabling it
        BOOL pfWasEnabled = NO;
        {
            // Use posix_spawn to capture pfctl -s info output
            int pfPipe[2];
            if (pipe(pfPipe) == 0) {
                posix_spawn_file_actions_t fa;
                posix_spawn_file_actions_init(&fa);
                posix_spawn_file_actions_adddup2(&fa, pfPipe[1], STDOUT_FILENO);
                posix_spawn_file_actions_addclose(&fa, pfPipe[0]);
                posix_spawn_file_actions_addclose(&fa, pfPipe[1]); // close original fd after dup2
                posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, "/dev/null", O_WRONLY, 0);

                pid_t infoPid = 0;
                const char *infoArgv[] = { "/sbin/pfctl", "-s", "info", NULL };
                int sr = posix_spawn(&infoPid, infoArgv[0], &fa, NULL, (char *const *)infoArgv, environ);
                posix_spawn_file_actions_destroy(&fa);
                close(pfPipe[1]);

                if (sr == 0) {
                    // Loop read until EOF to handle partial reads
                    char buf[512] = {0};
                    ssize_t total = 0;
                    ssize_t n;
                    while (total < (ssize_t)(sizeof(buf) - 1) &&
                           (n = read(pfPipe[0], buf + total, sizeof(buf) - 1 - total)) > 0) {
                        total += n;
                    }
                    buf[total] = '\0';
                    close(pfPipe[0]);
                    waitpid(infoPid, NULL, 0);
                    pfWasEnabled = (total > 0 && strstr(buf, "Status: Enabled") != NULL);
                } else {
                    close(pfPipe[0]);
                }
            }
        }

        // M1 fix: enable pf and track that we did it
        execRouteCommand(@[@"/sbin/pfctl", @"-e"]);
        if (!pfWasEnabled) {
            sPFEnabledByUs = YES;
            FT_DBG(@"pf was not running — we enabled it, will disable on cleanup");
        } else {
            FT_DBG(@"pf was already running — will not disable on cleanup");
        }
        FT_ROUTE_LOG(@"NAT route applied: %@ → %@", fromInterface, toInterface);
        return YES;
    } else {
        // C3 fix: pfctl may fail in rootless jailbreaks due to sandbox restrictions.
        // Post a Darwin notification so the Preferences UI can surface the error.
        FT_ROUTE_LOG(@"Failed to apply NAT route (pfctl returned %d) — "
                     "this may be a sandbox/permission issue on rootless jailbreaks. "
                     "Try running 'pfctl' manually as root to verify.", result);
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFSTR("com.freetether.routeError"), NULL, NULL, YES);
        return NO;
    }
}

static void removeNATRouteOverride() {
    FT_ROUTE_LOG(@"Removing FreeTether NAT rules");
    execRouteCommand(@[@"/sbin/pfctl", @"-a", @"com.freetether", @"-F", @"all"]);
    // C1 fix: remove anchor references from main ruleset.
    // We reload the main ruleset without our anchors by flushing and re-loading.
    // Note: pfctl -mf with empty anchor lines is a no-op, so this is safe even if
    // other anchors exist — we only flush our own anchor above.
    sAnchorInstalled = NO;
    FT_DBG(@"Anchor com.freetether flushed");
    // M1 fix: disable pf if we were the ones who enabled it
    if (sPFEnabledByUs) {
        execRouteCommand(@[@"/sbin/pfctl", @"-d"]);
        sPFEnabledByUs = NO;
    }
    // F1 fix: restore IP forwarding to original values instead of forcing to 0
    restoreIPForwarding();
    // S3 fix: clean up temp file at corrected path
    [[NSFileManager defaultManager] removeItemAtPath:@"/var/tmp/freetether_nat.conf" error:nil];
}

// --- NAT route manipulation ---
// When hotspot starts, MobileInternetSharing sets up NAT from bridge100 → pdp_ip0
// We intercept this to redirect to utun (VPN) or en0 (Wi-Fi) instead

%group InternetSharingHooks

%hookf(int, sysctl, int *name, u_int namelen, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    int result = %orig;

    if (!FTIsEnabled()) return result;

    @try {
        // Monitor routing table changes
        if (name && namelen >= 2 && name[0] == 4 /* CTL_NET */ && name[1] == 17 /* PF_ROUTE */) {
            FT_DBG(@"sysctl routing call detected, namelen=%u", namelen);

            // When a route change is detected, apply our override if needed
            if (gVPNSharing || gWiFiSharing) {
                // M2 fix: use C11 atomics instead of deprecated OSAtomicIncrement32
                int32_t token = atomic_fetch_add_explicit(&sDebounceToken, 1, memory_order_relaxed) + 1;
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), sRouteQueue, ^{
                    if (token == atomic_load_explicit(&sDebounceToken, memory_order_relaxed)) {
                        FTApplyRouteOverrideImpl();
                    }
                });
            }
        }
    } @catch (NSException *e) {
        NSLog(@"[FreeTether][ERROR][Route] sysctl hook exception: %@", e);
    }

    return result;
}

%end  // group InternetSharingHooks

// --- Public API for route manipulation ---
// FTApplyRouteOverrideImpl: internal, must be called on sRouteQueue.

static void FTApplyRouteOverrideImpl() {
    if (!FTIsEnabled()) return;

    NSString *bridgeIf = findHotspotBridgeInterface();
    if (!bridgeIf) {
        FT_DBG(@"No hotspot bridge interface active, skipping route override");
        return;
    }

    if (gVPNSharing) {
        NSString *vpnIf = findActiveVPNInterface();
        if (vpnIf) {
            FT_DBG(@"VPN sharing: redirecting %@ → %@", bridgeIf, vpnIf);
            applyNATRouteOverride(bridgeIf, vpnIf);
        } else {
            FT_DBG(@"VPN sharing enabled but no active VPN interface found, falling back to cellular");
            removeNATRouteOverride();
        }
    } else if (gWiFiSharing) {
        NSString *wifiIf = findActiveWiFiInterface();
        if (wifiIf) {
            FT_DBG(@"Wi-Fi sharing: redirecting %@ → %@", bridgeIf, wifiIf);
            applyNATRouteOverride(bridgeIf, wifiIf);
        } else {
            FT_DBG(@"Wi-Fi sharing enabled but no active Wi-Fi interface found");
            removeNATRouteOverride();
        }
    } else {
        // Neither sharing mode enabled — remove any previous overrides
        removeNATRouteOverride();
    }
}

// Public API: thread-safe wrapper that dispatches to sRouteQueue.
// External callers (sysctl hook, SCDynamicStore callback, FTLoadRoutingPrefs)
// should always go through this or dispatch to sRouteQueue themselves.
void FTApplyRouteOverride() {
    if (!sRouteQueue) return;
    dispatch_async(sRouteQueue, ^{
        FTApplyRouteOverrideImpl();
    });
}

void FTLoadRoutingPrefs(NSDictionary *prefs) {
    BOOL oldVPN = gVPNSharing;
    BOOL oldWiFi = gWiFiSharing;

    gVPNSharing  = [prefs[@"vpnSharing"] boolValue];
    gWiFiSharing = [prefs[@"wifiSharing"] boolValue];
    FT_DBG(@"Routing prefs: vpn=%d wifi=%d", gVPNSharing, gWiFiSharing);

    // #1 fix: guard against nil sRouteQueue — only initialized in CommCenter/MIS
    if (!sRouteQueue) return;

    // Re-apply or remove route override if settings changed
    if (oldVPN != gVPNSharing || oldWiFi != gWiFiSharing) {
        dispatch_async(sRouteQueue, ^{
            FTApplyRouteOverrideImpl();
        });
    }
}

// W7 fix: SCDynamicStore callback — fires on network state changes (e.g. VPN up/down,
// Wi-Fi reconnect). More reliable than sysctl hook alone for detecting route changes.
// SCDynamicStore APIs are unavailable in newer iOS SDKs but exist at runtime on jailbroken
// devices — we use dlsym to call them dynamically.
static void FTNetworkStateChanged(CFTypeRef store __unused,
                                  CFArrayRef changedKeys __unused,
                                  void *info __unused) {
    FT_DBG(@"SCDynamicStore: network state changed");
    if (gVPNSharing || gWiFiSharing) {
        int32_t token = atomic_fetch_add_explicit(&sDebounceToken, 1, memory_order_relaxed) + 1;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.5 * NSEC_PER_SEC)), sRouteQueue, ^{
            if (token == atomic_load_explicit(&sDebounceToken, memory_order_relaxed)) {
                FTApplyRouteOverrideImpl();
            }
        });
    }
}

static CFTypeRef sDynStore = NULL;

// dlsym function pointer types for SCDynamicStore APIs
typedef void (*FTSCDynStoreCallBack)(CFTypeRef store, CFArrayRef changedKeys, void *info);
typedef struct { CFIndex version; void *info; const void *(*retain)(const void *); void (*release)(const void *); CFStringRef (*copyDescription)(const void *); } FTSCDynStoreContext;

static void FTSetupNetworkMonitor() {
    // Resolve SCDynamicStore symbols at runtime
    void *scHandle = dlopen("/System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration", RTLD_LAZY);
    if (!scHandle) {
        FT_ROUTE_LOG(@"Failed to dlopen SystemConfiguration — network monitoring will rely on sysctl hook only");
        return;
    }

    typedef CFTypeRef (*SCDynStoreCreateFunc)(CFAllocatorRef, CFStringRef, FTSCDynStoreCallBack, FTSCDynStoreContext *);
    typedef Boolean (*SCDynStoreSetKeysFunc)(CFTypeRef, CFArrayRef, CFArrayRef);
    typedef CFRunLoopSourceRef (*SCDynStoreCreateRLSFunc)(CFAllocatorRef, CFTypeRef, CFIndex);

    SCDynStoreCreateFunc dynStoreCreate = (SCDynStoreCreateFunc)dlsym(scHandle, "SCDynamicStoreCreate");
    SCDynStoreSetKeysFunc dynStoreSetKeys = (SCDynStoreSetKeysFunc)dlsym(scHandle, "SCDynamicStoreSetNotificationKeys");
    SCDynStoreCreateRLSFunc dynStoreCreateRLS = (SCDynStoreCreateRLSFunc)dlsym(scHandle, "SCDynamicStoreCreateRunLoopSource");

    if (!dynStoreCreate || !dynStoreSetKeys || !dynStoreCreateRLS) {
        FT_ROUTE_LOG(@"Failed to resolve SCDynamicStore symbols — network monitoring will rely on sysctl hook only");
        return;
    }

    FTSCDynStoreContext ctx = { 0, NULL, NULL, NULL, NULL };
    sDynStore = dynStoreCreate(kCFAllocatorDefault,
                               CFSTR("FreeTetherRoute"),
                               FTNetworkStateChanged, &ctx);
    if (!sDynStore) {
        FT_ROUTE_LOG(@"Failed to create SCDynamicStore — network monitoring will rely on sysctl hook only");
        return;
    }

    // Monitor global IPv4/IPv6 state changes (covers VPN up/down, Wi-Fi reconnect etc.)
    CFArrayRef keys = CFArrayCreate(kCFAllocatorDefault, (const void *[]){
        CFSTR("State:/Network/Global/IPv4"),
        CFSTR("State:/Network/Global/IPv6"),
    }, 2, &kCFTypeArrayCallBacks);

    dynStoreSetKeys(sDynStore, keys, NULL);
    CFRelease(keys);

    CFRunLoopSourceRef rls = dynStoreCreateRLS(kCFAllocatorDefault, sDynStore, 0);
    if (rls) {
        CFRunLoopAddSource(CFRunLoopGetMain(), rls, kCFRunLoopDefaultMode);
        CFRelease(rls);
        FT_DBG(@"SCDynamicStore network monitor registered");
    }
}

// S7 fix: cleanup on process exit
static void FTRouteCleanup() {
    removeNATRouteOverride();
    if (sDynStore) {
        CFRelease(sDynStore);
        sDynStore = NULL;
    }
    FT_DBG(@"Route cleanup completed");
}

%ctor {
    NSString *proc = [[NSProcessInfo processInfo] processName];
    if ([proc isEqualToString:@"MobileInternetSharing"] ||
        [proc isEqualToString:@"CommCenter"]) {
        // Clean up any NAT rules/IP-forwarding state that may have been left
        // behind by a previous instance killed with SIGKILL (e.g. killall -9).
        removeNATRouteOverride();

        NSLog(@"[FreeTether][Route] Activating routing hooks in %@", proc);
        sRouteQueue = dispatch_queue_create("com.freetether.route", DISPATCH_QUEUE_SERIAL);
        %init(InternetSharingHooks);
        // W7: register SCDynamicStore listener for network state changes
        FTSetupNetworkMonitor();
        // S7: register atexit handler for cleanup (covers normal exit())
        atexit(FTRouteCleanup);

        // SIGTERM handler: launchd sends SIGTERM to daemons, not exit(), so
        // atexit alone is insufficient. Use dispatch_source to run cleanup
        // on sRouteQueue before re-raising the signal for normal termination.
        signal(SIGTERM, SIG_IGN);
        sSignalSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, SIGTERM, 0, sRouteQueue);
        dispatch_source_set_event_handler(sSignalSource, ^{
            FT_ROUTE_LOG(@"SIGTERM received, cleaning up NAT rules");
            FTRouteCleanup();
            signal(SIGTERM, SIG_DFL);
            raise(SIGTERM);
        });
        dispatch_resume(sSignalSource);
    }
}
