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

#import <ifaddrs.h>
#import <net/if.h>
#import <arpa/inet.h>
#import <dlfcn.h>
#import <sys/sysctl.h>
#import <spawn.h>
#import <sys/wait.h>

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
        "  diagnose            Dump network interfaces, pfctl, and CoreTelephony symbols\n"
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

// ---- diagnose ----

extern char **environ;

static void runCmd(const char *label, const char *path, const char *const argv[]) {
    printf("--- %s ---\n", label);
    pid_t pid = 0;
    int status = 0;
    if (posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ) == 0) {
        waitpid(pid, &status, 0);
    } else {
        printf("  (failed to spawn %s)\n", path);
    }
    printf("\n");
}

static void printDiagnose() {
    printStatus();

    // 1. Network interfaces
    printf("\n=== Network Interfaces ===\n");
    struct ifaddrs *ifs = NULL;
    if (getifaddrs(&ifs) == 0) {
        for (struct ifaddrs *ifp = ifs; ifp; ifp = ifp->ifa_next) {
            if (!ifp->ifa_name) continue;
            const char *name = ifp->ifa_name;
            unsigned int flags = ifp->ifa_flags;
            BOOL up = (flags & IFF_UP) != 0;
            BOOL ptp = (flags & IFF_POINTOPOINT) != 0;

            // Only show relevant interfaces
            BOOL relevant = NO;
            if (strncmp(name, "utun", 4) == 0 ||
                strncmp(name, "bridge", 6) == 0 ||
                strcmp(name, "en0") == 0 ||
                strncmp(name, "pdp_ip", 6) == 0 ||
                strncmp(name, "ipsec", 5) == 0) {
                relevant = YES;
            }
            if (!relevant) continue;

            char addrBuf[INET6_ADDRSTRLEN] = "(no addr)";
            const char *family = "";
            if (ifp->ifa_addr) {
                if (ifp->ifa_addr->sa_family == AF_INET) {
                    struct sockaddr_in *sin = (struct sockaddr_in *)ifp->ifa_addr;
                    inet_ntop(AF_INET, &sin->sin_addr, addrBuf, sizeof(addrBuf));
                    family = "IPv4";
                } else if (ifp->ifa_addr->sa_family == AF_INET6) {
                    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ifp->ifa_addr;
                    inet_ntop(AF_INET6, &sin6->sin6_addr, addrBuf, sizeof(addrBuf));
                    family = "IPv6";
                } else {
                    continue;  // skip link-layer entries for brevity
                }
            }

            printf("  %-12s %s  %-5s  %s  %s\n", name,
                   up ? "UP  " : "DOWN", family, addrBuf,
                   ptp ? "(point-to-point)" : "");
        }
        freeifaddrs(ifs);
    } else {
        printf("  (getifaddrs failed)\n");
    }

    // 2. IP forwarding
    printf("\n=== IP Forwarding ===\n");
    {
        int fwd4 = 0;
        size_t len4 = sizeof(fwd4);
        int mib[] = { CTL_NET, PF_INET, IPPROTO_IP, IPCTL_FORWARDING };
        if (sysctl(mib, 4, &fwd4, &len4, NULL, 0) == 0) {
            printf("  net.inet.ip.forwarding = %d\n", fwd4);
        }
        int fwd6 = 0;
        size_t len6 = sizeof(fwd6);
        if (sysctlbyname("net.inet6.ip6.forwarding", &fwd6, &len6, NULL, 0) == 0) {
            printf("  net.inet6.ip6.forwarding = %d\n", fwd6);
        }
    }

    // 3. pfctl anchor status
    printf("\n=== pfctl anchor (com.freetether) ===\n");
    {
        const char *pf1[] = { "/sbin/pfctl", "-s", "info", NULL };
        runCmd("pfctl -s info", pf1[0], pf1);
        const char *pf2[] = { "/sbin/pfctl", "-a", "com.freetether", "-s", "nat", NULL };
        runCmd("pfctl -a com.freetether -s nat", pf2[0], pf2);
        const char *pf3[] = { "/sbin/pfctl", "-a", "com.freetether", "-s", "rules", NULL };
        runCmd("pfctl -a com.freetether -s rules", pf3[0], pf3);
    }

    // 4. CoreTelephony symbols
    printf("=== CoreTelephony Symbols ===\n");
    {
        void *ct = dlopen("/System/Library/Frameworks/CoreTelephony.framework/CoreTelephony", RTLD_LAZY);
        if (!ct) {
            printf("  (failed to dlopen CoreTelephony)\n");
        } else {
            const char *syms[] = {
                "CTCarrierSpaceGetSetting",
                "CTCarrierSpaceSetSetting",
                "CTServerConnectionSetTetheredModeEnabled",
                "CTServerConnectionGetTetheredModeEnabled",
                "CTRegistrationGetCarrierBundleInfo",
                "CTRegistrationGetDataStatus",
                "CTServerConnectionSetPersistentTetheringAPN",
                NULL,
            };
            for (int i = 0; syms[i]; i++) {
                void *p = dlsym(ct, syms[i]);
                printf("  %-50s %s\n", syms[i], p ? "FOUND" : "NOT FOUND");
            }
            dlclose(ct);
        }
    }

    // 5. Process check
    printf("\n=== Process Check ===\n");
    {
        const char *ps[] = { "/bin/ps", "-eo", "pid,comm", NULL };
        runCmd("Running daemons", ps[0], ps);
    }

    printf("=== Recent [FreeTether] logs (last 30 lines) ===\n");
    printf("  Run: grep FreeTether /var/log/syslog | tail -30\n");
    printf("  Or:  oslog --predicate 'eventMessage CONTAINS \"FreeTether\"' --last 5m\n");
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
        } else if ([cmd isEqualToString:@"diagnose"]) {
            printDiagnose();
        } else {
            printUsage();
            return 1;
        }

        return 0;
    }
}
