// Probe/FTProbe.x
// Dumps ObjC classes + methods and C symbols related to tethering from CommCenter

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <mach-o/dyld.h>

// Keywords to filter relevant symbols
static NSArray *gKeywords;

static BOOL matchesKeywords(NSString *name) {
    NSString *lower = [name lowercaseString];
    for (NSString *kw in gKeywords) {
        if ([lower containsString:kw]) return YES;
    }
    return NO;
}

static NSString *outputDir() {
    // C6 fix: use /var/tmp/ which is world-writable. CommCenter runs as _wireless
    // user and cannot write to /var/mobile/Documents/.
    NSString *dir = @"/var/tmp/FTProbe";
    NSError *error = nil;
    BOOL ok = [[NSFileManager defaultManager] createDirectoryAtPath:dir
                                        withIntermediateDirectories:YES
                                                       attributes:nil
                                                            error:&error];
    if (!ok) {
        NSLog(@"[FTProbe] Failed to create output directory %@: %@", dir, error);
        return nil;
    }
    return dir;
}

static void dumpObjCClasses() {
    NSMutableString *output = [NSMutableString string];
    unsigned int classCount = 0;
    Class *classes = objc_copyClassList(&classCount);

    [output appendFormat:@"Total ObjC classes loaded: %u\n", classCount];
    [output appendString:@"=== Tethering-related classes ===\n\n"];

    int matchCount = 0;
    for (unsigned int i = 0; i < classCount; i++) {
        NSString *className = NSStringFromClass(classes[i]);
        if (!matchesKeywords(className)) continue;

        matchCount++;
        [output appendFormat:@"--- %@ ---\n", className];

        // Dump instance methods
        unsigned int methodCount = 0;
        Method *methods = class_copyMethodList(classes[i], &methodCount);
        for (unsigned int j = 0; j < methodCount; j++) {
            SEL sel = method_getName(methods[j]);
            const char *typeEnc = method_getTypeEncoding(methods[j]);
            [output appendFormat:@"  - %@ (%s)\n",
                NSStringFromSelector(sel), typeEnc ?: "?"];
        }
        free(methods);

        // Dump class methods
        Class metaClass = object_getClass(classes[i]);
        methods = class_copyMethodList(metaClass, &methodCount);
        for (unsigned int j = 0; j < methodCount; j++) {
            SEL sel = method_getName(methods[j]);
            [output appendFormat:@"  + %@\n", NSStringFromSelector(sel)];
        }
        free(methods);

        [output appendString:@"\n"];
    }
    free(classes);

    [output appendFormat:@"\nMatched %d classes out of %u total.\n", matchCount, classCount];

    NSString *dir = outputDir();
    if (!dir) { NSLog(@"[FTProbe] Skipping ObjC class dump — output dir unavailable"); return; }
    NSString *path = [dir stringByAppendingPathComponent:@"classes.txt"];
    NSError *writeError = nil;
    if (![output writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        NSLog(@"[FTProbe] Failed to write classes dump to %@: %@", path, writeError);
        return;
    }
    NSLog(@"[FTProbe] ObjC classes dumped to %@ (%d matches)", path, matchCount);
}

static void dumpLoadedFrameworks() {
    NSMutableString *output = [NSMutableString string];
    uint32_t count = _dyld_image_count();

    [output appendFormat:@"Total loaded images: %u\n\n", count];

    for (uint32_t i = 0; i < count; i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        NSString *imageName = [NSString stringWithUTF8String:name];

        // Log all images, but highlight interesting ones
        BOOL interesting = matchesKeywords([imageName lastPathComponent]);
        [output appendFormat:@"%@ %@\n", interesting ? @">>>" : @"   ", imageName];
    }

    NSString *dir = outputDir();
    if (!dir) { NSLog(@"[FTProbe] Skipping frameworks dump — output dir unavailable"); return; }
    NSString *path = [dir stringByAppendingPathComponent:@"frameworks.txt"];
    NSError *writeError = nil;
    if (![output writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        NSLog(@"[FTProbe] Failed to write frameworks dump to %@: %@", path, writeError);
        return;
    }
    NSLog(@"[FTProbe] Loaded frameworks dumped to %@", path);
}

static void dumpCSymbols() {
    NSMutableString *output = [NSMutableString string];
    uint32_t imageCount = _dyld_image_count();

    [output appendString:@"=== C symbols matching tethering keywords ===\n\n"];

    int totalMatches = 0;
    for (uint32_t i = 0; i < imageCount; i++) {
        const char *imageName = _dyld_get_image_name(i);
        if (!imageName) continue;
        NSString *name = [NSString stringWithUTF8String:imageName];

        // Only scan CommCenter binary and key frameworks
        BOOL shouldScan = NO;
        NSArray *targets = @[@"CommCenter", @"CoreTelephony", @"MobileWiFi",
                             @"InternetSharing", @"NetworkRelay"];
        for (NSString *t in targets) {
            if ([name containsString:t]) { shouldScan = YES; break; }
        }
        if (!shouldScan) continue;

        [output appendFormat:@"\n--- %@ ---\n", [name lastPathComponent]];

        void *handle = dlopen(imageName, RTLD_NOLOAD);
        if (!handle) {
            [output appendFormat:@"  (could not dlopen)\n"];
            continue;
        }

        // Check for known symbol patterns from research
        // dlsym does NOT require the leading underscore — Mach-O stores
        // symbols with '_' prefix internally, but dlsym handles that.
        NSArray *knownSymbols = @[
            // Carrier bundle related
            @"CTCarrierSpaceGetSetting",
            @"CTCarrierSpaceSetSetting",
            @"CTRegistrationGetCarrierBundleInfo",
            @"CTRegistrationGetCurrentMaxAllowedDataRate",
            // Tethering related
            @"CTServerConnectionSetTetheredModeEnabled",
            @"CTServerConnectionGetTetheredModeEnabled",
            @"CTServerConnectionSetPersistentTetheringAPN",
            @"CTServerConnectionGetPersistentTetheringAPN",
            // Entitlement related
            @"CTServerConnectionSetEntitlementCheck",
            @"CTRegistrationGetDataStatus",
            @"CTRegistrationGetDataCounterInfo",
            // Internet sharing
            @"WiFiManagerClientSetProperty",
            @"WiFiManagerClientCreate",
        ];

        for (NSString *sym in knownSymbols) {
            void *ptr = dlsym(handle, [sym UTF8String]);
            if (ptr) {
                totalMatches++;
                [output appendFormat:@"  FOUND: %@ @ %p\n", sym, ptr];
            }
        }

        // W: don't dlclose handles obtained via RTLD_NOLOAD — it decrements the
        // refcount on an already-loaded library and could theoretically unload it.
        // dlopen(RTLD_NOLOAD) does NOT increment the refcount in a way that pairs
        // with dlclose, so closing is both unnecessary and risky.
    }

    [output appendFormat:@"\nTotal symbol matches: %d\n", totalMatches];

    NSString *dir = outputDir();
    if (!dir) { NSLog(@"[FTProbe] Skipping C symbols dump — output dir unavailable"); return; }
    NSString *path = [dir stringByAppendingPathComponent:@"symbols.txt"];
    NSError *writeError = nil;
    if (![output writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&writeError]) {
        NSLog(@"[FTProbe] Failed to write symbols dump to %@: %@", path, writeError);
        return;
    }
    NSLog(@"[FTProbe] C symbols dumped to %@ (%d matches)", path, totalMatches);
}

%ctor {
    NSLog(@"[FTProbe] Starting probe in process: %@",
          [[NSProcessInfo processInfo] processName]);

    gKeywords = @[
        @"tether", @"hotspot", @"apn", @"carrier",
        @"entitlement", @"internetsharing",
        @"personalhotspot", @"provision",
        @"carrierbundle", @"dataattach"
    ];

    // Delay slightly to let CommCenter finish loading
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3 * NSEC_PER_SEC),
                   dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0), ^{
        NSLog(@"[FTProbe] Running probes...");
        dumpLoadedFrameworks();
        dumpObjCClasses();
        dumpCSymbols();
        NSLog(@"[FTProbe] All probes complete. Results in /var/tmp/FTProbe/");
    });
}
