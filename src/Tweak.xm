/*
 * CarBridgeReborn v3.5.0
 * iOS 17.0, arm64e, NathanLR rootless
 *
 * ROOT CAUSE of all crashes (confirmed from 15+ crash logs):
 *
 *   Exception: EXC_BAD_ACCESS SIGBUS at 0x00000000dac11950 (ALWAYS same address)
 *   ESR: 0x72000002 = Address size fault = PAC authentication failure
 *   Frame: NSString stringWithFormat: → objc_msgSend + 24 → PAC fault
 *
 * Our cb() helper took NSString* parameters:
 *   cb(lib, @"allInstalledApplications")
 *   ↑ @"..." NSString literal passed as NSString* parameter on arm64e
 *   ↑ ARC calls objc_storeStrong / objc_retain on the NSString*
 *   ↑ arm64e PAC authentication fails on pointer
 *   ↑ SIGBUS signal 10
 *
 * FIX: Change cb() and cb1() to use const char* + sel_registerName()
 * instead of NSString* + NSSelectorFromString().
 * const char* = pure C, zero ARC, zero PAC issues, always safe.
 *
 * Also: remove ALL NSString usage from injection hot paths.
 * Use snprintf + CBFileLog (pure C write()) everywhere.
 */

#import <UIKit/UIKit.h>
#import <strings.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <string.h>
#import <unistd.h>
#import <fcntl.h>
#import <stdio.h>

extern char *__progname;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-performSelector-leaks"
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#pragma clang diagnostic ignored "-Wunused-variable"
#pragma clang diagnostic ignored "-Wstrict-prototypes"

// ─── File logging — pure C only, zero ObjC ────────────────────────────────────
static int gLogFD = -1;
static void CBLog(const char *msg) {
    if (gLogFD < 0)
        gLogFD = open("/var/mobile/CBR_live.txt", O_WRONLY|O_CREAT|O_APPEND, 0666);
    if (gLogFD >= 0) { write(gLogFD, msg, strlen(msg)); write(gLogFD, "\n", 1); }
    write(2, msg, strlen(msg)); write(2, "\n", 1);
}
static void CBLogFmt(const char *fmt, ...) {
    char buf[256];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    CBLog(buf);
}

// ---- Stage 2 (CarPlay->SpringBoard) diagnostics: separate log + Darwin post ----
static int gCPFD = -1;
static void CBCarLog(const char *msg) {
    if (gCPFD < 0)
        gCPFD = open("/var/mobile/CBR_carplay_live.txt",
                     O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (gCPFD >= 0) { write(gCPFD, msg, strlen(msg)); write(gCPFD, "\n", 1); }
    write(2, msg, strlen(msg)); write(2, "\n", 1);
}
static void CBCarLogFmt(const char *fmt, ...) {
    char buf[512];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    CBCarLog(buf);
}
static void CBPostLaunch(const char *bid_cstr) {
    if (!bid_cstr) return;
    { int pfd = open("/var/mobile/CBR_pending_launch.txt",
                     O_WRONLY|O_CREAT|O_TRUNC, 0644);
      if (pfd >= 0) { write(pfd, bid_cstr, strlen(bid_cstr)); close(pfd); } }
    @try {
        CFStringRef bid = CFStringCreateWithCString(kCFAllocatorDefault,
                              bid_cstr, kCFStringEncodingUTF8);
        CFStringRef keys[1]   = { CFSTR("bundleID") };
        CFStringRef values[1] = { bid };
        CFDictionaryRef info = CFDictionaryCreate(kCFAllocatorDefault,
                                   (const void **)keys, (const void **)values, 1,
                                   &kCFTypeDictionaryKeyCallBacks,
                                   &kCFTypeDictionaryValueCallBacks);
        CFNotificationCenterPostNotification(
            CFNotificationCenterGetDarwinNotifyCenter(),
            CFSTR("com.carbridgereborn.launch"),
            NULL, info, TRUE);
        CBCarLogFmt("[CBR-CP] posted launch notif -> %s", bid_cstr);
        if (info) CFRelease(info);
        if (bid)  CFRelease(bid);
    } @catch(...) {
        CBCarLog("[CBR-CP] post EXCEPTION");
    }
}


// ─── Saved library — void* to avoid ANY ARC at store time ────────────────────
static void *gLibraryPtr = NULL;

// Bundle IDs of apps that shipped their OWN CarPlay declaration (native CarPlay).
// Snapshotted BEFORE injection so we leave real CarPlay apps (Spotify, Maps,
// Waze, onX...) completely alone.
static NSMutableSet *gNativeCarPlaySet = nil;

// ─── Helpers — const char* only, zero NSString, zero ARC, zero PAC issues ────
// KEY FIX: was NSString* + NSSelectorFromString() → PAC fault on arm64e
//          now const char* + sel_registerName() → pure C, always safe
static inline id cb(id o, const char *sel_name) {
    if (!o || !sel_name) return nil;
    SEL sel = sel_registerName(sel_name);
    if (!sel || ![o respondsToSelector:sel]) return nil;
    return ((id(*)(id,SEL))objc_msgSend)(o, sel);
}
static inline id cb1(id o, const char *sel_name, id a) {
    if (!o || !sel_name) return nil;
    SEL sel = sel_registerName(sel_name);
    if (!sel || ![o respondsToSelector:sel]) return nil;
    return ((id(*)(id,SEL,id))objc_msgSend)(o, sel, a);
}
static inline id cb1b(id o, const char *sel_name, BOOL a) {
    if (!o || !sel_name) return nil;
    SEL sel = sel_registerName(sel_name);
    if (!sel || ![o respondsToSelector:sel]) return nil;
    return ((id(*)(id,SEL,BOOL))objc_msgSend)(o, sel, a);
}

static inline id getIvar(id obj, const char *name) {
    if (!obj || !name) return nil;
    Class cls = object_getClass(obj);
    while (cls) {
        Ivar iv = class_getInstanceVariable(cls, name);
        if (iv) return object_getIvar(obj, iv);
        cls = class_getSuperclass(cls);
    }
    return nil;
}
static inline BOOL setIvar(id obj, const char *name, id val) {
    if (!obj || !name) return NO;
    Class cls = object_getClass(obj);
    while (cls) {
        Ivar iv = class_getInstanceVariable(cls, name);
        if (iv) { object_setIvar(obj, iv, val); return YES; }
        cls = class_getSuperclass(cls);
    }
    return NO;
}

static void CBOpenApp(const char *bundleID_cstr) {
    if (!bundleID_cstr) return;
    Class wsClass = objc_getClass("LSApplicationWorkspace");
    if (!wsClass) return;
    id ws = ((id(*)(id,SEL))objc_msgSend)(wsClass, sel_registerName("defaultWorkspace"));
    if (!ws) return;
    NSString *bid = [NSString stringWithUTF8String:bundleID_cstr];
    ((void(*)(id,SEL,id))objc_msgSend)(ws, sel_registerName("openApplicationWithBundleID:"), bid);
}

// ─── Declaration injector — no NSString parameters anywhere ──────────────────

// ─── Per-app enable check — reads the Settings selections ─────────────────────
// Settings UI stores per-bundle-id BOOLs in NSUserDefaults suite com.carbridgereborn.
static BOOL CBIsEnabled(const char *bid_cstr) {
    if (!bid_cstr) return NO;
    // Rootless split-brain fix: the Settings panel (running in Preferences) writes
    // com.carbridgereborn prefs to the rootless path, but CFPreferencesCopyAppValue
    // inside CarPlayApp resolves the same domain to the NON-jailbreak path (empty).
    // So read the real plist file directly, trying rootless first, then non-jb.
    NSString *bid = [NSString stringWithUTF8String:bid_cstr];
    if (!bid) return NO;

    static NSString *kRootless = @"/var/jb/var/mobile/Library/Preferences/com.carbridgereborn.plist";
    static NSString *kLegacy   = @"/var/mobile/Library/Preferences/com.carbridgereborn.plist";

    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kRootless];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:kLegacy];
    if (!d) return NO;

    id val = d[bid];
    if ([val isKindOfClass:[NSNumber class]]) return [val boolValue];
    return NO;
}

// CarPlay app-policy "allowed" enum value. iOS typically uses 1 == allowed.
// Adjustable at runtime via prefs key "PolicyAllowValue" once we confirm from logs.
static long CBAllowedPolicyValue(void) {
    NSUserDefaults *defs = [[NSUserDefaults alloc] initWithSuiteName:@"com.carbridgereborn"];
    id v = [defs objectForKey:@"PolicyAllowValue"];
    return v ? [v longValue] : 1;
}

static int gDumpFD = -1;
static void CBLibDump(const char *m) {
    if (gDumpFD < 0)
        gDumpFD = open("/var/mobile/CBR_libdump.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (gDumpFD >= 0) { write(gDumpFD, m, strlen(m)); write(gDumpFD, "\n", 1); }
}
static void CBLibDumpFmt(const char *fmt, ...) {
    char buf[400]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    CBLibDump(buf);
}

static void cbrDumpLibrary(id lib) {
    static BOOL done = NO;
    if (done) return;
    done = YES;

    CBLibDump("======== CBR LIBRARY DUMP (iOS17) ========");
    if (!lib) { CBLibDump("lib is NIL"); return; }

    Class libClass = object_getClass(lib);
    CBLibDumpFmt("library class: %s", class_getName(libClass));
    Class c = libClass;
    while (c && strcmp(class_getName(c), "NSObject") != 0) {
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(c, &n);
        CBLibDumpFmt("-- ivars of %s (%u) --", class_getName(c), n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivars[i]);
            const char *tp = ivar_getTypeEncoding(ivars[i]);
            CBLibDumpFmt("   %s : %s", nm ? nm : "?", tp ? tp : "?");
        }
        if (ivars) free(ivars);
        c = class_getSuperclass(c);
    }

    unsigned int lm = 0;
    Method *lmeth = class_copyMethodList(libClass, &lm);
    CBLibDump("-- library methods (add/register/insert/application/install) --");
    for (unsigned int i = 0; i < lm; i++) {
        const char *sn = sel_getName(method_getName(lmeth[i]));
        if (strcasestr(sn,"add")||strcasestr(sn,"register")||strcasestr(sn,"insert")||
            strcasestr(sn,"application")||strcasestr(sn,"install"))
            CBLibDumpFmt("   -%s", sn);
    }
    if (lmeth) free(lmeth);

    NSArray *apps = cb(lib, "allInstalledApplications");
    CBLibDumpFmt("allInstalledApplications count: %lu", (unsigned long)[apps count]);
    if (apps.count > 0) {
        id first = apps[0];
        Class appClass = object_getClass(first);
        CBLibDumpFmt("app-info class: %s", class_getName(appClass));
        unsigned int mn = 0;
        Method *am = class_copyMethodList(appClass, &mn);
        CBLibDump("-- app-info methods (carplay/declaration/bundle/tag) --");
        for (unsigned int i = 0; i < mn; i++) {
            const char *sn = sel_getName(method_getName(am[i]));
            if (strcasestr(sn,"carplay")||strcasestr(sn,"declaration")||
                strcasestr(sn,"bundle")||strcasestr(sn,"tag"))
                CBLibDumpFmt("   -%s", sn);
        }
        if (am) free(am);
    }

    CBLibDumpFmt("FBSApplicationLibrary avail: %s", %c(FBSApplicationLibrary) ? "YES" : "no");
    CBLibDumpFmt("LSApplicationWorkspace avail: %s", %c(LSApplicationWorkspace) ? "YES" : "no");
    CBLibDumpFmt("CRCarPlayAppDeclaration avail: %s", objc_getClass("CRCarPlayAppDeclaration") ? "YES" : "no");
    CBLibDump("======== END DUMP ========");
}

static NSArray *cbrEnabledBundleIDs(void) {
    static NSString *kRootless = @"/var/jb/var/mobile/Library/Preferences/com.carbridgereborn.plist";
    static NSString *kLegacy   = @"/var/mobile/Library/Preferences/com.carbridgereborn.plist";
    NSDictionary *d = [NSDictionary dictionaryWithContentsOfFile:kRootless];
    if (!d) d = [NSDictionary dictionaryWithContentsOfFile:kLegacy];
    NSMutableArray *out = [NSMutableArray array];
    for (NSString *k in d) {
        id v = d[k];
        if ([v isKindOfClass:[NSNumber class]] && [v boolValue]) [out addObject:k];
    }
    return out;
}

static void cbrInjectEnabledApps(id lib) {
    if (!lib) return;
    CBLibDump("==== INJECT PASS ====");

    NSArray *apps = cb(lib, "allInstalledApplications");
    NSMutableSet *have = [NSMutableSet set];
    for (id ai in apps) {
        id bidObj = cb(ai, "bundleIdentifier");
        if (bidObj) [have addObject:bidObj];
    }
    NSUInteger before = [apps count];
    CBLibDumpFmt("library before: %lu apps", (unsigned long)before);

    NSArray *enabled = cbrEnabledBundleIDs();
    CBLibDumpFmt("enabled apps: %lu", (unsigned long)[enabled count]);

    SEL addProxySel = sel_registerName("addApplicationProxy:withOverrideURL:");
    SEL addRecSel   = sel_registerName("addApplicationRecord:");
    SEL proxyForSel = sel_registerName("applicationProxyForIdentifier:");

    for (NSString *bid in enabled) {
        if ([have containsObject:bid]) {
            CBLibDumpFmt("  skip (already present): %s", [bid UTF8String]);
            continue;
        }
        @try {
            id proxy = ((id(*)(Class,SEL,id))objc_msgSend)(
                objc_getClass("LSApplicationProxy"), proxyForSel, bid);
            if (!proxy) { CBLibDumpFmt("  NO proxy: %s", [bid UTF8String]); continue; }

            if ([lib respondsToSelector:addProxySel]) {
                ((void(*)(id,SEL,id,id))objc_msgSend)(lib, addProxySel, proxy, nil);
                CBLibDumpFmt("  addApplicationProxy -> %s", [bid UTF8String]);
            } else if ([lib respondsToSelector:addRecSel]) {
                CBLibDumpFmt("  (proxy sel missing; addApplicationRecord available) %s", [bid UTF8String]);
            } else {
                CBLibDumpFmt("  NO insertion method for %s", [bid UTF8String]);
            }
        } @catch (NSException *e) {
            CBLibDumpFmt("  EXC %s: %s", [bid UTF8String], [[e description] UTF8String] ?: "?");
        }
    }

    NSUInteger after = [cb(lib, "allInstalledApplications") count];
    CBLibDumpFmt("library after: %lu apps (was %lu, delta %ld)",
                 (unsigned long)after, (unsigned long)before, (long)after - (long)before);
    CBLibDump("==== END INJECT ====");
}

static void cbrDumpPolicyInfo(id lib) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    CBLibDump("==== POLICY DIAGNOSTIC ====");

    Class envClass = objc_getClass("DBEnvironmentConfiguration");
    if (envClass) {
        Method m = class_getInstanceMethod(envClass, sel_registerName("policyForApplicationInfo:"));
        if (m) {
            char ret[128] = {0};
            method_getReturnType(m, ret, sizeof(ret));
            CBLibDumpFmt("policyForApplicationInfo: RETURNS '%s'", ret);
        } else {
            CBLibDump("policyForApplicationInfo: NOT on DBEnvironmentConfiguration");
        }
        Class c = envClass;
        while (c && strcmp(class_getName(c), "NSObject") != 0) {
            CBLibDumpFmt("  env class chain: %s", class_getName(c));
            c = class_getSuperclass(c);
        }
    } else {
        CBLibDump("DBEnvironmentConfiguration class NOT FOUND");
    }

    NSArray *apps = cb(lib, "allInstalledApplications");
    if (apps.count > 0) {
        id first = apps[0];
        id bidObj = cb(first, "bundleIdentifier");
        CBLibDumpFmt("-- FULL ivars of a NORMAL app-info (%s) --",
                     bidObj ? [bidObj UTF8String] : "?");
        Class ac = object_getClass(first);
        while (ac && strcmp(class_getName(ac), "NSObject") != 0) {
            unsigned int n = 0;
            Ivar *iv = class_copyIvarList(ac, &n);
            CBLibDumpFmt("  [%s] %u ivars:", class_getName(ac), n);
            for (unsigned int i = 0; i < n; i++) {
                const char *nm = ivar_getName(iv[i]);
                const char *tp = ivar_getTypeEncoding(iv[i]);
                CBLibDumpFmt("     %s : %s", nm ? nm : "?", tp ? tp : "?");
            }
            if (iv) free(iv);
            ac = class_getSuperclass(ac);
        }
        id decl = cb(first, "carPlayDeclaration");
        CBLibDumpFmt("normal carPlayDeclaration: %s ptr=%p",
                     decl ? class_getName(object_getClass(decl)) : "nil", (__bridge void *)decl);
    }
    CBLibDump("==== END POLICY DIAGNOSTIC ====");
}

static BOOL cbrHasValidDeclaration(id appInfo) {
    if (!appInfo) return NO;
    Ivar iv = class_getInstanceVariable(objc_getClass("DBApplicationInfo"), "_carPlayDeclaration");
    if (!iv) return NO;
    id decl = object_getIvar(appInfo, iv);
    if (!decl) return NO;
    uintptr_t p = (uintptr_t)decl;
    if (p < 0x1000) return NO;
    if (p & 0x7) return NO;
    @try {
        return [decl isKindOfClass:objc_getClass("CRCarPlayAppDeclaration")];
    } @catch (NSException *e) { return NO; }
}

static void cbrDeclDump(const char *m) {
    static int fd = -1;
    if (fd < 0) fd = open("/var/mobile/CBR_decldump.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd >= 0) { write(fd, m, strlen(m)); write(fd, "\n", 1); }
}
static void cbrDeclDumpFmt(const char *fmt, ...) {
    char buf[512]; va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    cbrDeclDump(buf);
}
static void cbrDumpOneClass(const char *clsname) {
    Class dc = objc_getClass(clsname);
    if (!dc) { cbrDeclDumpFmt("%s NOT FOUND", clsname); return; }
    Class c = dc;
    while (c && strcmp(class_getName(c), "NSObject") != 0) {
        unsigned int n = 0;
        Ivar *iv = class_copyIvarList(c, &n);
        cbrDeclDumpFmt("-- [%s] %u ivars --", class_getName(c), n);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(iv[i]);
            const char *tp = ivar_getTypeEncoding(iv[i]);
            cbrDeclDumpFmt("   %s : %s", nm ? nm : "?", tp ? tp : "?");
        }
        if (iv) free(iv);
        c = class_getSuperclass(c);
    }
    unsigned int mn = 0;
    Method *mm = class_copyMethodList(dc, &mn);
    cbrDeclDumpFmt("-- [%s] methods (%u) --", clsname, mn);
    for (unsigned int i = 0; i < mn; i++)
        cbrDeclDumpFmt("   -%s", sel_getName(method_getName(mm[i])));
    if (mm) free(mm);
}
static void cbrDumpDeclClass(void) {
    static BOOL done = NO;
    if (done) return;
    done = YES;
    cbrDeclDump("==== CLASS DUMP ====");
    cbrDumpOneClass("CRCarPlayAppDeclaration");
    cbrDumpOneClass("CRCarPlayAppPolicy");
    cbrDeclDump("==== END CLASS DUMP ====");
}
// True if this app shipped its OWN CarPlay declaration (native CarPlay app).
// Apps WE tagged are excluded, so our injected apps are never mistaken for
// native even if the library gets re-snapshotted after injection.
static BOOL cbrAppHasNativeDecl(id appInfo) {
    if (!appInfo) return NO;
    @try {
        NSArray *tags = cb(appInfo, "tags");
        if (!tags) tags = getIvar(appInfo, "_tags");
        for (id tag in tags) {
            const char *t = ((const char*(*)(id,SEL))objc_msgSend)(tag,
                sel_registerName("UTF8String"));
            if (t && strcmp(t, "CarPlayEnable") == 0) return NO;  // ours, not native
        }
    } @catch (NSException *e) {}
    id decl = getIvar(appInfo, "_carPlayDeclaration");
    if (!decl) decl = cb(appInfo, "carPlayDeclaration");
    if (!decl) return NO;
    uintptr_t pp = (uintptr_t)decl;
    if (pp < 0x1000 || (pp & 0x7)) return NO;
    @try {
        return [decl isKindOfClass:objc_getClass("CRCarPlayAppDeclaration")];
    } @catch (NSException *e) { return NO; }
}

// Capture native-CarPlay bundle IDs from the library's CURRENT contents.
// Called at the top of addCarplayDeclarations, BEFORE we inject, so it only
// sees apps that already had CarPlay support. Cleared and rebuilt each pass.
static void cbrSnapshotNativeSet(id lib) {
    if (!gNativeCarPlaySet) gNativeCarPlaySet = [[NSMutableSet alloc] init];
    [gNativeCarPlaySet removeAllObjects];
    NSArray *apps = cb(lib, "allInstalledApplications");
    for (id ai in apps) {
        if (cbrAppHasNativeDecl(ai)) {
            id bidObj = cb(ai, "bundleIdentifier");
            if (bidObj) [gNativeCarPlaySet addObject:bidObj];
        }
    }
    CBLogFmt("[CBR] native CarPlay snapshot: %lu apps",
             (unsigned long)[gNativeCarPlaySet count]);
}

// Bundle-ID membership test against the native snapshot.
static BOOL cbrBidIsNative(const char *bid_cstr) {
    if (!bid_cstr || !gNativeCarPlaySet) return NO;
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];
        return bid ? [gNativeCarPlaySet containsObject:bid] : NO;
    } @catch (NSException *e) { return NO; }
}

// ---- v3.13.5: static, timing-independent native-CarPlay detection ----
// v3.13.4's snapshot missed Spotify: the OS builds _carPlayDeclaration
// LAZILY, only once policy is actually queried for that app -- so at
// cbrSnapshotNativeSet() time (during _newApplicationLibrary) Spotify had
// no declaration yet and never made it into gNativeCarPlaySet. Fix: read
// the app's OWN Info.plist straight from disk. Any app that supports
// CarPlay MUST declare a scene under UIApplicationSceneManifest -- a
// static file, so there is zero timing dependency. A small hardcoded set
// is kept as a backstop for apps (Spotify chief among them) that have
// burned us; it needs no filesystem access at all, so it always works.
static NSSet *gCBRManualNativeSet = nil;

static BOOL cbrBundleDeclaresCarPlayInInfoPlist(NSString *bundlePath) {
    if (!bundlePath.length) return NO;
    @try {
        NSString *infoPath = [bundlePath stringByAppendingPathComponent:@"Info.plist"];
        NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:infoPath];
        if (![info isKindOfClass:[NSDictionary class]]) return NO;
        id manifest = info[@"UIApplicationSceneManifest"];
        id configs = [manifest isKindOfClass:[NSDictionary class]] ? manifest[@"UISceneConfigurations"] : nil;
        if (![configs isKindOfClass:[NSDictionary class]]) return NO;
        for (NSString *key in configs) {
            if ([key isKindOfClass:[NSString class]] &&
                ([key rangeOfString:@"CarPlay" options:NSCaseInsensitiveSearch].location != NSNotFound ||
                 [key hasPrefix:@"CPTemplateApplication"])) {
                return YES;
            }
        }
        return NO;
    } @catch (NSException *e) { return NO; }
}

static BOOL cbrBundleIsNativeCarPlay(NSString *bid, NSString *bundlePath) {
    if (bid.length) {
        if (!gCBRManualNativeSet) {
            gCBRManualNativeSet = [NSSet setWithObjects:
                @"com.spotify.client", @"com.apple.Music", @"com.apple.podcasts",
                @"com.apple.Maps", @"com.audible.iphone", @"com.waze.iphone",
                @"com.google.Maps", @"tunein.player", @"com.amazon.musicplayer",
                @"com.iheart.iHeartRadioIntl", @"com.aspiro.tidal",
                @"com.pandora.radio", nil];
        }
        if ([gCBRManualNativeSet containsObject:bid]) return YES;
    }
    if (bundlePath.length) {
        return cbrBundleDeclaresCarPlayInInfoPlist(bundlePath);
    }
    return NO;
}

static BOOL cbrAppHasNativeCarPlay(id appInfo) {
    if (!appInfo) return NO;
    @try {
        id bidObj = cb(appInfo, "bundleIdentifier");
        id bundleURL = cb(appInfo, "bundleURL");
        id pathObj = bundleURL ? cb(bundleURL, "path") : nil;
        NSString *bid = [bidObj isKindOfClass:[NSString class]] ? bidObj : nil;
        NSString *bundlePath = [pathObj isKindOfClass:[NSString class]] ? pathObj : nil;
        return cbrBundleIsNativeCarPlay(bid, bundlePath);
    } @catch (NSException *e) { return NO; }
}

static BOOL cbrDeclarationIsForNativeCarPlayApp(id declaration) {
    if (!declaration) return NO;
    @try {
        id bidObj = cb(declaration, "bundleIdentifier");
        id pathObj = cb(declaration, "bundlePath");
        NSString *bid = [bidObj isKindOfClass:[NSString class]] ? bidObj : nil;
        NSString *bundlePath = [pathObj isKindOfClass:[NSString class]] ? pathObj : nil;
        return cbrBundleIsNativeCarPlay(bid, bundlePath);
    } @catch (NSException *e) { return NO; }
}

// Only flags genuinely CORRUPTED pointers (tiny/misaligned non-null values,
// the exact 0x1-style garbage from the original SIGSEGV). A nil pointer is
// NOT corruption -- it just means the OS hasn't lazily built this app's
// declaration yet, and %orig must be allowed to run so it can.
static BOOL cbrDeclarationPointerLooksCorrupted(id appInfo) {
    if (!appInfo) return NO;
    Ivar iv = class_getInstanceVariable(objc_getClass("DBApplicationInfo"), "_carPlayDeclaration");
    if (!iv) return NO;
    id decl = object_getIvar(appInfo, iv);
    if (!decl) return NO;
    uintptr_t p = (uintptr_t)decl;
    if (p < 0x1000) return YES;
    if (p & 0x7) return YES;
    return NO;
}

static BOOL cbrIsOurApp(id appInfo) {
    if (!appInfo) return NO;
    @try {
        id bidObj = cb(appInfo, "bundleIdentifier");
        const char *bid = bidObj ? ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
            sel_registerName("UTF8String")) : NULL;
        if (cbrAppHasNativeCarPlay(appInfo)) {
            if (bid) CBLogFmt("[CBR] cbrIsOurApp(%s): native CarPlay -> not ours", bid);
            return NO;
        }
        if (!bid) return NO;
        return CBIsEnabled(bid);
    } @catch (NSException *e) { return NO; }
}

// Build a CRCarPlayAppPolicy directly so we never call %orig on our (mangled) apps.
static id cbrMakePolicy(id appInfo) {
    Class polClass = objc_getClass("CRCarPlayAppPolicy");
    if (!polClass) return nil;
    id pol = [[polClass alloc] init];
    if (!pol) return nil;
    cb1b(pol, "setCarPlaySupported:", YES);
    cb1b(pol, "setCanDisplayOnCarScreen:", YES);
    cb1b(pol, "setLaunchUsingTemplateUI:", NO);
    cb1b(pol, "setLaunchUsingSiri:", NO);
    cb1b(pol, "setLaunchNotificationsUsingSiri:", NO);
    cb1b(pol, "setLaunchUsingMusicUIService:", NO);
    cb1b(pol, "setBadgesAppIcon:", NO);
    cb1b(pol, "setShowsNotifications:", NO);
    cb1b(pol, "setHandlesCarIntents:", NO);
    @try {
        id bURL = cb(appInfo, "bundleURL");
        id bPath = bURL ? cb(bURL, "path") : nil;   // NSString, not NSURL
        if (bPath) cb1(pol, "setBundlePath:", bPath);
    } @catch (NSException *e) {}
    return pol;
}

static void addCarplayDeclarations(id lib) {
    if (!lib) { CBLog("[CBR] addDeclarations: lib nil"); return; }
    cbrSnapshotNativeSet(lib);   // capture native-CarPlay apps BEFORE injecting ours
    cbrDumpLibrary(lib);
    cbrDumpPolicyInfo(lib);
    cbrInjectEnabledApps(lib);

    Class declClass = objc_getClass("CRCarPlayAppDeclaration");
    if (!declClass) { CBLog("[CBR] CRCarPlayAppDeclaration not found"); return; }

    NSArray *apps = cb(lib, "allInstalledApplications");
    if (!apps) { CBLog("[CBR] allInstalledApplications nil"); return; }

    char msg[80];
    snprintf(msg, sizeof(msg), "[CBR] Library has %lu apps", (unsigned long)[apps count]);
    CBLog(msg);

    NSUInteger injected = 0;
    cbrDumpDeclClass();
    for (id appInfo in apps) {
        @try {
            // Get bundleIdentifier as const char* — no NSString parameter
            id bidObj = cb(appInfo, "bundleIdentifier");
            if (!bidObj) continue;
            const char *bid_cstr = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                sel_registerName("UTF8String"));
            if (!bid_cstr) continue;

            // Skip if already has a declaration
            id existing = getIvar(appInfo, "_carPlayDeclaration");
            if (!existing) existing = cb(appInfo, "carPlayDeclaration");
            if (existing) continue;

            // Only user apps — skip Apple system apps
            id btype = cb(appInfo, "bundleType");
            const char *btype_cstr = btype ?
                ((const char*(*)(id,SEL))objc_msgSend)(btype, sel_registerName("UTF8String")) : NULL;
            if ((!btype_cstr || strcmp(btype_cstr, "User") != 0) &&
                strncmp(bid_cstr, "com.apple.", 10) == 0) continue;

            // Only inject apps the user enabled in Settings → CarBridge Reborn
            if (!CBIsEnabled(bid_cstr)) continue;

            id decl = [[declClass alloc] init];
            cb1b(decl, "setSupportsTemplates:", NO);   // NO = 0
            cb1b(decl, "setSupportsMaps:", NO);        // YES = 1
            cb1(decl, "setBundleIdentifier:", bidObj);
            id bundleURL = cb(appInfo, "bundleURL");
            id declPath = bundleURL ? cb(bundleURL, "path") : nil;
            if (declPath) cb1(decl, "setBundlePath:", declPath);

            BOOL set = setIvar(appInfo, "_carPlayDeclaration", decl);
            if (!set) {
                SEL setter = sel_registerName("setCarPlayDeclaration:");
                if (setter && [appInfo respondsToSelector:setter])
                    ((void(*)(id,SEL,id))objc_msgSend)(appInfo, setter, decl);
            }

            // Tag the app for launch interception
            NSArray *old = cb(appInfo, "tags");
            if (!old) old = getIvar(appInfo, "_tags");
            if (!old) old = @[];

            BOOL tagged = NO;
            for (id tag in old) {
                const char *t = ((const char*(*)(id,SEL))objc_msgSend)(tag,
                    sel_registerName("UTF8String"));
                if (t && strcmp(t, "CarPlayEnable") == 0) { tagged = YES; break; }
            }
            if (!tagged) {
                NSString *tagStr = @"CarPlayEnable";
                NSArray *newTags = [@[tagStr] arrayByAddingObjectsFromArray:old];
                if (!setIvar(appInfo, "_tags", newTags))
                    cb1(appInfo, "setTags:", newTags);
            }
            injected++;
        } @catch(...) {}
    }

    snprintf(msg, sizeof(msg), "[CBR] Injected %lu declarations", (unsigned long)injected);
    CBLog(msg);
}


// ---- v3.14.0 SpringBoard side: receive the CarPlay launch signal ----
// Darwin notifications carry no userInfo across processes, so CarPlay writes the
// target bundle id to a file then posts a name-only notification; we read it here.
// Pure logging: proves the signal reaches SpringBoard with the right bid. No
// scene/window code yet (that is the next, riskier stage).
static void cbrSBLog(const char *msg) {
    int fd = open("/var/mobile/CBR_springboard.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd >= 0) { write(fd, msg, strlen(msg)); write(fd, "\n", 1); close(fd); }
    write(2, msg, strlen(msg)); write(2, "\n", 1);
}
static void cbrSBDumpOneClass(int fd, const char *clsname) {
    Class dc = objc_getClass(clsname);
    if (!dc) {
        char miss[128]; int n = snprintf(miss, sizeof(miss), "  [%s] NOT FOUND\n", clsname);
        if (fd>=0) write(fd, miss, n); return;
    }
    char hdr[160]; int hn = snprintf(hdr, sizeof(hdr), "== %s ==\n", clsname);
    if (fd>=0) write(fd, hdr, hn);
    Class c = dc; int depth = 0;
    while (c && strcmp(class_getName(c), "NSObject") != 0 && depth < 3) {
        unsigned int mn = 0;
        Method *m = class_copyMethodList(c, &mn);
        char cl[160]; int cn = snprintf(cl, sizeof(cl), " -[%s] %u methods:\n", class_getName(c), mn);
        if (fd>=0) write(fd, cl, cn);
        for (unsigned int i = 0; i < mn; i++) {
            const char *sn = sel_getName(method_getName(m[i]));
            // only the interesting ones: scene/display/host/screen/carplay/external/launch
            if (strcasestr(sn,"scene")||strcasestr(sn,"display")||strcasestr(sn,"host")||
                strcasestr(sn,"screen")||strcasestr(sn,"carplay")||strcasestr(sn,"external")||
                strcasestr(sn,"launch")||strcasestr(sn,"window")||strcasestr(sn,"context")) {
                char ml[200]; int mnl = snprintf(ml, sizeof(ml), "    -%s\n", sn);
                if (fd>=0) write(fd, ml, mnl);
            }
        }
        if (m) free(m);
        c = class_getSuperclass(c); depth++;
    }
}
static void cbrSBDumpSceneClasses(void) {
    static int done = 0;
    if (done) return;
    done = 1;
    int fd = open("/var/mobile/CBR_sb_classes.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return;
    write(fd, "==== SB SCENE/DISPLAY CLASS DUMP (iOS17) ====\n", 45);
    // Candidate class names across the SpringBoard/FrontBoard scene + display stack.
    const char *names[] = {
        "SBSceneManager", "SBSceneManagerCoordinator", "SBMainDisplaySceneManager",
        "SBSceneHandle", "SBApplicationSceneHandle", "FBSceneManager", "FBScene",
        "FBSceneHostManager", "FBSSceneHostManager", "UISceneHostingController",
        "SBSceneHostManager", "SBDisplayManager", "SBExternalDisplayManager",
        "FBSDisplayConfiguration", "FBSDisplayLayout", "CADisplay", "UIScreen",
        "SBApplicationController", "FBSSceneClientProvider",
        "SBWindowScene", "UIWindowScene", "SBSceneView", "SBDeviceApplicationSceneView",
        "CRSExternalDisplayManager", "CarDisplayInfo", "SBHDisplayIdentifier",
        NULL };
    for (int i = 0; names[i]; i++) cbrSBDumpOneClass(fd, names[i]);
    write(fd, "==== END SB CLASS DUMP ====\n", 28);
    close(fd);
    cbrSBLog("[CBR-SB] scene/display class dump written to CBR_sb_classes.txt");
}
static void cbrSBProbeDisplays(void) {
    static int done = 0; if (done) return; done = 1;
    int fd = open("/var/mobile/CBR_sb_probe.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return;
    #define PB(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define PBF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    PB("==== SB DISPLAY/SCENEMGR PROBE ====\n");

    // 1) Enumerate UIScreens, flag the car screen.
    @try {
        Class UIScreenCls = objc_getClass("UIScreen");
        id screens = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("screens"));
        NSUInteger sc = screens ? [screens count] : 0;
        PBF("UIScreen.screens count: %lu\n", (unsigned long)sc);
        for (NSUInteger i = 0; i < sc; i++) {
            id scr = [screens objectAtIndex:i];
            BOOL isCar = ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen"));
            BOOL isMain = ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isMainScreen"));
            BOOL isExt  = ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isExternal"));
            CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));
            PBF("  screen[%lu] car=%d main=%d ext=%d bounds=%.0fx%.0f class=%s\n",
                (unsigned long)i, isCar, isMain, isExt, b.size.width, b.size.height,
                class_getName(object_getClass(scr)));
            id ident = cb(scr, "displayIdentity");
            PBF("     displayIdentity: %s (%s)\n",
                ident ? "present" : "nil",
                ident ? class_getName(object_getClass(ident)) : "-");
            id cfg = cb(scr, "displayConfiguration");
            if (cfg) {
                BOOL dCar = ((BOOL(*)(id,SEL))objc_msgSend)(cfg, sel_registerName("isCarDisplay"));
                PBF("     displayConfiguration.isCarDisplay=%d class=%s\n",
                    dCar, class_getName(object_getClass(cfg)));
            }
        }
    } @catch (NSException *e) { PBF("screen probe EXC: %s\n", [[e reason] UTF8String] ?: "?"); }

    // 2) Can we reach a scene manager / coordinator?
    @try {
        Class coordCls = objc_getClass("SBSceneManagerCoordinator");
        PBF("SBSceneManagerCoordinator class: %s\n", coordCls ? "present" : "MISSING");
        Class sbbCls = objc_getClass("SBApplicationController");
        id shared = sbbCls ? ((id(*)(id,SEL))objc_msgSend)(sbbCls, sel_registerName("sharedInstance")) : nil;
        PBF("SBApplicationController.sharedInstance: %s\n", shared ? "present" : "nil");
    } @catch (NSException *e) { PBF("scenemgr probe EXC: %s\n", [[e reason] UTF8String] ?: "?"); }

    PB("==== END PROBE ====\n");
    close(fd);
    cbrSBLog("[CBR-SB] display/scenemgr probe written to CBR_sb_probe.txt");
}
// v3.15.0: STEP 1 of rendering - just prove we can own a window on the car screen.
// No scene, no app hosting yet. A solid-color window appearing on the CarPlay
// display means the riskiest unknown (SpringBoard accepting our window on the
// external car screen) is solved. Logs before/after every call so a respring
// points at the exact failing operation.
static id gCBRCarWindow = nil;
// cbrFindCarWindowScene: scene-attach variant  // retain so ARC doesn't release it
static void cbrSBRenderWindow(void) {
    static int done = 0; if (done) return; done = 1;
    cbrSBLog("[CBR-SB] render-window: START");

    @try {
        // Find the car screen.
        Class UIScreenCls = objc_getClass("UIScreen");
        id screens = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("screens"));
        id carScreen = nil;
        NSUInteger sc = screens ? [screens count] : 0;
        for (NSUInteger i = 0; i < sc; i++) {
            id scr = [screens objectAtIndex:i];
            if (((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen"))) {
                carScreen = scr; break;
            }
        }
        if (!carScreen) { cbrSBLog("[CBR-SB] render-window: NO car screen -> abort"); return; }
        CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(carScreen, sel_registerName("bounds"));
        char bb[128]; snprintf(bb, sizeof(bb), "[CBR-SB] render-window: car screen %.0fx%.0f",
                               b.size.width, b.size.height); cbrSBLog(bb);

        // Allocate a UIWindow bound to the car screen.
        cbrSBLog("[CBR-SB] render-window: alloc UIWindow");
        Class UIWindowCls = objc_getClass("UIWindow");
        id win = ((id(*)(id,SEL))objc_msgSend)(UIWindowCls, sel_registerName("alloc"));

        cbrSBLog("[CBR-SB] render-window: initWithFrame");
        win = ((id(*)(id,SEL,CGRect))objc_msgSend)(win, sel_registerName("initWithFrame:"), b);
        if (!win) { cbrSBLog("[CBR-SB] render-window: init nil -> abort"); return; }

        cbrSBLog("[CBR-SB] render-window: setScreen");
        ((void(*)(id,SEL,id))objc_msgSend)(win, sel_registerName("setScreen:"), carScreen);

        // iOS 17: associate the window with the car screen's UIWindowScene, or it
        // renders nowhere. Find a window scene whose screen is the car screen.
        cbrSBLog("[CBR-SB] render-window: searching for car UIWindowScene");
        id carScene = nil;
        @try {
            Class appCls = objc_getClass("UIApplication");
            id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
            id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
            id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
            NSUInteger cnt = all ? [all count] : 0;
            char cb0[96]; snprintf(cb0,sizeof(cb0),"[CBR-SB] connectedScenes: %lu",(unsigned long)cnt); cbrSBLog(cb0);
            for (NSUInteger i = 0; i < cnt; i++) {
                id s = [all objectAtIndex:i];
                if (![s isKindOfClass:objc_getClass("UIWindowScene")]) continue;
                id scr = cb(s, "screen");
                BOOL isCar = scr ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen")) : NO;
                char sl[160]; snprintf(sl,sizeof(sl),"[CBR-SB]   scene[%lu] %s car=%d",
                    (unsigned long)i, class_getName(object_getClass(s)), isCar); cbrSBLog(sl);
                if (isCar) { carScene = s; break; }
            }
        } @catch (NSException *e) {
            char eb[200]; snprintf(eb,sizeof(eb),"[CBR-SB] scene search EXC: %s",[[e reason] UTF8String]?:"?"); cbrSBLog(eb);
        }

        if (carScene) {
            cbrSBLog("[CBR-SB] render-window: attaching to car windowScene");
            ((void(*)(id,SEL,id))objc_msgSend)(win, sel_registerName("setWindowScene:"), carScene);
        } else {
            cbrSBLog("[CBR-SB] render-window: NO car windowScene found (will try screen-only)");
        }

        // Bright background so it's unmistakable on the dash.
        cbrSBLog("[CBR-SB] render-window: set backgroundColor");
        Class UIColorCls = objc_getClass("UIColor");
        id red = ((id(*)(id,SEL))objc_msgSend)(UIColorCls, sel_registerName("redColor"));
        ((void(*)(id,SEL,id))objc_msgSend)(win, sel_registerName("setBackgroundColor:"), red);

        cbrSBLog("[CBR-SB] render-window: setHidden:NO");
        ((void(*)(id,SEL,BOOL))objc_msgSend)(win, sel_registerName("setHidden:"), NO);

        cbrSBLog("[CBR-SB] render-window: makeKeyAndVisible");
        ((void(*)(id,SEL))objc_msgSend)(win, sel_registerName("makeKeyAndVisible"));

        gCBRCarWindow = win;  // retain
        cbrSBLog("[CBR-SB] render-window: DONE - red window should be on car screen");
    } @catch (NSException *e) {
        char eb[300]; snprintf(eb, sizeof(eb), "[CBR-SB] render-window EXC: %s",
                               [[e reason] UTF8String] ?: "?"); cbrSBLog(eb);
    }
}
// v3.16.2: can SpringBoard hand us an application scene handle for the tapped app?
// This is the decisive Option-A test. Query + log only. Creating a scene handle
// MAY spin up the app's scene, so this is run parked with disable staged.
// v3.17.0: actually CREATE the app's scene handle (creating path, no request object).
// Uses the confirmed createPrimaryIfRequired: identity path, then fetches the handle.
// This is the first CREATING call - may spin up the app's scene. Parked + disable staged.
static id gCBRSceneHandle = nil;  // retain the handle we create
// v3.17.1: discover how to CREATE (not just fetch) a scene handle. Logs the
// fetchOrCreate signature + candidate request classes so we build the request right.
static void cbrSBProbeRequest(id mgr, id sbApp, id identity) {
    int fd = open("/var/mobile/CBR_sb_request.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define RQ(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define RQF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    RQ("==== REQUEST PROBE ====\n");
    @try {
        // 1) All fetchOrCreate / create methods on the scene manager.
        Class mgrCls = object_getClass(mgr);
        Class c = mgrCls; int depth=0;
        while (c && strcmp(class_getName(c),"NSObject")!=0 && depth<4) {
            unsigned int n=0; Method *m=class_copyMethodList(c,&n);
            for (unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i]));
                if (strcasestr(sn,"fetchorcreate")||strcasestr(sn,"createscene")||
                    (strcasestr(sn,"handle")&&strcasestr(sn,"for")))
                    RQF("  mgr -%s\n", sn); }
            if(m)free(m); c=class_getSuperclass(c); depth++;
        }
        // 2) Candidate request classes present on device.
        const char *reqClasses[] = {"FBSceneManagerRequest","FBSSceneRequest","SBApplicationSceneEntity",
            "FBApplicationSceneEntity","SBSceneHandleRequest","FBSceneRequest",
            "SBApplicationSceneHandleRequest","FBProcessManager", NULL};
        for (int i=0;reqClasses[i];i++)
            RQF("  class %s: %s\n", reqClasses[i], objc_getClass(reqClasses[i])?"present":"MISSING");
        // 3) identity's own methods (maybe it builds a request/entity).
        if (identity) {
            RQF("  identity class: %s\n", class_getName(object_getClass(identity)));
        }
        // 4) Does the app object vend an entity/request?
        if (sbApp) {
            const char *appProbes[] = {"sceneEntity","applicationSceneEntity","mainSceneEntity","sceneHandle", NULL};
            for (int i=0;appProbes[i];i++){ id r=cb(sbApp,appProbes[i]);
                RQF("  app.%s -> %s\n", appProbes[i], r?class_getName(object_getClass(r)):"nil"); }
        }
    } @catch (NSException *e) { RQF("REQ EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    RQ("==== END ====\n");
    if(fd>=0)close(fd);
}
static id cbrSBCreateSceneHandle(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_sb_create.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define CR(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define CRF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    CR("==== CREATE SCENE HANDLE ====\n");
    id handle = nil;
    if (!bid_cstr || !bid_cstr[0]) { CR("no bid\n"); if(fd>=0)close(fd); return nil; }
    CRF("bid: %s\n", bid_cstr);
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];

        // App object.
        Class acCls = objc_getClass("SBApplicationController");
        id ac = acCls ? ((id(*)(id,SEL))objc_msgSend)(acCls, sel_registerName("sharedInstance")) : nil;
        id sbApp = ac ? ((id(*)(id,SEL,id))objc_msgSend)(ac, sel_registerName("applicationWithBundleIdentifier:"), bid) : nil;
        CRF("SBApplication: %s\n", sbApp ? class_getName(object_getClass(sbApp)) : "nil");
        if (!sbApp) { CR("no app -> abort\n"); CR("==== END ====\n"); if(fd>=0)close(fd); return nil; }

        // Scene manager for the main display.
        Class coordCls = objc_getClass("SBSceneManagerCoordinator");
        id coord = coordCls ? ((id(*)(id,SEL))objc_msgSend)(coordCls, sel_registerName("sharedInstance")) : nil;
        Class UIScreenCls = objc_getClass("UIScreen");
        id mainScreen = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("mainScreen"));
        id dispIdentity = cb(mainScreen, "displayIdentity");
        id mgr = nil;
        if (coord && dispIdentity) {
            SEL sMgr = sel_registerName("sceneManagerForDisplayIdentity:");
            if ([coord respondsToSelector:sMgr])
                mgr = ((id(*)(id,SEL,id))objc_msgSend)(coord, sMgr, dispIdentity);
        }
        CRF("scene manager: %s\n", mgr ? class_getName(object_getClass(mgr)) : "nil");
        if (!mgr) { CR("no mgr -> abort\n"); CR("==== END ====\n"); if(fd>=0)close(fd); return nil; }

        // Create-or-get a scene identity (createPrimaryIfRequired: = creating path, no request obj).
        id identity = nil;
        @try {
            SEL createSel = sel_registerName("sceneIdentityForApplication:createPrimaryIfRequired:sceneSessionRole:");
            if ([mgr respondsToSelector:createSel]) {
                // sceneSessionRole: 0 is the default application role on iOS.
                identity = ((id(*)(id,SEL,id,BOOL,NSInteger))objc_msgSend)(mgr, createSel, sbApp, YES, (NSInteger)0);
            }
        } @catch (NSException *e) { CRF("createIdentity EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        CRF("created sceneIdentity: %s\n", identity ? class_getName(object_getClass(identity)) : "nil");

        if (!identity) { CR("no identity -> abort\n"); CR("==== END ====\n"); if(fd>=0)close(fd); return nil; }

        cbrSBProbeRequest(mgr, sbApp, identity);

        // Fetch the handle for that identity.
        @try {
            SEL esh = sel_registerName("existingSceneHandleForSceneIdentity:");
            if ([mgr respondsToSelector:esh])
                handle = ((id(*)(id,SEL,id))objc_msgSend)(mgr, esh, identity);
        } @catch (NSException *e) { CRF("fetchHandle EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        CRF("scene handle: %s\n", handle ? class_getName(object_getClass(handle)) : "nil");

        if (handle) {
            gCBRSceneHandle = handle;  // retain
            // Log the handle's scene identifier + whether it can mint a scene view.
            id sid = cb(handle, "sceneIdentifier");
            CRF("handle.sceneIdentifier: %s\n", sid ? [[sid description] UTF8String] : "nil");
            SEL mkView = sel_registerName("newSceneViewWithReferenceSize:contentOrientation:containerOrientation:hostRequester:");
            CRF("handle can mint scene view: %s\n", [handle respondsToSelector:mkView] ? "YES" : "no");
            CR("SUCCESS: got a live scene handle\n");
        }
    } @catch (NSException *e) {
        CRF("CREATE EXC: %s\n", [[e reason] UTF8String] ?: "?");
    }
    CR("==== END ====\n");
    if (fd>=0) close(fd);
    return handle;
}
static void cbrSBProbeSceneHandle(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_sb_handle.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define HP(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define HPF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    HP("==== SCENE HANDLE PROBE ====\n");
    if (!bid_cstr || !bid_cstr[0]) { HP("no bid\n"); if(fd>=0)close(fd); return; }
    HPF("bid: %s\n", bid_cstr);

    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];

        // 1) Reach a scene manager via the coordinator.
        Class coordCls = objc_getClass("SBSceneManagerCoordinator");
        id coord = nil;
        if (coordCls) {
            // Common singletons.
            for (const char *acc : (const char*[]){"sharedInstance","mainDisplaySceneManagerCoordinator", NULL}) {
                if (!acc) break;
                SEL s = sel_registerName(acc);
                if ([coordCls respondsToSelector:s]) { coord = ((id(*)(id,SEL))objc_msgSend)(coordCls, s); if (coord) break; }
            }
        }
        HPF("coordinator: %s\n", coord ? class_getName(object_getClass(coord)) : "nil");

        // 2) Get the app for the bundle id (SBApplicationController).
        id sbApp = nil;
        @try {
            Class acCls = objc_getClass("SBApplicationController");
            id ac = acCls ? ((id(*)(id,SEL))objc_msgSend)(acCls, sel_registerName("sharedInstance")) : nil;
            if (ac) {
                SEL appForBID = sel_registerName("applicationWithBundleIdentifier:");
                if ([ac respondsToSelector:appForBID])
                    sbApp = ((id(*)(id,SEL,id))objc_msgSend)(ac, appForBID, bid);
            }
        } @catch (NSException *e) {}
        HPF("SBApplication: %s\n", sbApp ? class_getName(object_getClass(sbApp)) : "nil");

        // 3) Main-display scene manager: try the coordinator's per-display lookup,
        //    or fall back to a shared SBMainDisplaySceneManager if exposed.
        id mgr = nil;
        @try {
            // Try to get main display identity from UIScreen.mainScreen.
            Class UIScreenCls = objc_getClass("UIScreen");
            id mainScreen = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("mainScreen"));
            id dispIdentity = cb(mainScreen, "displayIdentity");
            HPF("main displayIdentity: %s\n", dispIdentity ? class_getName(object_getClass(dispIdentity)) : "nil");
            if (coord && dispIdentity) {
                SEL sMgr = sel_registerName("sceneManagerForDisplayIdentity:");
                if ([coord respondsToSelector:sMgr])
                    mgr = ((id(*)(id,SEL,id))objc_msgSend)(coord, sMgr, dispIdentity);
            }
        } @catch (NSException *e) {}
        HPF("scene manager: %s\n", mgr ? class_getName(object_getClass(mgr)) : "nil");

        if (!mgr) { HP("no scene manager -> cannot probe handle\n"); HP("==== END ====\n"); if(fd>=0)close(fd); return; }

        // 4) sceneIdentityForApplication: (needs the SBApplication object).
        id identity = nil;
        @try {
            SEL sid = sel_registerName("sceneIdentityForApplication:");
            if (sbApp && [mgr respondsToSelector:sid])
                identity = ((id(*)(id,SEL,id))objc_msgSend)(mgr, sid, sbApp);
        } @catch (NSException *e) { HPF("sceneIdentityForApplication EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        HPF("sceneIdentity: %s\n", identity ? class_getName(object_getClass(identity)) : "nil");

        // 5) existingSceneHandleForSceneIdentity: (non-creating - safest).
        id handle = nil;
        @try {
            SEL esh = sel_registerName("existingSceneHandleForSceneIdentity:");
            if (identity && [mgr respondsToSelector:esh])
                handle = ((id(*)(id,SEL,id))objc_msgSend)(mgr, esh, identity);
        } @catch (NSException *e) { HPF("existingSceneHandle EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        HPF("existing handle: %s\n", handle ? class_getName(object_getClass(handle)) : "nil");

        // 6) Report whether the creating API exists (do NOT call it yet - creating
        //    may launch the app scene; we just confirm it's reachable).
        SEL fc = sel_registerName("fetchOrCreateApplicationSceneHandleForRequest:");
        HPF("fetchOrCreate available on mgr: %s\n", [mgr respondsToSelector:fc] ? "YES" : "no");
        SEL scForApp = sel_registerName("sceneIdentityForApplication:createPrimaryIfRequired:sceneSessionRole:");
        HPF("createPrimary variant available: %s\n", [mgr respondsToSelector:scForApp] ? "YES" : "no");

    } @catch (NSException *e) {
        HPF("PROBE EXC: %s\n", [[e reason] UTF8String] ?: "?");
    }
    HP("==== END ====\n");
    if (fd>=0) close(fd);
}
static void cbrSBLaunchCallback(CFNotificationCenterRef center, void *observer,
                                CFStringRef name, const void *object,
                                CFDictionaryRef userInfo) {
    char bid[256] = {0};
    int fd = open("/var/mobile/CBR_pending_launch.txt", O_RDONLY);
    if (fd >= 0) {
        ssize_t n = read(fd, bid, sizeof(bid) - 1);
        close(fd);
        if (n > 0) { bid[n] = 0; for (int i = 0; bid[i]; i++) if (bid[i]=='\n'||bid[i]=='\r'){bid[i]=0;break;} }
    }
    char line[320];
    snprintf(line, sizeof(line), "[CBR-SB] received launch signal -> %s",
             bid[0] ? bid : "(no pending file)");
    cbrSBLog(line);
    cbrSBProbeSceneHandle(bid);
    cbrSBCreateSceneHandle(bid);
    cbrSBDumpSceneClasses();
    cbrSBProbeDisplays();
    cbrSBRenderWindow();
}
static void cbrSBRegisterListener(void) {
    cbrSBLog("[CBR-SB] v3.14.0 listener registering in SpringBoard");
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
        NULL, cbrSBLaunchCallback, CFSTR("com.carbridgereborn.launch"),
        NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    cbrSBLog("[CBR-SB] observer registered for com.carbridgereborn.launch");
}

// v3.15.2: probe the CarPlayApp process's own scenes/screens. The car window
// scene is NOT in SpringBoard's connectedScenes (CarPlay UI runs in this
// process, com.apple.CarPlayApp). Find where the car scene actually lives.
static id gCBRCarTestWindow;  // forward decl (defined below)
static void cbrCPDismissWindow(void) {
    @try {
        if (gCBRCarTestWindow) {
            ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBRCarTestWindow, sel_registerName("setHidden:"), YES);
            ((void(*)(id,SEL))objc_msgSend)(gCBRCarTestWindow, sel_registerName("resignKeyWindow"));
            gCBRCarTestWindow = nil;  // ARC releases -> window gone, dashboard returns
            CBLog("[CBR-CP] dismiss: window removed");
        }
    } @catch(...) {}
}
// gCBRCarTestWindow defined above (defaults nil)
// marker: cbrCPShowPendingApp
static void cbrCPRenderTest(void) {
    CBLog("[CBR-CP] render-test: START (CarPlayApp side)");
    if (gCBRCarTestWindow) { cbrCPDismissWindow(); return; }  // tap again = dismiss
    @try {
        // Get the car window scene in THIS (CarPlayApp) process.
        Class appCls = objc_getClass("UIApplication");
        id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? [all count] : 0;
        id carScene = nil;
        for (NSUInteger i = 0; i < cnt; i++) {
            id s = [all objectAtIndex:i];
            id scr = cb(s, "screen");
            if (scr && ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen"))) { carScene = s; break; }
        }
        if (!carScene) { CBLog("[CBR-CP] render-test: no car scene -> abort"); return; }
        CBLog("[CBR-CP] render-test: got car scene");

        id scr = cb(carScene, "screen");
        CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));

        // Build a window bound to the car window scene.
        CBLog("[CBR-CP] render-test: alloc window");
        Class UIWindowCls = objc_getClass("UIWindow");
        id win = ((id(*)(id,SEL))objc_msgSend)(UIWindowCls, sel_registerName("alloc"));

        // initWithWindowScene: is the iOS-13+ correct initializer.
        SEL initScene = sel_registerName("initWithWindowScene:");
        if ([win respondsToSelector:initScene]) {
            CBLog("[CBR-CP] render-test: initWithWindowScene:");
            win = ((id(*)(id,SEL,id))objc_msgSend)(win, initScene, carScene);
        } else {
            CBLog("[CBR-CP] render-test: initWithFrame (fallback)");
            win = ((id(*)(id,SEL,CGRect))objc_msgSend)(win, sel_registerName("initWithFrame:"), b);
        }
        if (!win) { CBLog("[CBR-CP] render-test: win nil -> abort"); return; }
        ((void(*)(id,SEL,CGRect))objc_msgSend)(win, sel_registerName("setFrame:"), b);

        // Root VC whose view shows the tapped app's icon + name (proves per-app routing).
        CBLog("[CBR-CP] render-test: build rootVC + per-app content");
        Class VCCls = objc_getClass("UIViewController");
        id vc = ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(VCCls, sel_registerName("alloc")), sel_registerName("init"));
        id view = cb(vc, "view");
        Class UIColorCls = objc_getClass("UIColor");
        id black = ((id(*)(id,SEL))objc_msgSend)(UIColorCls, sel_registerName("blackColor"));
        ((void(*)(id,SEL,id))objc_msgSend)(view, sel_registerName("setBackgroundColor:"), black);
        ((void(*)(id,SEL,id))objc_msgSend)(win, sel_registerName("setRootViewController:"), vc);

        // Read the pending bundle id written by the CarPlay tap.
        char pend[256] = {0};
        int pfd = open("/var/mobile/CBR_pending_launch.txt", O_RDONLY);
        if (pfd >= 0) { ssize_t n = read(pfd, pend, sizeof(pend)-1); close(pfd);
            if (n > 0) { pend[n]=0; for (int i=0;pend[i];i++) if(pend[i]=='\n'||pend[i]=='\r'){pend[i]=0;break;} } }
        NSString *bid = pend[0] ? [NSString stringWithUTF8String:pend] : @"(none)";
        CBLogFmt("[CBR-CP] render-test: pending bid = %s", pend[0]?pend:"(none)");

        // App display name via LSApplicationProxy.
        NSString *name = bid;
        @try {
            Class LSAP = objc_getClass("LSApplicationProxy");
            id proxy = pend[0] ? ((id(*)(id,SEL,id))objc_msgSend)(LSAP, sel_registerName("applicationProxyForIdentifier:"), bid) : nil;
            id ln = proxy ? cb(proxy, "localizedName") : nil;
            if ([ln isKindOfClass:objc_getClass("NSString")] && [ln length]) name = ln;
        } @catch (NSException *e) {}

        // App icon via UIImage private API.
        id icon = nil;
        @try {
            Class UIImageCls = objc_getClass("UIImage");
            SEL iconSel = sel_registerName("_applicationIconImageForBundleIdentifier:format:scale:");
            if (pend[0] && [UIImageCls respondsToSelector:iconSel])
                icon = ((id(*)(id,SEL,id,int,double))objc_msgSend)(UIImageCls, iconSel, bid, 2, (double)2.0);
        } @catch (NSException *e) {}

        // Icon image view, centered-ish.
        @try {
            if (icon) {
                Class IVCls = objc_getClass("UIImageView");
                id iv = ((id(*)(id,SEL,id))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(IVCls, sel_registerName("alloc")), sel_registerName("initWithImage:"), icon);
                ((void(*)(id,SEL,CGRect))objc_msgSend)(iv, sel_registerName("setFrame:"), CGRectMake(b.size.width/2.0-40, 50, 80, 80));
                ((void(*)(id,SEL,id))objc_msgSend)(view, sel_registerName("addSubview:"), iv);
            }
        } @catch (NSException *e) {}

        // Name label.
        @try {
            Class LblCls = objc_getClass("UILabel");
            id lbl = ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(LblCls, sel_registerName("alloc")), sel_registerName("init"));
            ((void(*)(id,SEL,CGRect))objc_msgSend)(lbl, sel_registerName("setFrame:"), CGRectMake(0, 150, b.size.width, 40));
            NSString *disp = [@"Bridged: " stringByAppendingString:name];
            ((void(*)(id,SEL,id))objc_msgSend)(lbl, sel_registerName("setText:"), disp);
            id white = ((id(*)(id,SEL))objc_msgSend)(UIColorCls, sel_registerName("whiteColor"));
            ((void(*)(id,SEL,id))objc_msgSend)(lbl, sel_registerName("setTextColor:"), white);
            ((void(*)(id,SEL,NSInteger))objc_msgSend)(lbl, sel_registerName("setTextAlignment:"), (NSInteger)1);
            ((void(*)(id,SEL,id))objc_msgSend)(view, sel_registerName("addSubview:"), lbl);
        } @catch (NSException *e) {}

        CBLog("[CBR-CP] render-test: setWindowLevel");
        ((void(*)(id,SEL,double))objc_msgSend)(win, sel_registerName("setWindowLevel:"), (double)10000.0);
        CBLog("[CBR-CP] render-test: makeKeyAndVisible");
        ((void(*)(id,SEL))objc_msgSend)(win, sel_registerName("makeKeyAndVisible"));
        ((void(*)(id,SEL,BOOL))objc_msgSend)(win, sel_registerName("setHidden:"), NO);

        gCBRCarTestWindow = win;
        // Tap anywhere on our view dismisses (return to dashboard). Gesture target is the
        // window; selector implemented via a hooked class below is overkill, so use a
        // simple approach: auto-remove after 15s no matter what, plus the toggle above.
        @try {
            // schedule auto-dismiss: perform cbrCPDismissWindow via a timer block.
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(15 * NSEC_PER_SEC)),
                dispatch_get_main_queue(), ^{ cbrCPDismissWindow(); });
            CBLog("[CBR-CP] render-test: 15s auto-dismiss armed");
        } @catch(...) {}
        CBLog("[CBR-CP] render-test: DONE - red should be on CAR screen now");
    } @catch (NSException *e) {
        char eb[300]; snprintf(eb,sizeof(eb),"[CBR-CP] render-test EXC: %s",[[e reason] UTF8String]?:"?"); CBLog(eb);
    }
}
static void cbrCPProbeCarSceneGuts(void) {
    static int done = 0; if (done) return; done = 1;
    int fd = open("/var/mobile/CBR_cp_scene_guts.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return;
    #define GP(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define GPF(...) do{ char _b[500]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    GP("==== CAR SCENE GUTS ====\n");
    @try {
        Class appCls = objc_getClass("UIApplication");
        id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? [all count] : 0;
        id carScene = nil;
        for (NSUInteger i = 0; i < cnt; i++) {
            id s = [all objectAtIndex:i];
            id scr = cb(s, "screen");
            if (scr && ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen"))) { carScene = s; break; }
        }
        if (!carScene) { GP("no car scene\n"); close(fd); return; }
        GPF("car scene: %s\n", class_getName(object_getClass(carScene)));

        // The scene's delegate - this is who manages hosting.
        id delegate = cb(carScene, "delegate");
        GPF("scene.delegate: %s\n", delegate ? class_getName(object_getClass(delegate)) : "nil");

        // Walk the windows and their root VCs / view hierarchy top level.
        id wins = cb(carScene, "windows");
        NSUInteger wc = wins ? [wins count] : 0;
        GPF("windows: %lu\n", (unsigned long)wc);
        for (NSUInteger i = 0; i < wc; i++) {
            id w = [wins objectAtIndex:i];
            GPF("  window[%lu] %s\n", (unsigned long)i, class_getName(object_getClass(w)));
            id rvc = cb(w, "rootViewController");
            GPF("     rootVC: %s\n", rvc ? class_getName(object_getClass(rvc)) : "nil");
            id cv = cb(w, "contentView");
            if (cv) GPF("     contentView: %s\n", class_getName(object_getClass(cv)));
            // top-level subviews of the root view
            id rv = rvc ? cb(rvc, "view") : nil;
            id subs = rv ? cb(rv, "subviews") : nil;
            NSUInteger svc = subs ? [subs count] : 0;
            GPF("     rootView subviews: %lu\n", (unsigned long)svc);
            for (NSUInteger j = 0; j < svc && j < 8; j++)
                GPF("        subview[%lu] %s\n", (unsigned long)j,
                    class_getName(object_getClass([subs objectAtIndex:j])));
        }

        // Does the scene expose a hosting/scene-manager-ish API?
        const char *probes[] = {"sceneManager","_sceneManager","sceneHandle","_sceneHandle",
                                "sceneManagerCoordinator","displayIdentity", NULL};
        for (int k = 0; probes[k]; k++) {
            id r = cb(carScene, probes[k]);
            GPF("  carScene.%s -> %s\n", probes[k], r ? class_getName(object_getClass(r)) : "nil/none");
        }
    } @catch (NSException *e) { GPF("EXC: %s\n", [[e reason] UTF8String] ?: "?"); }
    GP("==== END CAR SCENE GUTS ====\n");
    close(fd);
    CBLog("[CBR] car scene guts written to CBR_cp_scene_guts.txt");
}
static void cbrCPProbeScenes(void) {
    static int done = 0; if (done) return; done = 1;
    int fd = open("/var/mobile/CBR_cp_scenes.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd < 0) return;
    #define CPP(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define CPPF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    CPP("==== CARPLAYAPP SCENE/SCREEN PROBE ====\n");

    @try {
        Class appCls = objc_getClass("UIApplication");
        id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? [all count] : 0;
        CPPF("connectedScenes: %lu\n", (unsigned long)cnt);
        for (NSUInteger i = 0; i < cnt; i++) {
            id s = [all objectAtIndex:i];
            id scr = cb(s, "screen");
            BOOL isCar = scr ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen")) : NO;
            CGRect b = scr ? ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds")) : CGRectZero;
            CPPF("  scene[%lu] %s car=%d screen=%.0fx%.0f\n", (unsigned long)i,
                 class_getName(object_getClass(s)), isCar, b.size.width, b.size.height);
            // list windows in this scene
            id wins = cb(s, "windows");
            NSUInteger wc = wins ? [wins count] : 0;
            CPPF("     windows: %lu\n", (unsigned long)wc);
        }
    } @catch (NSException *e) { CPPF("scenes EXC: %s\n", [[e reason] UTF8String] ?: "?"); }

    // Also list this process's UIScreens.
    @try {
        Class UIScreenCls = objc_getClass("UIScreen");
        id screens = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("screens"));
        NSUInteger sc = screens ? [screens count] : 0;
        CPPF("UIScreen.screens: %lu\n", (unsigned long)sc);
        for (NSUInteger i = 0; i < sc; i++) {
            id scr = [screens objectAtIndex:i];
            BOOL isCar = ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen"));
            CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));
            CPPF("  screen[%lu] car=%d %.0fx%.0f\n", (unsigned long)i, isCar, b.size.width, b.size.height);
        }
    } @catch (NSException *e) { CPPF("screens EXC: %s\n", [[e reason] UTF8String] ?: "?"); }

    CPP("==== END CARPLAYAPP PROBE ====\n");
    close(fd);
    CBLog("[CBR] CarPlayApp scene probe written to CBR_cp_scenes.txt");
}
%group CARPLAY

// ── Phase 1: DashBoard._newApplicationLibrary ─────────────────────────────────
// Pure C storage via __bridge void* — zero ARC, zero ObjC, zero PAC issues
%hook DashBoard

+ (id)_newApplicationLibrary {
    CBLog("[CBR] DashBoard._newApplicationLibrary called");
    id lib = %orig;
    if (lib) {
        gLibraryPtr = (__bridge void *)lib;
        CBLog("[CBR] Library stored");
    }
    return lib;
}

%end


%hook DBEnvironmentConfiguration
- (id)policyForApplicationInfo:(id)appInfo {
    if (cbrIsOurApp(appInfo)) {
        id pol = cbrMakePolicy(appInfo);
        if (pol) { CBLog("[CBR] policy: our app -> synth canDisplay=YES"); return pol; }
        CBLog("[CBR] policy: synth failed -> nil");
        return nil;
    }
    if (appInfo && cbrDeclarationPointerLooksCorrupted(appInfo)) {
        CBLog("[CBR] policy: corrupted decl ptr -> nil (avoid crash)");
        return nil;
    }
    return %orig;
}
%end


// ── Entitlement bypass: make non-CarPlay apps "allowed" on the dashboard ──────
// Normally CarPlay only shows apps with a CarPlay entitlement. The official
// CarBridge hooks this evaluator to force-allow bridged apps. We log every
// evaluation so we can confirm the iOS 17 enum values from a real device.
%hook CRCarPlayAppPolicyEvaluator

- (NSInteger)effectivePolicyForAppDeclaration:(id)declaration {
    NSInteger orig = %orig;
    @try {
        id bidObj = cb(declaration, "bundleIdentifier");
        if (bidObj) {
            const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                sel_registerName("UTF8String"));
            if (bid) {
                CBLogFmt("[CBR] policy(%s) orig=%ld", bid, (long)orig);
                if (CBIsEnabled(bid) && !cbrDeclarationIsForNativeCarPlayApp(declaration)) {
                    NSInteger allow = (NSInteger)CBAllowedPolicyValue();
                    CBLogFmt("[CBR]   -> forcing policy=%ld for %s", (long)allow, bid);
                    return allow;
                }
            }
        }
    } @catch(...) {}
    return orig;
}

- (NSInteger)effectivePolicyForAppDeclaration:(id)declaration inVehicleWithCertificateSerial:(id)serial {
    NSInteger orig = %orig;
    @try {
        id bidObj = cb(declaration, "bundleIdentifier");
        if (bidObj) {
            const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                sel_registerName("UTF8String"));
            if (bid) {
                CBLogFmt("[CBR] policy2(%s) orig=%ld", bid, (long)orig);
                if (CBIsEnabled(bid) && !cbrDeclarationIsForNativeCarPlayApp(declaration)) {
                    NSInteger allow = (NSInteger)CBAllowedPolicyValue();
                    CBLogFmt("[CBR]   -> forcing policy2=%ld for %s", (long)allow, bid);
                    return allow;
                }
            }
        }
    } @catch(...) {}
    return orig;
}

%end


// ── Phase 2: _setupIconModel — inject before icon model is built ──────────────
// Called from DBDashboardHomeViewController viewDidLoad when car connects.
// By this point the ObjC runtime is fully up and our const char* helpers work.
%hook DBDashboardHomeViewController

- (void)_setupIconModel {
    cbrCPProbeScenes();
    cbrCPProbeCarSceneGuts();
    CBLog("[CBR] _setupIconModel called");

    if (gLibraryPtr) {
        id lib = (__bridge id)gLibraryPtr;
        addCarplayDeclarations(lib);
        gLibraryPtr = NULL;
    } else {
        CBLog("[CBR] gLibraryPtr nil — trying self");
        id lib = cb(self, "applicationLibrary");
        if (!lib) lib = cb(self, "library");
        if (lib) addCarplayDeclarations(lib);
        else CBLog("[CBR] no library found");
    }

    %orig;
}

%end


// ── DBApplicationLaunchInfo — tap interception ────────────────────────────────
%hook DBApplicationLaunchInfo

+ (id)launchInfoForApplication:(id)appInfo withActivationSettings:(id)settings {
    BOOL handled = NO;
    @try {
        NSArray *tags = cb(appInfo, "tags");
        if (!tags) tags = getIvar(appInfo, "_tags");

        BOOL isOurs = NO;
        for (id tag in tags) {
            const char *t = ((const char*(*)(id,SEL))objc_msgSend)(tag,
                sel_registerName("UTF8String"));
            if (t && strcmp(t, "CarPlayEnable") == 0) { isOurs = YES; break; }
        }

        if (isOurs) {
            id bidObj = cb(appInfo, "bundleIdentifier");
            if (bidObj) {
                const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                    sel_registerName("UTF8String"));
                CBCarLogFmt("[CBR-CP] tap(launchInfo) -> %s", bid ?: "?");
                CBPostLaunch(bid);   // PROBE-ONLY v3.16.4: posts to SpringBoard scene-handle probe
                CBLogFmt("[CBR] Tapped bridged app: %s", bid ?: "?");
                // cbrCPRenderTest();  // placeholder disabled - no car-screen window this build
                handled = YES;
            }
        }
    } @catch(...) { handled = NO; }

    if (handled) return nil;
    return %orig;
}

%end


// ── DBIconView — long press ───────────────────────────────────────────────────
%hook DBIconView

- (void)didMoveToWindow {
    %orig;
    @try {
        NSArray *grs = [(UIView *)self gestureRecognizers];
        for (UIGestureRecognizer *g in grs)
            if ([g isKindOfClass:[UILongPressGestureRecognizer class]]) return;
        UILongPressGestureRecognizer *g = [[UILongPressGestureRecognizer alloc]
            initWithTarget:self action:@selector(cbLongPress:)];
        g.minimumPressDuration = 1.5;
        [(UIView *)self addGestureRecognizer:g];
    } @catch(...) {}
}

%new
- (void)cbLongPress:(UILongPressGestureRecognizer *)g {
    if (g.state != UIGestureRecognizerStateBegan) return;
    @try {
        id icon = cb(self, "icon");
        id bidObj = cb(icon, "applicationBundleID");
        if (!bidObj) return;
        const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
            sel_registerName("UTF8String"));
        CBCarLogFmt("[CBR-CP] tap(longpress) -> %s", bid ?: "?");
        CBPostLaunch(bid);
        CBLogFmt("[CBR] Long press: %s", bid ?: "?");
        CBOpenApp(bid);
    } @catch(...) {}
}

%end

%end  // group CARPLAY


%ctor {
    // PURE C — no ObjC whatsoever
    if (strcmp(__progname, "CarPlay") == 0) {
        unlink("/var/mobile/CBR_live.txt");
        gLogFD = open("/var/mobile/CBR_live.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666);
        %init(CARPLAY);
        const char msg[] = "[CBR] v3.17.1 init - probe scene-request construction\n";
        write(gLogFD, msg, sizeof(msg)-1);
        write(2, msg, sizeof(msg)-1);
    }
    else if (strcmp(__progname, "SpringBoard") == 0) {
        cbrSBRegisterListener();
    }
}

#pragma clang diagnostic pop
