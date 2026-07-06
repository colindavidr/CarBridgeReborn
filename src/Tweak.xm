#include <signal.h>
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
#import <dlfcn.h>
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

// v3.20.2: STRONG-hold every declaration we synthesize for the entire
// CarPlayApp process lifetime. object_setIvar into _carPlayDeclaration does
// NOT reliably take ownership of this ivar, so under ARC our local decl was
// freed at loop-scope end and the ivar dangled; CarPlay's async analytics
// (_DBAnalyticsAppInfo initWithBundleIdentifier:appDeclaration:policyEvaluator:)
// then retained a dead pointer and crash-looped the process. Keeping our own
// strong reference makes the object immortal so every later read is valid.
static NSMutableArray *gCBRDeclarations = nil;
// Associated-object key: also pins each declaration to its appInfo's lifetime.
static const void *kCBRDeclKey = &kCBRDeclKey;

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
            // v3.20.2: populate ALL 21 ivars so analytics can never dereference
            // an uninitialized field. cb1b/cb1 no-op safely if a setter is absent.
            // 17 BOOL support flags — all NO for a bridged (non-native) app:
            cb1b(decl, "setSystemApp:", NO);
            cb1b(decl, "setRequiresGeoSupport:", NO);
            cb1b(decl, "setLaunchUsingSiri:", NO);
            cb1b(decl, "setLaunchNotificationsUsingSiri:", NO);
            cb1b(decl, "setSupportsPlayableContent:", NO);
            cb1b(decl, "setSupportsMessaging:", NO);
            cb1b(decl, "setSupportsCalling:", NO);
            cb1b(decl, "setSupportsMaps:", NO);          // NO = normal icon path
            cb1b(decl, "setSupportsAudio:", NO);
            cb1b(decl, "setSupportsCommunication:", NO);
            cb1b(decl, "setSupportsTemplates:", NO);     // NO = not a template app
            cb1b(decl, "setSupportsCharging:", NO);
            cb1b(decl, "setSupportsParking:", NO);
            cb1b(decl, "setSupportsPublicSafety:", NO);
            cb1b(decl, "setSupportsQuickOrdering:", NO);
            cb1b(decl, "setSupportsFueling:", NO);
            cb1b(decl, "setSupportsDrivingTask:", NO);
            // 3 object fields — never leave nil for the analytics reader:
            cb1(decl, "setBundleIdentifier:", bidObj);
            id bundleURL = cb(appInfo, "bundleURL");
            id declPath = bundleURL ? cb(bundleURL, "path") : nil;
            cb1(decl, "setBundlePath:", declPath ?: @"");
            cb1(decl, "setAutoMakerProtocols:", [NSSet set]);  // was left nil before

            // v3.20.2 CRITICAL: take ownership BEFORE the ivar store so the
            // object cannot be freed when this scope ends (the crash-loop fix).
            if (!gCBRDeclarations) gCBRDeclarations = [[NSMutableArray alloc] init];
            [gCBRDeclarations addObject:decl];
            objc_setAssociatedObject(appInfo, kCBRDeclKey, decl,
                                     OBJC_ASSOCIATION_RETAIN_NONATOMIC);

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
static id gCBROverlayWindow = nil;  // v3.20.31: separate window for exit button
static NSString *gCBRLastBidStr = nil;  // v3.20.33: bid to terminate on exit
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
static id gCBRLastMgr = nil;  // last scene manager (for host activation)
// v3.17.1: discover how to CREATE (not just fetch) a scene handle. Logs the
// fetchOrCreate signature + candidate request classes so we build the request right.
// v3.17.2: dump SBApplicationSceneHandleRequest + SBApplicationSceneEntity init/setters,
// then ATTEMPT the create via fetchOrCreateApplicationSceneHandleForRequest:.
static id gCBRRealHandle = nil;
static void cbrSBDumpRequestClass(void) {
    static int done=0; if(done)return; done=1;
    int fd = open("/var/mobile/CBR_sb_reqclass.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define RD(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define RDF(...) do{ char _b[300]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    for (const char *cn : (const char*[]){"SBApplicationSceneHandleRequest","SBApplicationSceneEntity", NULL}) {
        if (!cn) break;
        Class dc = objc_getClass(cn);
        if (!dc){ RDF("%s MISSING\n", cn); continue; }
        RDF("== %s (init/setters) ==\n", cn);
        unsigned int mn=0; Method *m=class_copyMethodList(dc,&mn);
        for (unsigned int i=0;i<mn;i++){ const char*sn=sel_getName(method_getName(m[i]));
            if (strncmp(sn,"init",4)==0||strncmp(sn,"set",3)==0||strcasestr(sn,"request")||
                strcasestr(sn,"entity")||strcasestr(sn,"identity")||strcasestr(sn,"application"))
                RDF("   -%s\n", sn); }
        if(m)free(m);
        // class methods too (factory)
        Class mc = object_getClass(dc);
        unsigned int cn2=0; Method *cm=class_copyMethodList(mc,&cn2);
        for (unsigned int i=0;i<cn2;i++){ const char*sn=sel_getName(method_getName(cm[i]));
            if (strncmp(sn,"request",7)==0||strcasestr(sn,"entity")||strncmp(sn,"scene",5)==0)
                RDF("   +%s\n", sn); }
        if(cm)free(cm);
    }
    if(fd>=0)close(fd);
}
static void cbrSBProbeRequest(id mgr, id sbApp, id identity) {
    int fd = open("/var/mobile/CBR_sb_request.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define RQ(s) do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define RQF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    cbrSBDumpRequestClass();
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
        gCBRLastMgr = mgr;
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

        // Build the request via the factory that takes exactly what we have, then CREATE.
        id request = nil;
        @try {
            Class reqCls = objc_getClass("SBApplicationSceneHandleRequest");
            SEL fac = sel_registerName("defaultRequestForApplication:sceneIdentity:displayIdentity:");
            if (reqCls && [reqCls respondsToSelector:fac]) {
                request = ((id(*)(id,SEL,id,id,id))objc_msgSend)(reqCls, fac, sbApp, identity, dispIdentity);
            }
        } @catch (NSException *e) { CRF("buildRequest EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        CRF("request: %s\n", request ? class_getName(object_getClass(request)) : "nil");

        // fetchOrCreate: the CREATE call (makes the handle if it doesn't exist).
        @try {
            SEL fc = sel_registerName("fetchOrCreateApplicationSceneHandleForRequest:");
            if (request && [mgr respondsToSelector:fc])
                handle = ((id(*)(id,SEL,id))objc_msgSend)(mgr, fc, request);
        } @catch (NSException *e) { CRF("fetchOrCreate EXC: %s\n", [[e reason] UTF8String]?:"?"); }
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
// Host a live scene handle's view in a window on the CAR screen. Dismiss-on-timeout
// so it can't lock you out. This is the render step.
static id cbrGetCarplayCADisplay(void) {
    @try {
        Class avExt = objc_getClass("AVExternalDevice");
        id dev = avExt ? ((id(*)(id,SEL))objc_msgSend)(avExt, sel_registerName("currentCarPlayExternalDevice")) : nil;
        if (!dev) return nil;
        id screenIDs = ((id(*)(id,SEL))objc_msgSend)(dev, sel_registerName("screenIDs"));
        if (!screenIDs || [screenIDs count] == 0) return nil;
        NSString *uid = [screenIDs objectAtIndex:0];
        Class caDisp = objc_getClass("CADisplay");
        id displays = ((id(*)(id,SEL))objc_msgSend)(caDisp, sel_registerName("displays"));
        for (id d in displays) {
            id dUid = ((id(*)(id,SEL))objc_msgSend)(d, sel_registerName("uniqueId"));
            if ([uid isEqualToString:dUid]) return d;
        }
    } @catch (NSException *e) {}
    return nil;
}
static id gCBRRootWindow = nil;
static id gCBRAppVC = nil;
static id gCBRActiveTxns = nil;
static id gCBRTxn = nil;         // v3.19.5: strong-hold txn for safe completion
static NSMutableSet *gCBRKeepAlive = nil;  // v3.20.18: bundle IDs whose scenes must NOT be backgrounded while hosted on CarPlay
static void cbrSBHostDismiss(void) {
    @try {
        int fd=open("/var/mobile/CBR_sb_host.txt",O_WRONLY|O_CREAT|O_APPEND,0644);
        #define DD(m) do{ if(fd>=0){const char*_m=(m);write(fd,_m,strlen(_m));} }while(0)
        // v3.20.24: teardown-restore. Before we drop our window, put the app's scene view
        // back to normal LiveContent mode (0). Without this, the app's real scene is left
        // stuck in the grafted display mode 4 -> reopening shows a black screen until respring.
        // (Mirrors carplay-cast cleanupAfterCarplay, which CBR's dismiss previously omitted.)
        @try {
            if (gCBRAppVC) {
                id dvc = getIvar(gCBRAppVC, "_deviceAppViewController");
                id sv  = dvc ? getIvar(dvc, "_sceneView") : nil;
                if (!sv && [gCBRAppVC respondsToSelector:sel_registerName("appView")])
                    sv = ((id(*)(id,SEL))objc_msgSend)(gCBRAppVC, sel_registerName("appView"));
                if (sv) {
                    id animF = nil; Class savc = objc_getClass("SBApplicationSceneView");
                    SEL af = sel_registerName("defaultDisplayModeAnimationFactory");
                    if (savc && [(id)savc respondsToSelector:af]) animF = ((id(*)(id,SEL))objc_msgSend)((id)savc, af);
                    SEL sdm = sel_registerName("setDisplayMode:animationFactory:completion:");
                    if ([sv respondsToSelector:sdm]) {
                        ((void(*)(id,SEL,int,id,void*))objc_msgSend)(sv, sdm, 0, animF, NULL);  // 0 = normal LiveContent
                        DD("[restore] app scene view -> mode 0 (LiveContent)\n");
                    } else { DD("[restore] no setDisplayMode on scene view\n"); }
                } else { DD("[restore] no scene view to restore\n"); }
            } else { DD("[restore] no gCBRAppVC\n"); }
        } @catch(NSException *e) { DD("[restore] EXC\n"); }

        // v3.20.33: TERMINATE the app on exit instead of backgrounding it. Reopen then does a
        // FRESH LAUNCH, which renders reliably (proven on first-open) - re-hosting a backgrounded
        // app produced a perfect host log but BLACK screen (render server never re-bound). A killed
        // app also can't keep playing audio. So: exit = kill, reopen = fresh launch = renders + silent.
        @try {
            NSString *_bidStr = gCBRLastBidStr;  // stored at host time
            if (_bidStr) {
                Class acCls = objc_getClass("SBApplicationController");
                id ac = acCls ? ((id(*)(id,SEL))objc_msgSend)(acCls, sel_registerName("sharedInstance")) : nil;
                id app = ac ? ((id(*)(id,SEL,id))objc_msgSend)(ac, sel_registerName("applicationWithBundleIdentifier:"), _bidStr) : nil;
                if (app) {
                    // Prefer SBMainWorkspace/RunningBoard-style termination via the app process.
                    id proc = [app respondsToSelector:sel_registerName("process")] ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("process")) : nil;
                    BOOL killed = NO;
                    if (proc) {
                        for (const char *sel : (const char*[]){"terminateForReason:andReport:withDescription:", NULL}) { (void)sel; }
                        SEL tk = sel_registerName("terminateForReasonAndReportWithDescription:");
                        // Simpler: use the scene handle's application to request termination.
                    }
                    // Most reliable on 17: ask SBMainWorkspace to deactivate+terminate.
                    Class wsCls = objc_getClass("SBMainWorkspace");
                    id ws = wsCls ? ((id(*)(id,SEL))objc_msgSend)(wsCls, sel_registerName("sharedInstance")) : nil;
                    if (!ws && wsCls) ws = ((id(*)(id,SEL))objc_msgSend)(wsCls, sel_registerName("mainWorkspace"));
                    // Fallback path: kill the process by pid via the scene's clientProcess.
                    id sc = gCBRSceneHandle ? ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("sceneIfExists")) : nil;
                    id cp = sc && [sc respondsToSelector:sel_registerName("clientProcess")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("clientProcess")) : nil;
                    if (cp && [cp respondsToSelector:sel_registerName("pid")]) {
                        int pid = ((int(*)(id,SEL))objc_msgSend)(cp, sel_registerName("pid"));
                        if (pid > 0) { kill(pid, 9); killed = YES; DD("[exit] terminated app via SIGKILL to clientProcess pid\n"); }
                    }
                    if (!killed) DD("[exit] could not resolve pid to terminate\n");
                } else { DD("[exit] no SBApplication to terminate\n"); }
            } else { DD("[exit] no stored bid to terminate\n"); }
        } @catch(NSException *e) { DD("[exit] terminate EXC\n"); }

        if (gCBRRootWindow) { ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBRRootWindow, sel_registerName("setHidden:"), YES); }
        @try { if (gCBROverlayWindow) { ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBROverlayWindow, sel_registerName("setHidden:"), YES); gCBROverlayWindow = nil; } } @catch(...) {}
        gCBRRootWindow = nil; gCBRAppVC = nil; gCBRActiveTxns = nil;
        // v3.20.32: NOW release keep-alive (the .25 retain kept the app running -> audio continued +
        // left it in a half-state that black-screened on reopen). Releasing lets it suspend cleanly.
        @try { if (gCBRKeepAlive) [gCBRKeepAlive removeAllObjects]; } @catch(...) {}
        DD("[host] dismissed (backgrounded + keep-alive released)\n");
        if(fd>=0)close(fd);
        #undef DD
    } @catch(...) {}
}

// v3.20.23: target object for the CarPlay exit button (UIButton needs an ObjC target+selector).
@interface CBRExitTarget : NSObject
@end
@implementation CBRExitTarget
- (void)cbrExitTapped { cbrSBHostDismiss(); }
@end
static CBRExitTarget *gCBRExitTarget = nil;
// v3.19.2: REFERENCE PROBE v2 - three routes to a live app scene view.
static void cbrDumpViewTree(id v, int fd, int depth, int maxdepth) {
    if (!v || depth > maxdepth) return;
    @try {
        const char *cn = class_getName(object_getClass(v));
        CGRect fr = ((CGRect(*)(id,SEL))objc_msgSend)(v, sel_registerName("frame"));
        char pad[40]; int pn = depth*2 < 38 ? depth*2 : 38; for(int i=0;i<pn;i++) pad[i]=' '; pad[pn]='\0';
        char lb[320]; int ln = snprintf(lb, sizeof(lb), "%s- %s (%.0fx%.0f)\n", pad, cn, fr.size.width, fr.size.height);
        if (fd>=0) write(fd, lb, ln);
        id subs = ((id(*)(id,SEL))objc_msgSend)(v, sel_registerName("subviews"));
        if (subs) for (id s in subs) cbrDumpViewTree(s, fd, depth+1, maxdepth);
    } @catch(...) {}
}
// If a view (or any descendant) is an SBApplicationSceneView, dump its content container.
static int cbrFindAndDumpSceneView(id v, int fd, int depth) {
    if (!v || depth > 8) return 0;
    int found = 0;
    @try {
        const char *cn = class_getName(object_getClass(v));
        if (strstr(cn, "ApplicationSceneView") || strstr(cn, "DeviceApplicationSceneView")) {
            char hb[200]; int hn=snprintf(hb,sizeof(hb),"\n>>> LIVE sceneView in window tree: %s\n", cn); if(fd>=0)write(fd,hb,hn);
            @try { NSInteger dm=((NSInteger(*)(id,SEL))objc_msgSend)(v,sel_registerName("displayMode")); char b[80];int n=snprintf(b,sizeof(b),"    displayMode: %ld\n",(long)dm);if(fd>=0)write(fd,b,n);} @catch(...) {}
            id ccv = getIvar(v,"_sceneContentContainerView"); if(!ccv) ccv=getIvar(v,"_contentContainerView");
            char cb2[160]; int cn2=snprintf(cb2,sizeof(cb2),"    contentContainer: %s\n", ccv?class_getName(object_getClass(ccv)):"nil"); if(fd>=0)write(fd,cb2,cn2);
            if (ccv) { id cs=((id(*)(id,SEL))objc_msgSend)(ccv,sel_registerName("subviews")); char sb[80];int sn=snprintf(sb,sizeof(sb),"    container has %lu subviews:\n",cs?(unsigned long)[cs count]:0);if(fd>=0)write(fd,sb,sn);
                if(cs) for(id s in cs){ char eb[160];int en=snprintf(eb,sizeof(eb),"       * %s\n",class_getName(object_getClass(s)));if(fd>=0)write(fd,eb,en);} }
            if(fd>=0)write(fd,"    FULL TREE:\n",15);
            cbrDumpViewTree(v, fd, 2, 6);
            found = 1;
        }
        id subs = ((id(*)(id,SEL))objc_msgSend)(v, sel_registerName("subviews"));
        if (subs) for (id s in subs) { found += cbrFindAndDumpSceneView(s, fd, depth+1); if (found >= 2) break; }
    } @catch(...) {}
    return found;
}
static void cbrReferenceProbe(void) {
    int fd = open("/var/mobile/CBR_reference.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define RF(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define RFF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)

    // ROUTE 1: enumerate real class names for layout/switcher controllers.
    RF("==== ROUTE 1: class name discovery ====\n");
    @try {
        unsigned int n=0; Class *all=objc_copyClassList(&n);
        for(unsigned int i=0;i<n;i++){ const char*cn=class_getName(all[i]);
            if(strncmp(cn,"SB",2)==0 && (strstr(cn,"Layout")||strstr(cn,"Switcher")||strstr(cn,"SceneManager")) && (strstr(cn,"ViewController")||strstr(cn,"Manager")))
                RFF("  %s\n", cn); }
        if(all) free(all);
    } @catch(...) {}

    // ROUTE 2: frontmost app scene via scene manager.
    RF("\n==== ROUTE 2: frontmost scene via SBSceneManager ====\n");
    @try {
        Class smCls = objc_getClass("SBSceneManagerCoordinator"); id sm=nil;
        if(smCls && [smCls respondsToSelector:sel_registerName("sharedInstance")]) sm=((id(*)(id,SEL))objc_msgSend)(smCls,sel_registerName("sharedInstance"));
        RFF("  SBSceneManagerCoordinator: %s\n", sm?class_getName(object_getClass(sm)):"nil");
        // Also try main display scene manager directly.
        Class mdsm = objc_getClass("SBMainDisplaySceneManager");
        RFF("  SBMainDisplaySceneManager class: %s\n", mdsm?"EXISTS":"nil");
    } @catch(...) {}

    // ROUTE 3: brute-force walk all main-screen windows for a live scene view.
    RF("\n==== ROUTE 3: walk main-screen windows for live SBApplicationSceneView ====\n");
    @try {
        Class scr = objc_getClass("UIScreen");
        id mainScreen = ((id(*)(id,SEL))objc_msgSend)(scr, sel_registerName("mainScreen"));
        // Get windows via UIApplication.
        Class appCls = objc_getClass("UIApplication");
        id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
        id windows = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("windows")) : nil;
        RFF("  windows: %lu\n", windows?(unsigned long)[windows count]:0);
        int total = 0;
        if (windows) for (id w in windows) {
            @try {
                id ws = ((id(*)(id,SEL))objc_msgSend)(w, sel_registerName("screen"));
                if (ws != mainScreen) continue;   // main screen only
                total += cbrFindAndDumpSceneView(w, fd, 0);
                if (total >= 2) break;
            } @catch(...) {}
        }
        if (!total) RF("  no live SBApplicationSceneView found in any main-screen window\n");
    } @catch (NSException *e) { RFF("  ROUTE3 EXC: %s\n", [[e reason] UTF8String]?:"?"); }

    RF("==== END ====\n");
    if(fd>=0) close(fd);
}


static void cbrSBHostScene(const char *bid_cstr, id handle) {
    int fd = open("/var/mobile/CBR_sb_host.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define HH(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define HHF(...) do{ char _b[420]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    HH("==== HOST SCENE v3.18.0 (port) ====\n");
    if (!bid_cstr || !bid_cstr[0]) { HH("no bid\n"); if(fd>=0)close(fd); return; }
    if (!handle) { HH("no handle -> abort\n"); if(fd>=0)close(fd); return; }
    // v3.20.3: don't blind-toggle on a possibly-stale global. Tear down old window and
    // continue hosting the freshly-tapped app. Fixes "worked once, black after".
    if (gCBRRootWindow) { HH("was hosting -> dismiss old, re-host fresh\n"); cbrSBHostDismiss(); }
    HHF("bid: %s\n", bid_cstr);
        @try { gCBRLastBidStr = [NSString stringWithUTF8String:bid_cstr]; } @catch(...) {}
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];
        Class acCls = objc_getClass("SBApplicationController");
        id ac = ((id(*)(id,SEL))objc_msgSend)(acCls, sel_registerName("sharedInstance"));
        id application = ((id(*)(id,SEL,id))objc_msgSend)(ac, sel_registerName("applicationWithBundleIdentifier:"), bid);
        HHF("application: %s\n", application ? class_getName(object_getClass(application)) : "nil");
        if (!application) { HH("no application -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        // v3.20.18: mark this app keep-alive so the FBScene/lock hooks refuse to
        // background its scene while it is hosted on CarPlay (fixes the brief-death).
        @try { if (!gCBRKeepAlive) gCBRKeepAlive = [[NSMutableSet alloc] init]; [gCBRKeepAlive addObject:bid]; HH("marked keep-alive\n"); } @catch(...) {}
        id caDisplay = cbrGetCarplayCADisplay();
        HHF("carplay CADisplay: %s\n", caDisplay ? class_getName(object_getClass(caDisplay)) : "nil");
        if (!caDisplay) { HH("no carplay CADisplay -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        Class fbsCfgCls = objc_getClass("FBSDisplayConfiguration");
        id dispCfg = ((id(*)(id,SEL,id,BOOL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(fbsCfgCls, sel_registerName("alloc")), sel_registerName("initWithCADisplay:isMainDisplay:"), caDisplay, NO);
        HHF("displayConfiguration: %s\n", dispCfg ? class_getName(object_getClass(dispCfg)) : "nil");
        if (!dispCfg) { HH("no displayConfiguration -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        Class rootWinCls = objc_getClass("UIRootSceneWindow");
        id rootWindow = ((id(*)(id,SEL,id))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(rootWinCls, sel_registerName("alloc")), sel_registerName("initWithDisplayConfiguration:"), dispCfg);
        HHF("rootWindow: %s\n", rootWindow ? class_getName(object_getClass(rootWindow)) : "nil");
        if (!rootWindow) { HH("no rootWindow -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        gCBRRootWindow = rootWindow;
        @try { id layer = cb(rootWindow, "layer"); ((void(*)(id,SEL,CGFloat))objc_msgSend)(layer, sel_registerName("setCornerRadius:"), (CGFloat)13.0); ((void(*)(id,SEL,BOOL))objc_msgSend)(layer, sel_registerName("setMasksToBounds:"), YES); } @catch(...) {}
        // v3.20.26: force the WINDOW itself to landscape (orientation 3); scene orientation
        // alone leaves it portrait on auto-launch. Guarded + logged for iOS 17.
        @try {
            SEL _rot = sel_registerName("_rotateWindowToOrientation:updateStatusBar:duration:skipCallbacks:");
            if ([rootWindow respondsToSelector:_rot]) {
                ((void(*)(id,SEL,int,int,int,int))objc_msgSend)(rootWindow, _rot, 3, 1, 0, 0);
                HH("window rotated to landscape via _rotateWindowToOrientation:3\n");
            } else {
                HH("_rotateWindowToOrientation: NOT on iOS 17 - need fallback\n");
            }
        } @catch(...) { HH("window rotate threw\n"); }
        Class entCls = objc_getClass("SBDeviceApplicationSceneEntity");
        id appSceneEntity = ((id(*)(id,SEL,id))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(entCls, sel_registerName("alloc")), sel_registerName("initWithApplicationSceneHandle:"), handle);
        HHF("appSceneEntity: %s\n", appSceneEntity ? class_getName(object_getClass(appSceneEntity)) : "nil");
        if (!appSceneEntity) { HH("no entity -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        Class avcCls = objc_getClass("SBAppViewController");
        id appVC = ((id(*)(id,SEL,id,id))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(avcCls, sel_registerName("alloc")), sel_registerName("initWithIdentifier:andApplicationSceneEntity:"), bid, appSceneEntity);
        HHF("appViewController: %s\n", appVC ? class_getName(object_getClass(appVC)) : "nil");
        if (!appVC) { HH("no appVC -> abort\n"); HH("==== END ====\n"); if(fd>=0)close(fd); return; }
        gCBRAppVC = appVC;
        @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(appVC, sel_registerName("setIgnoresOcclusions:"), NO); } @catch(...) {}
        @try { Ivar mIv = class_getInstanceVariable(object_getClass(appVC), "_currentMode"); if (mIv) object_setIvar(appVC, mIv, @(2)); } @catch(...) {}
        @try { id actSettings = getIvar(appVC, "_activationSettings"); if (actSettings) ((void(*)(id,SEL))objc_msgSend)(actSettings, sel_registerName("clearActivationSettings")); } @catch(...) {}
        @try {
            CGRect wf = ((CGRect(*)(id,SEL))objc_msgSend)(rootWindow, sel_registerName("frame"));
            Class UIViewCls = objc_getClass("UIView");
            id container = ((id(*)(id,SEL,CGRect))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(UIViewCls, sel_registerName("alloc")), sel_registerName("initWithFrame:"), wf);
            id clear = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
            ((void(*)(id,SEL,id))objc_msgSend)(container, sel_registerName("setBackgroundColor:"), clear);
            ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("addSubview:"), container);
            id vcView = cb(appVC, "view");
            ((void(*)(id,SEL,CGRect))objc_msgSend)(vcView, sel_registerName("setFrame:"), wf);
            ((void(*)(id,SEL,id))objc_msgSend)(container, sel_registerName("addSubview:"), vcView);
            HH("mounted appVC.view\n");
        } @catch (NSException *e) { HHF("mount EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        // --- v3.18.3: drive the transaction EXACTLY like the source ---
        @try {
            SEL mkTxn = sel_registerName("_createSceneUpdateTransactionForApplicationSceneEntity:deliveringActions:");
            if ([appVC respondsToSelector:mkTxn]) {
                id txn = ((id(*)(id,SEL,id,BOOL))objc_msgSend)(appVC, mkTxn, appSceneEntity, YES);
                HHF("sceneUpdateTransaction: %s\n", txn ? class_getName(object_getClass(txn)) : "nil");
                if (txn) {
                    id activeTxns = getIvar(appVC, "_activeTransitions");
                    HHF("_activeTransitions: %s\n", activeTxns ? class_getName(object_getClass(activeTxns)) : "nil");
                    gCBRActiveTxns = activeTxns;
                    // v3.19.5: NO __block object captures (they dangle -> objc_retain segfault
                    // in BSTransaction _noteCompleted). Hold strongly in globals set before begin,
                    // read them back inside the block, null-check everything.
                    gCBRTxn = txn; gCBRAppVC = appVC; gCBRSceneHandle = handle;
                    void (^completion)(int) = ^(int arg1) {
                        id bAppVC = gCBRAppVC; id bHandle = gCBRSceneHandle; id bTxn = gCBRTxn;
                        if (!bAppVC || !bHandle) { int _cf=open("/var/mobile/CBR_sb_host.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_cf>=0){const char*m="completion: globals nil, bailing safely\n";write(_cf,m,strlen(m));close(_cf);} return; }
                        int cfd = open("/var/mobile/CBR_sb_host.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
                        #define CH(s) do{ if(cfd>=0) write(cfd,(s),strlen(s)); }while(0)
                        #define CHF(...) do{ char _b[400]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(cfd>=0)write(cfd,_b,_n);}while(0)
                        CH("---- txn COMPLETION fired ----\n");
                        @try {
                            id at = getIvar(bAppVC, "_activeTransitions");
                            if (at && bTxn) ((void(*)(id,SEL,id))objc_msgSend)(at, sel_registerName("removeObject:"), bTxn);
                        } @catch(...) {}
                        @try {
                            id scn = ((id(*)(id,SEL))objc_msgSend)(bHandle, sel_registerName("sceneIfExists"));
                            CHF("scene in completion: %s\n", scn ? class_getName(object_getClass(scn)) : "STILL nil");
                            if (scn) {
                                // Dump FBScene settings methods once so we use the right one.
                                static int fbd=0;
                                if(!fbd){ fbd=1; int df=open("/var/mobile/CBR_fbscene.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
                                    Class sc=object_getClass(scn); int d=0;
                                    while(sc && strcmp(class_getName(sc),"NSObject")!=0 && d<4){ unsigned int n=0; Method *m=class_copyMethodList(sc,&n);
                                        for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i]));
                                            if(strcasestr(sn,"setting")||strcasestr(sn,"update")||strcasestr(sn,"foreground")||strcasestr(sn,"activat")){ char lb[200]; int ln=snprintf(lb,sizeof(lb),"-%s\n",sn); if(df>=0)write(df,lb,ln);} }
                                        if(m)free(m); sc=class_getSuperclass(sc); d++; }
                                    if(df>=0)close(df); }
                                // Update scene settings via the scene's updateSettings:withTransitionContext: using a settings-diff block.
                                @try {
                                    SEL updBlk = sel_registerName("updateSettingsWithBlock:");
                                    if ([scn respondsToSelector:updBlk]) {
                                        void (^diff)(id) = ^(id mutableSettings) {
                                            @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(mutableSettings, sel_registerName("setForeground:"), YES); } @catch(...) {}
                                            @try { ((void(*)(id,SEL,NSInteger))objc_msgSend)(mutableSettings, sel_registerName("setInterfaceOrientation:"), (NSInteger)3); } @catch(...) {}
                                            @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(mutableSettings, sel_registerName("setDeactivated:"), NO); } @catch(...) {}
                                            // [FIX-CRS] v3.20.28: content reference size = the CAR's size (dynamic per vehicle),
                                            // so the app re-lays-out for the real display instead of stretching a phone-sized render.
                                            @try {
                                                CGRect _cwb = gCBRRootWindow ? ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds")) : CGRectZero;
                                                if (_cwb.size.width > 0 && _cwb.size.height > 0) {
                                                    // v3.20.32: setFrame/orientation-lock REMOVED - the car bounds came back
                                                    // portrait (281x472) so setFrame made the app render phone-portrait (stretch bug).
                                                    // Window rotation alone handled orientation correctly in earlier builds.

                                                    SEL _crs = sel_registerName("setContentReferenceSize:withInterfaceOrientation:");
                                                    if (0 && [mutableSettings respondsToSelector:_crs]) {
                                                        CHF("[FIX-CRS] (dead)\n");
                                                    } else {
                                                        SEL _crs2 = sel_registerName("setContentReferenceSize:");
                                                        if ([mutableSettings respondsToSelector:_crs2]) { ((void(*)(id,SEL,CGSize))objc_msgSend)(mutableSettings, _crs2, _cwb.size); CH("[FIX-CRS] setContentReferenceSize (no-orient) applied\n"); }
                                                        else {
                                                            CH("[FIX-CRS] NO setContentReferenceSize - dumping settings methods\n");
                                                            // v3.20.29: dump the settings object's ACTUAL methods to find the iOS17 selector.
                                                            static int _sd=0;
                                                            if(!_sd){ _sd=1; int df2=open("/var/mobile/CBR_settings.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
                                                                if(df2>=0){ const char *cn=class_getName(object_getClass(mutableSettings)); char hb[128]; int hl=snprintf(hb,sizeof(hb),"SETTINGS CLASS: %s\n",cn); write(df2,hb,hl); }
                                                                Class _sc=object_getClass(mutableSettings); int _d=0;
                                                                while(_sc && strcmp(class_getName(_sc),"NSObject")!=0 && _d<4){ unsigned int _n=0; Method *_m=class_copyMethodList(_sc,&_n);
                                                                    for(unsigned int _i=0;_i<_n;_i++){ const char*_sn=sel_getName(method_getName(_m[_i]));
                                                                        if(strncmp(_sn,"set",3)==0 && (strcasestr(_sn,"size")||strcasestr(_sn,"reference")||strcasestr(_sn,"content")||strcasestr(_sn,"bound")||strcasestr(_sn,"frame")||strcasestr(_sn,"canvas")||strcasestr(_sn,"scale"))){ char lb[200]; int ln=snprintf(lb,sizeof(lb),"-%s\n",_sn); if(df2>=0)write(df2,lb,ln);} }
                                                                    if(_m)free(_m); _sc=class_getSuperclass(_sc); _d++; }
                                                                if(df2>=0)close(df2); }
                                                        }
                                                    }
                                                } else { CH("[FIX-CRS] car window bounds zero - skipped\n"); }
                                            } @catch(...) { CH("[FIX-CRS] threw\n"); }
                                        };
                                        ((void(*)(id,SEL,id))objc_msgSend)(scn, updBlk, diff);
                                        CH("scene updateSettingsWithBlock: applied (fg+landscape)\n");
                                // v3.20.12: RE-DRIVE the mode-4 render HERE, where the scene is
                                // confirmed LIVE. The sync render ran when sceneIfExists was nil
                                // (racing the async scene creation and losing). This runs the render
                                // trigger against the now-existing scene - the fix for "worked once, lost the race after".
                                @try {
                                    // v3.20.13: ensure the scene view controller exists FIRST, so appView is
                                    // non-nil regardless of sync/async completion ordering (warm boot ran
                                    // completion before the sync _createSceneViewController -> appView was nil).
                                    @try {
                                        SEL rdCsvc = sel_registerName("_createSceneViewController");
                                        if ([bAppVC respondsToSelector:rdCsvc]) { ((void(*)(id,SEL))objc_msgSend)(bAppVC, rdCsvc); CH("REDRIVE(comp) ensured scene view controller\n"); }
                                    } @catch(...) {}
                                    id rdAppView = [bAppVC respondsToSelector:sel_registerName("appView")] ? ((id(*)(id,SEL))objc_msgSend)(bAppVC, sel_registerName("appView")) : nil;
                                    CHF("REDRIVE(comp) appView: %s\n", rdAppView ? class_getName(object_getClass(rdAppView)) : "nil");
                                    if (rdAppView) {
                                        id rdAnim = nil;
                                        Class rdSavc = objc_getClass("SBApplicationSceneView");
                                        SEL rdAf = sel_registerName("defaultDisplayModeAnimationFactory");
                                        if (rdSavc && [rdSavc respondsToSelector:rdAf]) rdAnim = ((id(*)(id,SEL))objc_msgSend)(rdSavc, rdAf);
                                        SEL rdSdm = sel_registerName("setDisplayMode:animationFactory:completion:");
                                        if ([rdAppView respondsToSelector:rdSdm]) {
                                            // bounce 0 -> 4 to force a rebind against the live scene
                                            @try { ((void(*)(id,SEL,int,id,void*))objc_msgSend)(rdAppView, rdSdm, 0, rdAnim, NULL); } @catch(...) {}
                                            ((void(*)(id,SEL,int,id,void*))objc_msgSend)(rdAppView, rdSdm, 4, rdAnim, NULL);
                                            CH("REDRIVE(comp) setDisplayMode 0->4 applied against LIVE scene\n");
                                        } else { CH("REDRIVE(comp) MISSING setDisplayMode\n"); }
                                    }
                                    // size the live scene view to the car window
                                    id rdDvc = getIvar(bAppVC, "_deviceAppViewController");
                                    id rdSv = rdDvc ? getIvar(rdDvc, "_sceneView") : nil;
                                    if (rdSv && gCBRRootWindow) {
                                        CGRect wf = ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds"));
                                        ((void(*)(id,SEL,CGRect))objc_msgSend)(rdSv, sel_registerName("setFrame:"), CGRectMake(0,0,wf.size.width,wf.size.height));
                                        CH("REDRIVE(comp) sized live sceneView to car window\n");
                                    }
                                } @catch (NSException *e) { CHF("REDRIVE(comp) EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                                    } else {
                                        CH("no updateSettingsWithBlock: - see CBR_fbscene.txt\n");
                                    }
                                } @catch (NSException *e) { CHF("updateSettingsWithBlock EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                            }
                            // Try to activate the scene onscreen (stronger than settings).
                            /* activate: removed v3.18.8 - traps SpringBoard mid-completion */
                            // Scene is live + foregrounded. Show the window UNCONDITIONALLY. The old show was
                            // gated behind finding sv/sv2, which stays nil every run - so the window never
                            // actually appeared. The scene view is a subview of appVC.view once the scene
                            // connects, so showing the window + sizing appVC.view should reveal the app.
                            if (gCBRRootWindow) {
                                CGRect wb = ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds"));
                                @try { id av = cb(bAppVC, "view"); if (av) ((void(*)(id,SEL,CGRect))objc_msgSend)(av, sel_registerName("setFrame:"), CGRectMake(0,0,wb.size.width,wb.size.height)); } @catch(...) {}
                                ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBRRootWindow, sel_registerName("setHidden:"), NO);
                                ((void(*)(id,SEL,double))objc_msgSend)(gCBRRootWindow, sel_registerName("setAlpha:"), (double)1.0);
                                CH("window shown + appVC sized (forced)\n");
                            }
                        } @catch (NSException *e) { CHF("completion EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                        CH("---- end completion ----\n");
                        if(cfd>=0) close(cfd);
                    };
                    @try { ((void(*)(id,SEL,id))objc_msgSend)(txn, sel_registerName("setCompletionBlock:"), completion); HH("completion block set\n"); }
                    @catch (NSException *e) { HHF("setCompletionBlock EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                    @try { if (activeTxns) ((void(*)(id,SEL,id))objc_msgSend)(activeTxns, sel_registerName("addObject:"), txn); HH("added to _activeTransitions\n"); } @catch(...) {}
                    @try { ((void(*)(id,SEL))objc_msgSend)(txn, sel_registerName("begin")); HH("txn begin called\n"); }
                    @catch (NSException *e) { HHF("txn begin EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    /* ---- v3.18.8: render the carplay-cast way: _createSceneViewController + appView setDisplayMode:4 ---- */
    @try {
        @try { [appVC setValue:@2 forKey:@"_currentMode"]; HH("set _currentMode=2\n"); } @catch(...) {}
        @try { id _as = getIvar(appVC, "_activationSettings"); if(_as){ ((void(*)(id,SEL))objc_msgSend)(_as, sel_registerName("clearActivationSettings")); HH("cleared activationSettings\n"); } } @catch(...) {}
        @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(appVC, sel_registerName("setIgnoresOcclusions:"), NO); } @catch(...) {}

        SEL _csvc = sel_registerName("_createSceneViewController");
        if ([appVC respondsToSelector:_csvc]) { ((void(*)(id,SEL))objc_msgSend)(appVC, _csvc); HH("_createSceneViewController called\n"); }
        else { HH("MISSING _createSceneViewController\n"); }

        id _animF = nil;
        Class _savc = objc_getClass("SBApplicationSceneView");
        SEL _afSel = sel_registerName("defaultDisplayModeAnimationFactory");
        if (_savc && [_savc respondsToSelector:_afSel]) _animF = ((id(*)(id,SEL))objc_msgSend)(_savc, _afSel);
        HHF("animationFactory: %s\n", _animF ? class_getName(object_getClass(_animF)) : "nil");

        SEL _avSel = sel_registerName("appView");
        id _appView = [appVC respondsToSelector:_avSel] ? ((id(*)(id,SEL))objc_msgSend)(appVC, _avSel) : nil;
        HHF("appView: %s\n", _appView ? class_getName(object_getClass(_appView)) : "nil (MISSING appView)");

        if (_appView) {
            SEL _sdm = sel_registerName("setDisplayMode:animationFactory:completion:");
            if ([_appView respondsToSelector:_sdm]) { ((void(*)(id,SEL,int,id,void*))objc_msgSend)(_appView, _sdm, 4, _animF, NULL); HH("appView setDisplayMode:4 applied (LIVE CONTENT)\n"); }
            else { HH("MISSING setDisplayMode:animationFactory:completion:\n"); }
        }

        @try { id _v = ((id(*)(id,SEL))objc_msgSend)(appVC, sel_registerName("view")); if(_v){ Class _uic=objc_getClass("UIColor"); id _clr=((id(*)(id,SEL))objc_msgSend)(_uic, sel_registerName("clearColor")); ((void(*)(id,SEL,id))objc_msgSend)(_v, sel_registerName("setBackgroundColor:"), _clr); } } @catch(...) {}

        if (gCBRRootWindow) {
            ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBRRootWindow, sel_registerName("setHidden:"), NO);
            ((void(*)(id,SEL,double))objc_msgSend)(gCBRRootWindow, sel_registerName("setAlpha:"), (double)1.0);
            HH("window shown\n");
        }

        @try { id _dvc = getIvar(appVC, "_deviceAppViewController"); id _sv = _dvc ? getIvar(_dvc, "_sceneView") : nil; HHF("POST _sceneView: %s\n", _sv ? class_getName(object_getClass(_sv)) : "STILL nil"); } @catch(...) {}
    } @catch (NSException *e) { HHF("render-live EXC: %s\n", [[e reason] UTF8String] ?: "?"); }
    /* ---- end v3.18.8 render ---- */
                }
            } else { HH("appVC has no _createSceneUpdateTransaction -> cannot launch\n"); }
        } @catch (NSException *e) { HHF("transaction EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        // --- v3.18.1: unblank + foreground + orientation (from carplay-cast source) ---
        @try {
            // Unblank the display (source: required for video/animation to render).
            void *bks = dlsym(RTLD_DEFAULT, "BKSDisplayServicesSetScreenBlanked");
            if (bks) { ((void(*)(int))bks)(0); HH("BKSDisplayServicesSetScreenBlanked(0)\n"); }
            else HH("BKS symbol not found (continuing)\n");
        } @catch(...) {}
        // Force the scene to foreground so it actually renders.
        @try {
            id sceneNow = ((id(*)(id,SEL))objc_msgSend)(handle, sel_registerName("sceneIfExists"));
            HHF("sceneIfExists: %s\n", sceneNow ? class_getName(object_getClass(sceneNow)) : "nil");
            if (sceneNow) {
                // v3.20.25 foreground-via-block: FBScene has no mutableSettings on iOS 17 (it
                // threw every time). Use updateSettingsWithBlock: (the working API) to foreground
                // the scene on reopen, so the app's scene actually presents instead of black.
                SEL _ub = sel_registerName("updateSettingsWithBlock:");
                if ([sceneNow respondsToSelector:_ub]) {
                    void (^_fgb)(id) = ^(id ms){
                        @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(ms, sel_registerName("setForeground:"), YES); } @catch(...) {}
                        @try { ((void(*)(id,SEL,NSInteger))objc_msgSend)(ms, sel_registerName("setInterfaceOrientation:"), (NSInteger)3); } @catch(...) {}
                        @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(ms, sel_registerName("setDeactivated:"), NO); } @catch(...) {}
                    };
                    @try { ((void(*)(id,SEL,id))objc_msgSend)(sceneNow, _ub, _fgb); HH("reopen foreground via updateSettingsWithBlock applied\n"); } @catch(...) { HH("reopen fg block EXC\n"); }
                }
                id mset = nil;
                if (0) {   // dead: old mutableSettings path disabled
                    @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(mset, sel_registerName("setForeground:"), YES); } @catch(...) {}
                    @try { ((void(*)(id,SEL,NSInteger))objc_msgSend)(mset, sel_registerName("setInterfaceOrientation:"), (NSInteger)3); } @catch(...) {}
                    @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(mset, sel_registerName("setDeactivated:"), NO); } @catch(...) {}
                    // apply the mutated settings back onto the scene.
                    @try {
                        SEL upd = sel_registerName("updateSettings:");
                        if ([sceneNow respondsToSelector:upd]) { ((void(*)(id,SEL,id))objc_msgSend)(sceneNow, upd, mset); HH("scene settings updated (fg+landscape)\n"); }
                    } @catch (NSException *e) { HHF("updateSettings EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                }
            }
        } @catch (NSException *e) { HHF("foreground EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        // Force the app VC view + scene content container to fill the car screen.
        @try {
            id devVC = getIvar(appVC, "_deviceAppViewController");
            id sceneView = devVC ? getIvar(devVC, "_sceneView") : nil;
            HHF("appVC._deviceAppViewController._sceneView: %s\n", sceneView ? class_getName(object_getClass(sceneView)) : "nil");
            if (sceneView) {
                CGRect wf = ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("frame"));
                ((void(*)(id,SEL,CGRect))objc_msgSend)(sceneView, sel_registerName("setFrame:"), CGRectMake(0,0,wf.size.width,wf.size.height));
                HH("forced sceneView frame to full car screen\n");
            }
        } @catch (NSException *e) { HHF("sceneView frame EXC: %s\n", [[e reason] UTF8String]?:"?"); }

        @try { ((void(*)(id,SEL,double))objc_msgSend)(rootWindow, sel_registerName("setAlpha:"), (double)1.0); ((void(*)(id,SEL,BOOL))objc_msgSend)(rootWindow, sel_registerName("setHidden:"), NO); } @catch(...) {}
        // [FIX-CHROME] v3.20.28: probe CarPlay's window topology on this display + attempt to
        // let the stock chrome (sidebar/home button) show by lowering our window below it.
        // Logs levels/frames so we can tune precisely if the sidebar still doesn't appear.
        @try {
            int cf = open("/var/mobile/CBR_chrome.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
            #define CF(...) do{ char _b[300]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(cf>=0)write(cf,_b,_n);}while(0)
            CF("==== CHROME PROBE (car display window topology) ====\n");
            // our window's current level
            @try { double myLvl = ((double(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("windowLevel")); CF("our UIRootSceneWindow level = %.1f\n", myLvl); } @catch(...) {}
            // enumerate all windows on the same UIScreen as our car window
            @try {
                id ourScreen = [gCBRRootWindow respondsToSelector:sel_registerName("screen")] ? ((id(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("screen")) : nil;
                Class uiapp = objc_getClass("UIApplication");
                id app = ((id(*)(id,SEL))objc_msgSend)(uiapp, sel_registerName("sharedApplication"));
                id wins = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("windows")) : nil;
                unsigned long wc = wins && [wins respondsToSelector:sel_registerName("count")] ? (unsigned long)[wins count] : 0;
                CF("UIApplication.windows count = %lu\n", wc);
                if (wins) for (id w in wins) {
                    @try {
                        id ws = [w respondsToSelector:sel_registerName("screen")] ? ((id(*)(id,SEL))objc_msgSend)(w, sel_registerName("screen")) : nil;
                        int sameScr = (ws == ourScreen) ? 1 : 0;
                        double lvl = ((double(*)(id,SEL))objc_msgSend)(w, sel_registerName("windowLevel"));
                        CGRect wfr = ((CGRect(*)(id,SEL))objc_msgSend)(w, sel_registerName("frame"));
                        int hid = ((BOOL(*)(id,SEL))objc_msgSend)(w, sel_registerName("isHidden"));
                        CF("  win %s sameScreen=%d level=%.1f hidden=%d frame=%.0f,%.0f %.0fx%.0f\n",
                           class_getName(object_getClass(w)), sameScr, lvl, hid, wfr.origin.x, wfr.origin.y, wfr.size.width, wfr.size.height);
                    } @catch(...) {}
                }
            } @catch(...) { CF("window enum threw\n"); }
            // ATTEMPT: lower our window level so CarPlay chrome (if it's a higher-level window) shows on top.
            // v3.20.29: REVERTED level-1.0 - it broke taps and can't reveal chrome anyway
            // (CarPlay chrome is in the CarPlayApp process on a screen SpringBoard can't enumerate).
            CF("NOTE: level change reverted - chrome unreachable from SpringBoard side\n");
            CF("==== END ====\n");
            if(cf>=0)close(cf);
            #undef CF
        } @catch(...) {}

        // v3.20.23: exit/home button so the user can return to the CarPlay dashboard.
        // NOTE: kept for now as a fallback. If stock chrome shows after the level change, we remove it next build.
        @try {
            if (!gCBRExitTarget) gCBRExitTarget = [[CBRExitTarget alloc] init];
            Class _btnCls = objc_getClass("UIButton");
            id _exit = ((id(*)(id,SEL,long))objc_msgSend)(_btnCls, sel_registerName("buttonWithType:"), (long)1);
            if (_exit) {
                ((void(*)(id,SEL,CGRect))objc_msgSend)(_exit, sel_registerName("setFrame:"), CGRectMake(18, 18, 92, 44));
                ((void(*)(id,SEL,id,long))objc_msgSend)(_exit, sel_registerName("setTitle:forState:"), @"Exit", (long)0);
                Class _uic = objc_getClass("UIColor");
                id _wht = ((id(*)(id,SEL))objc_msgSend)(_uic, sel_registerName("whiteColor"));
                ((void(*)(id,SEL,id,long))objc_msgSend)(_exit, sel_registerName("setTitleColor:forState:"), _wht, (long)0);
                id _bg = ((id(*)(id,SEL,CGFloat,CGFloat))objc_msgSend)(_uic, sel_registerName("colorWithWhite:alpha:"), (CGFloat)0.0, (CGFloat)0.55);
                ((void(*)(id,SEL,id))objc_msgSend)(_exit, sel_registerName("setBackgroundColor:"), _bg);
                id _blayer = ((id(*)(id,SEL))objc_msgSend)(_exit, sel_registerName("layer"));
                if (_blayer) ((void(*)(id,SEL,CGFloat))objc_msgSend)(_blayer, sel_registerName("setCornerRadius:"), (CGFloat)10.0);
                ((void(*)(id,SEL,id,SEL,unsigned long))objc_msgSend)(_exit, sel_registerName("addTarget:action:forControlEvents:"), gCBRExitTarget, sel_registerName("cbrExitTapped"), (unsigned long)(1UL<<6));
                // v3.20.31: add the exit button to a SEPARATE overlay window at a HIGHER level than
                // the scene view, so the app's full-screen scene view can't swallow its taps (the reason
                // Exit didn't work - it was under the scene view in the same window).
                @try {
                    Class _winCls = objc_getClass("UIRootSceneWindow");
                    id _ovl = ((id(*)(id,SEL,id))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(_winCls, sel_registerName("alloc")), sel_registerName("initWithDisplayConfiguration:"), dispCfg);
                    if (_ovl) {
                        gCBROverlayWindow = _ovl;
                        ((void(*)(id,SEL,double))objc_msgSend)(_ovl, sel_registerName("setWindowLevel:"), (double)100.0);
                        id _clear = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
                        ((void(*)(id,SEL,id))objc_msgSend)(_ovl, sel_registerName("setBackgroundColor:"), _clear);
                        // host the button in a passthrough container so only the button area is touchable
                        ((void(*)(id,SEL,id))objc_msgSend)(_ovl, sel_registerName("addSubview:"), _exit);
                        ((void(*)(id,SEL,BOOL))objc_msgSend)(_ovl, sel_registerName("setHidden:"), NO);
                        ((void(*)(id,SEL))objc_msgSend)(_ovl, sel_registerName("makeKeyAndVisible"));
                        HH("exit button in separate overlay window (level 100)\n");
                    } else {
                        ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("addSubview:"), _exit);
                        HH("overlay window failed - exit button on root window (may be covered)\n");
                    }
                } @catch(...) { ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("addSubview:"), _exit); }
                ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("bringSubviewToFront:"), _exit);
                HH("exit button added\n");
            }
        } @catch(...) { HH("exit button failed\n"); }
        // --- v3.18.2: the scene is created ASYNC after launch. Re-run foreground +
        //     sceneView grab on a delay so the scene actually exists. ---
        // v3.20.7: delayed diagnostic pass REMOVED - it walked live scene client/subtree
        // objects and caused objc_retain safe-mode crashes. Rendering work is done synchronously above.

        // v3.20.16: TEARDOWN POLL - sample scene-view state every 0.5s for 20s so we can
        // SEE what tears the render down (it renders briefly then dies). Reads only safe
        // properties - no live-render-object walking (that crashed before).
        for (int _pi = 1; _pi <= 40; _pi++) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(_pi * 0.5 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
                int pf = open("/var/mobile/CBR_teardown.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
                #define PF(...) do{ char _b[300]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(pf>=0)write(pf,_b,_n);}while(0)
                @try {
                    double t = _pi * 0.5;
                    // scene still exists on the handle?
                    id sc = gCBRSceneHandle ? ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("sceneIfExists")) : nil;
                    // scene view state
                    id dvc = gCBRAppVC ? getIvar(gCBRAppVC, "_deviceAppViewController") : nil;
                    id sv = dvc ? getIvar(dvc, "_sceneView") : nil;
                    int svHidden = -1; double svAlpha = -1; int hasSuper = -1; int dispMode = -1;
                    if (sv) {
                        @try { svHidden = ((BOOL(*)(id,SEL))objc_msgSend)(sv, sel_registerName("isHidden")); } @catch(...) {}
                        @try { svAlpha = ((double(*)(id,SEL))objc_msgSend)(sv, sel_registerName("alpha")); } @catch(...) {}
                        @try { id spv = ((id(*)(id,SEL))objc_msgSend)(sv, sel_registerName("superview")); hasSuper = spv ? 1 : 0; } @catch(...) {}
                        @try { dispMode = (int)((NSInteger(*)(id,SEL))objc_msgSend)(sv, sel_registerName("displayMode")); } @catch(...) {}
                    }
                    // window state
                    int winHidden = -1;
                    if (gCBRRootWindow) { @try { winHidden = ((BOOL(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("isHidden")); } @catch(...) {} }
                    PF("t=%.1fs scene=%s sv=%s svHidden=%d svAlpha=%.2f svSuper=%d dispMode=%d winHidden=%d\n",
                       t, sc?"LIVE":"GONE", sv?"yes":"NIL", svHidden, svAlpha, hasSuper, dispMode, winHidden);
                    // v3.20.17: AUTO-REHOST on scene death. The scene dies (scene=GONE) but the
                    // HANDLE survives and everything else stays intact. Re-create the scene via the
                    // handle (fetchOrCreate) + re-apply mode-4 to resurrect it within 0.5s of death.
                    if (!sc && gCBRSceneHandle) {
                        @try {
                            // re-create the scene on the handle
                            SEL foc = sel_registerName("scene");
                            id newScene = nil;
                            @try { newScene = ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("sceneIfExists")); } @catch(...) {}
                            if (!newScene) {
                                // force creation
                                @try { newScene = ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("scene")); } @catch(...) {}
                            }
                            PF("  AUTO-REHOST: recreated scene = %s\n", newScene ? class_getName(object_getClass(newScene)) : "still nil");
                            // re-apply mode-4 on the appView against the (hopefully) live scene
                            if (gCBRAppVC) {
                                @try { SEL csvc=sel_registerName("_createSceneViewController"); if([gCBRAppVC respondsToSelector:csvc]) ((void(*)(id,SEL))objc_msgSend)(gCBRAppVC, csvc); } @catch(...) {}
                                id av = [gCBRAppVC respondsToSelector:sel_registerName("appView")] ? ((id(*)(id,SEL))objc_msgSend)(gCBRAppVC, sel_registerName("appView")) : nil;
                                if (av) {
                                    id anim=nil; Class savc=objc_getClass("SBApplicationSceneView"); SEL af=sel_registerName("defaultDisplayModeAnimationFactory");
                                    if(savc && [savc respondsToSelector:af]) anim=((id(*)(id,SEL))objc_msgSend)(savc,af);
                                    SEL sdm=sel_registerName("setDisplayMode:animationFactory:completion:");
                                    if([av respondsToSelector:sdm]){ ((void(*)(id,SEL,int,id,void*))objc_msgSend)(av,sdm,4,anim,NULL); PF("  AUTO-REHOST: re-applied mode-4\n"); }
                                }
                            }
                        } @catch (NSException *e) { PF("  AUTO-REHOST EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                    }
                } @catch (NSException *e) { PF("poll EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                if (pf>=0) close(pf);
            });
        }
        // v3.20.18: removed the hardcoded 30s auto-dismiss - the keep-alive hooks hold
        // the scene now, so let it render until CarPlay disconnects instead of timing out.
        // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBHostDismiss(); });
        HH("SUCCESS: port host complete (30s) - watch car screen\n");
    } @catch (NSException *e) { HHF("HOST EXC: %s\n", [[e reason] UTF8String] ?: "?"); }
    HH("==== END ====\n");
    if (fd>=0) close(fd);
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
        id dispIdentity = nil;  // v3.19.9: hoisted - needed by request build below
        @try {
            // Try to get main display identity from UIScreen.mainScreen.
            Class UIScreenCls = objc_getClass("UIScreen");
            id mainScreen = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("mainScreen"));
            dispIdentity = cb(mainScreen, "displayIdentity");
            HPF("main displayIdentity: %s\n", dispIdentity ? class_getName(object_getClass(dispIdentity)) : "nil");
            if (coord && dispIdentity) {
                SEL sMgr = sel_registerName("sceneManagerForDisplayIdentity:");
                if ([coord respondsToSelector:sMgr])
                    mgr = ((id(*)(id,SEL,id))objc_msgSend)(coord, sMgr, dispIdentity);
            }
        } @catch (NSException *e) {}
        HPF("scene manager: %s\n", mgr ? class_getName(object_getClass(mgr)) : "nil");

        if (!mgr) { HP("no scene manager -> cannot probe handle\n"); HP("==== END ====\n"); if(fd>=0)close(fd); return; }

        // 4) v3.19.9 STEP 1: create the identity as a PRIMARY launchable scene
        //    (was sceneIdentityForApplication: non-creating; that yields a hollow handle
        //    with no client. Mirror the probe-path creating sequence at 1013-1045.)
        id identity = nil;
        @try {
            SEL createSel = sel_registerName("sceneIdentityForApplication:createPrimaryIfRequired:sceneSessionRole:");
            if (sbApp && [mgr respondsToSelector:createSel])
                identity = ((id(*)(id,SEL,id,BOOL,NSInteger))objc_msgSend)(mgr, createSel, sbApp, YES, (NSInteger)0);
        } @catch (NSException *e) { HPF("HOST createIdentity EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        HPF("HOST: created sceneIdentity (primary): %s\n", identity ? class_getName(object_getClass(identity)) : "nil");
        if (!identity) { HP("HOST: no primary identity -> abort\n"); HP("==== END ====\n"); if(fd>=0)close(fd); return; }

        // 5) Build the launch request (app + identity + MAIN display identity).
        id request = nil;
        @try {
            Class reqCls = objc_getClass("SBApplicationSceneHandleRequest");
            SEL fac = sel_registerName("defaultRequestForApplication:sceneIdentity:displayIdentity:");
            if (reqCls && [reqCls respondsToSelector:fac])
                request = ((id(*)(id,SEL,id,id,id))objc_msgSend)(reqCls, fac, sbApp, identity, dispIdentity);
        } @catch (NSException *e) { HPF("HOST buildRequest EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        HPF("HOST: request: %s\n", request ? class_getName(object_getClass(request)) : "nil");
        if (!request) { HP("HOST: no request -> abort\n"); HP("==== END ====\n"); if(fd>=0)close(fd); return; }

        // 6) CREATE the handle (this is the real creating call - may launch the scene).
        id handle = nil;
        @try {
            SEL fc = sel_registerName("fetchOrCreateApplicationSceneHandleForRequest:");
            if ([mgr respondsToSelector:fc])
                handle = ((id(*)(id,SEL,id))objc_msgSend)(mgr, fc, request);
        } @catch (NSException *e) { HPF("HOST fetchOrCreate EXC: %s\n", [[e reason] UTF8String]?:"?"); }
        HPF("HOST: CREATED handle: %s\n", handle ? class_getName(object_getClass(handle)) : "nil");

    } @catch (NSException *e) {
        HPF("PROBE EXC: %s\n", [[e reason] UTF8String] ?: "?");
    }
    HP("==== END ====\n");
    if (fd>=0) close(fd);
}
// v3.20.4: PATH-A LOCATOR - find the app's REAL client-bearing scene + its contextID.
// The hollow scene we create has client:nil. The app's process connects to ITS OWN
// scene (main display). To mirror content onto CarPlay we must first FIND that scene.
static void cbrSBLocateLiveScene(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_locate.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define LO(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define LOF(...) do{ char _b[440]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    LO("==== PATH-A LIVE SCENE LOCATOR ====\n");
    if (!bid_cstr || !bid_cstr[0]) { LO("no bid\n"); if(fd>=0)close(fd); return; }
    LOF("target bid: %s\n", bid_cstr);
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];
        Class acCls = objc_getClass("SBApplicationController");
        id ac = acCls ? ((id(*)(id,SEL))objc_msgSend)(acCls, sel_registerName("sharedInstance")) : nil;
        id app = ac ? ((id(*)(id,SEL,id))objc_msgSend)(ac, sel_registerName("applicationWithBundleIdentifier:"), bid) : nil;
        LOF("SBApplication: %s\n", app ? class_getName(object_getClass(app)) : "nil");
        if (!app) { LO("no app\n"); if(fd>=0)close(fd); return; }

        // 1) Dump EVERY SBApplication method mentioning scene/process/pid - find real accessors.
        LO("-- SBApplication scene/process methods --\n");
        Class ac2 = object_getClass(app); int d=0;
        while (ac2 && strcmp(class_getName(ac2),"NSObject")!=0 && d<3) {
            unsigned int n=0; Method *m=class_copyMethodList(ac2,&n);
            for (unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i]));
                if (strcasestr(sn,"scene")||strcasestr(sn,"process")||strcasestr(sn,"pid")||strcasestr(sn,"running")||strcasestr(sn,"context"))
                    LOF("  -%s\n", sn); }
            if(m)free(m); ac2=class_getSuperclass(ac2); d++;
        }

        // 2) Ask the scene manager for ALL scenes, find ones whose client process is alive.
        LO("-- scene manager enumeration --\n");
        Class coordCls = objc_getClass("SBSceneManagerCoordinator");
        id coord = coordCls ? ((id(*)(id,SEL))objc_msgSend)(coordCls, sel_registerName("sharedInstance")) : nil;
        Class UIScreenCls = objc_getClass("UIScreen");
        id mainScreen = ((id(*)(id,SEL))objc_msgSend)(UIScreenCls, sel_registerName("mainScreen"));
        id dispId = cb(mainScreen, "displayIdentity");
        id mgr = nil;
        if (coord && dispId) { SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,dispId); }
        LOF("scene mgr: %s\n", mgr ? class_getName(object_getClass(mgr)) : "nil");
        if (mgr) {
            // Dump mgr methods that return scene collections.
            LO("  -- mgr scene-collection methods --\n");
            Class mc=object_getClass(mgr); int md=0;
            while(mc && strcmp(class_getName(mc),"NSObject")!=0 && md<3){ unsigned int n=0; Method *m=class_copyMethodList(mc,&n);
                for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i]));
                    if((strcasestr(sn,"scene")&&(strcasestr(sn,"all")||strcasestr(sn,"applic")||strcasestr(sn,"active")||strcasestr(sn,"connected")))||strcasestr(sn,"scenesPassing")) LOF("    -%s\n",sn); }
                if(m)free(m); mc=class_getSuperclass(mc); md++; }

            // Try the common collection accessors and inspect each scene's client + display + contextID.
            for (const char *sel : (const char*[]){"allApplicationScenes","applicationScenes","_applicationScenes","allScenes","_allScenes","activeApplicationScenes", NULL}) {
                if (!sel) break; SEL se=sel_registerName(sel);
                if (![mgr respondsToSelector:se]) { LOF("  mgr.%s: no selector\n", sel); continue; }
                id scenes = ((id(*)(id,SEL))objc_msgSend)(mgr, se);
                unsigned long cnt = scenes && [scenes respondsToSelector:sel_registerName("count")] ? (unsigned long)[scenes count] : 0;
                LOF("  mgr.%s -> %lu scenes\n", sel, cnt);
                if (!scenes) continue;
                // scenes may be dict or array; normalize to enumerate values.
                id list = scenes;
                if ([scenes respondsToSelector:sel_registerName("allValues")]) list = ((id(*)(id,SEL))objc_msgSend)(scenes, sel_registerName("allValues"));
                @try {
                    for (id sc in list) {
                        const char *scn = class_getName(object_getClass(sc));
                        // client + pid
                        id cl = [sc respondsToSelector:sel_registerName("client")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("client")) : nil;
                        int pid = -1;
                        if (cl) { id pr=[cl respondsToSelector:sel_registerName("process")]?((id(*)(id,SEL))objc_msgSend)(cl,sel_registerName("process")):nil; if(pr && [pr respondsToSelector:sel_registerName("pid")]) pid=((int(*)(id,SEL))objc_msgSend)(pr,sel_registerName("pid")); }
                        // identity/bundle to see if it's OUR target app
                        id ident = [sc respondsToSelector:sel_registerName("identity")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("identity")) : nil;
                        NSString *identStr = ident ? [NSString stringWithFormat:@"%@", ident] : @"?";
                        BOOL isTarget = [identStr containsString:bid];
                        // contextID
                        unsigned int cid = 0;
                        if ([sc respondsToSelector:sel_registerName("contextID")]) cid = ((unsigned int(*)(id,SEL))objc_msgSend)(sc, sel_registerName("contextID"));
                        LOF("    %s%s client:%s pid:%d contextID:%u ident:%.60s\n",
                            isTarget?">>> TARGET ":"    ", scn, cl?"YES":"nil", pid, cid, [identStr UTF8String]);
                    }
                } @catch (NSException *e) { LOF("    enum EXC: %s\n", [[e reason] UTF8String]?:"?"); }
                if (cnt > 0) break;  // found a working accessor
            }
        }
    } @catch (NSException *e) { LOF("LOCATE EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    LO("==== END ====\n");
    if(fd>=0) close(fd);
}

// v3.20.5: PATH-A LOCATOR v2 - use the REAL accessors the mgr dump revealed:
// runningApplicationScenes:, externalApplicationSceneHandles. Find the client/contextID
// via the scene's process (client:nil on FBScene means client lives elsewhere).
static void cbrSBLocateLiveScene2(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_locate2.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define L2(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define L2F(...) do{ char _b[460]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    L2("==== PATH-A LOCATOR v2 ====\n");
    if (!bid_cstr||!bid_cstr[0]) { L2("no bid\n"); if(fd>=0)close(fd); return; }
    L2F("target: %s\n", bid_cstr);
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];
        Class coordCls = objc_getClass("SBSceneManagerCoordinator");
        id coord = coordCls ? ((id(*)(id,SEL))objc_msgSend)(coordCls, sel_registerName("sharedInstance")) : nil;
        id mainScreen = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIScreen"), sel_registerName("mainScreen"));
        id dispId = cb(mainScreen, "displayIdentity");
        id mgr = nil;
        if (coord && dispId){ SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,dispId); }
        L2F("mgr: %s\n", mgr?class_getName(object_getClass(mgr)):"nil");
        if(!mgr){ L2("no mgr\n"); if(fd>=0)close(fd); return; }

        // A) runningApplicationScenes: - dump its type encoding to learn the arg, then try forms.
        SEL runSel = sel_registerName("runningApplicationScenes:");
        Method rm = class_getInstanceMethod(object_getClass(mgr), runSel);
        if (rm) { char *enc = method_copyArgumentType(rm, 2); L2F("runningApplicationScenes: arg2 type = %s\n", enc?enc:"?"); if(enc)free(enc); }

        // Try runningApplicationScenes: with a predicate block that accepts all (returns YES).
        @try {
            BOOL (^pred)(id) = ^BOOL(id scene){ return YES; };
            if ([mgr respondsToSelector:runSel]) {
                id running = ((id(*)(id,SEL,id))objc_msgSend)(mgr, runSel, pred);
                unsigned long rc = running && [running respondsToSelector:sel_registerName("count")] ? (unsigned long)[running count] : 0;
                L2F("runningApplicationScenes:(pred) -> %lu\n", rc);
                if (running) for (id sc in running) {
                    id ident = [sc respondsToSelector:sel_registerName("identity")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("identity")):nil;
                    NSString *is = ident?[NSString stringWithFormat:@"%@",ident]:@"?";
                    L2F("  running scene: %s ident:%.70s\n", class_getName(object_getClass(sc)), [is UTF8String]);
                }
            }
        } @catch (NSException *e) { L2F("runningScenes(pred) EXC: %s\n", [[e reason] UTF8String]?:"?"); }

        // B) The YouTube scene from allScenes - dig for process/contextID via alternate paths.
        id allScenes = [mgr respondsToSelector:sel_registerName("allScenes")]?((id(*)(id,SEL))objc_msgSend)(mgr,sel_registerName("allScenes")):nil;
        if (allScenes) for (id sc in allScenes) {
            id ident=[sc respondsToSelector:sel_registerName("identity")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("identity")):nil;
            NSString *is=ident?[NSString stringWithFormat:@"%@",ident]:@"?";
            if (![is containsString:bid]) continue;
            L2F("TARGET scene: %s\n", class_getName(object_getClass(sc)));
            // Dump ALL methods of this FBScene mentioning client/process/context/host/layer.
            Class scc=object_getClass(sc); int d=0;
            while(scc && strcmp(class_getName(scc),"NSObject")!=0 && d<3){ unsigned int n=0; Method *m=class_copyMethodList(scc,&n);
                for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i]));
                    if(strcasestr(sn,"client")||strcasestr(sn,"process")||strcasestr(sn,"context")||strcasestr(sn,"host")||strcasestr(sn,"layer")||strcasestr(sn,"pid"))
                        L2F("   -%s\n", sn); }
                if(m)free(m); scc=class_getSuperclass(scc); d++; }
            // Try clientProcess / process / _process / contextHost
            for (const char *sel : (const char*[]){"clientProcess","process","_process","clientHandle","_client", NULL}) {
                if(!sel) break; SEL se=sel_registerName(sel);
                if([sc respondsToSelector:se]){ id r=((id(*)(id,SEL))objc_msgSend)(sc,se); L2F("   sc.%s -> %s\n", sel, r?class_getName(object_getClass(r)):"nil"); }
            }
        }

        // C) externalApplicationSceneHandles - SpringBoard's external-display app scene tracking.
        for (const char *sel : (const char*[]){"externalApplicationSceneHandles","externalForegroundApplicationSceneHandles", NULL}) {
            if(!sel) break; SEL se=sel_registerName(sel);
            if([mgr respondsToSelector:se]){ id h=((id(*)(id,SEL))objc_msgSend)(mgr,se);
                unsigned long hc = h && [h respondsToSelector:sel_registerName("count")]?(unsigned long)[h count]:0;
                L2F("mgr.%s -> %lu handles\n", sel, hc);
                if(h) for(id hh in h) L2F("   handle: %s\n", class_getName(object_getClass(hh)));
            } else L2F("mgr.%s: no selector\n", sel);
        }
    } @catch (NSException *e) { L2F("LOC2 EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    L2("==== END ====\n");
    if(fd>=0) close(fd);
}

// v3.20.6: PATH-A - inspect the external handle + the live scene's clientHandle/layerManager
// for a hostable contextID. Two mechanisms: (A) mirror live layer, (B) drive external handle.
static void cbrSBInspectExternal(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_ext.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define E3(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define E3F(...) do{ char _b[460]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    E3("==== EXTERNAL HANDLE + CLIENT HANDLE INSPECT ====\n");
    if(!bid_cstr||!bid_cstr[0]){ E3("no bid\n"); if(fd>=0)close(fd); return; }
    E3F("target: %s\n", bid_cstr);
    @try {
        NSString *bid=[NSString stringWithUTF8String:bid_cstr];
        Class coordCls=objc_getClass("SBSceneManagerCoordinator");
        id coord=coordCls?((id(*)(id,SEL))objc_msgSend)(coordCls,sel_registerName("sharedInstance")):nil;
        id mainScreen=((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("mainScreen"));
        id dispId=cb(mainScreen,"displayIdentity");
        id mgr=nil; if(coord&&dispId){ SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,dispId); }
        if(!mgr){ E3("no mgr\n"); if(fd>=0)close(fd); return; }

        // === PART 1: the external handle - what app is it, and its whole API ===
        id extH=[mgr respondsToSelector:sel_registerName("externalApplicationSceneHandles")]?((id(*)(id,SEL))objc_msgSend)(mgr,sel_registerName("externalApplicationSceneHandles")):nil;
        if(extH) for(id h in extH){
            E3F("external handle: %s\n", class_getName(object_getClass(h)));
            // What bundle / scene identity does this handle carry?
            for(const char*sel:(const char*[]){"sceneIdentifier","application","sceneHandleIdentifier","identifier", NULL}){
                if(!sel)break; SEL se=sel_registerName(sel);
                if([h respondsToSelector:se]){ id r=((id(*)(id,SEL))objc_msgSend)(h,se); E3F("  h.%s -> %s (%.60s)\n", sel, r?class_getName(object_getClass(r)):"nil", r?[[NSString stringWithFormat:@"%@",r] UTF8String]:""); }
            }
            // Its scene, if any, and that scene's display.
            @try { id scn=[h respondsToSelector:sel_registerName("sceneIfExists")]?((id(*)(id,SEL))objc_msgSend)(h,sel_registerName("sceneIfExists")):nil;
                E3F("  h.sceneIfExists: %s\n", scn?class_getName(object_getClass(scn)):"nil");
                if(scn){ id disp=[scn respondsToSelector:sel_registerName("display")]?((id(*)(id,SEL))objc_msgSend)(scn,sel_registerName("display")):nil;
                    E3F("    scene.display: %.60s\n", disp?[[NSString stringWithFormat:@"%@",disp] UTF8String]:"nil"); } } @catch(...) {}
        }

        // === PART 2: the LIVE youtube scene's clientHandle + layerManager -> contextID ===
        id allScenes=[mgr respondsToSelector:sel_registerName("allScenes")]?((id(*)(id,SEL))objc_msgSend)(mgr,sel_registerName("allScenes")):nil;
        if(allScenes) for(id sc in allScenes){
            id ident=[sc respondsToSelector:sel_registerName("identity")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("identity")):nil;
            NSString*is=ident?[NSString stringWithFormat:@"%@",ident]:@"?";
            if(![is containsString:bid]) continue;
            E3("LIVE youtube scene found\n");
            // clientHandle - the render-server connection.
            id ch=[sc respondsToSelector:sel_registerName("clientHandle")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("clientHandle")):nil;
            E3F("  clientHandle: %s\n", ch?class_getName(object_getClass(ch)):"nil");
            if(ch){ Class chc=object_getClass(ch); int d=0;
                E3("  -- clientHandle methods (context/layer/id/process) --\n");
                while(chc&&strcmp(class_getName(chc),"NSObject")!=0&&d<2){ unsigned int n=0; Method*m=class_copyMethodList(chc,&n);
                    for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); if(strcasestr(sn,"context")||strcasestr(sn,"layer")||strcasestr(sn,"identity")||strcasestr(sn,"process")||strcasestr(sn,"pid")) E3F("     -%s\n",sn); }
                    if(m)free(m); chc=class_getSuperclass(chc); d++; }
                // Try to pull a contextID off the client handle.
                for(const char*sel:(const char*[]){"contextID","contextId","_contextID", NULL}){ if(!sel)break; SEL se=sel_registerName(sel);
                    if([ch respondsToSelector:se]){ unsigned int cid=((unsigned int(*)(id,SEL))objc_msgSend)(ch,se); E3F("  ch.%s = %u\n", sel, cid); } }
            }
            // layerManager -> layers now (app is running, should be non-empty this time)
            id lm=[sc respondsToSelector:sel_registerName("layerManager")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("layerManager")):nil;
            if(lm){ id layers=[lm respondsToSelector:sel_registerName("layers")]?((id(*)(id,SEL))objc_msgSend)(lm,sel_registerName("layers")):nil;
                unsigned long lc=layers&&[layers respondsToSelector:sel_registerName("count")]?(unsigned long)[layers count]:0;
                E3F("  layerManager.layers = %lu\n", lc);
                if(layers) for(id ly in layers){ E3F("     layer: %s\n", class_getName(object_getClass(ly)));
                    for(const char*sel:(const char*[]){"contextID","context","layer", NULL}){ if(!sel)break; SEL se=sel_registerName(sel);
                        if([ly respondsToSelector:se]){ @try{ id r=((id(*)(id,SEL))objc_msgSend)(ly,se); E3F("        ly.%s -> %s\n", sel, r?class_getName(object_getClass(r)):"nil/scalar"); }@catch(...){ unsigned int v=((unsigned int(*)(id,SEL))objc_msgSend)(ly,se); E3F("        ly.%s = %u\n", sel, v); } } }
                }
            }
            // clientProcess pid (confirm it's the live one)
            id cp=[sc respondsToSelector:sel_registerName("clientProcess")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("clientProcess")):nil;
            if(cp && [cp respondsToSelector:sel_registerName("pid")]){ int pid=((int(*)(id,SEL))objc_msgSend)(cp,sel_registerName("pid")); E3F("  clientProcess pid: %d\n", pid); }
        }
    } @catch (NSException *e){ E3F("EXT EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    E3("==== END ====\n");
    if(fd>=0) close(fd);
}

// v3.20.8: PATH-A SHOT - move YouTube's LIVE scene from Main display to CarPlay.
// The scene already renders (clientProcess live). It's pinned to Main. We try to
// reassign its display to the CarPlay FBSDisplayConfiguration. Strict lifetime:
// find ONE handle, CFRetain, act once, release. No loose transient reads.
static void cbrSBReassignToCarPlay(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_reassign.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define RA(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define RAF(...) do{ char _b[440]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    RA("==== PATH-A: REASSIGN TO CARPLAY ====\n");
    if(!bid_cstr||!bid_cstr[0]){ RA("no bid\n"); if(fd>=0)close(fd); return; }
    RAF("target: %s\n", bid_cstr);
    @try {
        NSString *bid = [NSString stringWithUTF8String:bid_cstr];

        // 1) Get the CarPlay display configuration (same builder the host uses).
        id caDisplay = cbrGetCarplayCADisplay();
        if(!caDisplay){ RA("no carplay CADisplay -> abort\n"); RA("==== END ====\n"); if(fd>=0)close(fd); return; }
        Class fbsCfgCls = objc_getClass("FBSDisplayConfiguration");
        id carCfg = ((id(*)(id,SEL,id,BOOL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(fbsCfgCls, sel_registerName("alloc")), sel_registerName("initWithCADisplay:isMainDisplay:"), caDisplay, NO);
        if(!carCfg){ RA("no carplay FBSDisplayConfiguration -> abort\n"); RA("==== END ====\n"); if(fd>=0)close(fd); return; }
        id carDispId = [carCfg respondsToSelector:sel_registerName("identity")] ? ((id(*)(id,SEL))objc_msgSend)(carCfg, sel_registerName("identity")) : nil;
        RAF("carplay displayIdentity: %s\n", carDispId ? class_getName(object_getClass(carDispId)) : "nil");

        // 2) Find the ONE external handle whose sceneIdentifier matches our bid. Retain it immediately.
        Class coordCls=objc_getClass("SBSceneManagerCoordinator");
        id coord=coordCls?((id(*)(id,SEL))objc_msgSend)(coordCls,sel_registerName("sharedInstance")):nil;
        id mainScreen=((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("mainScreen"));
        id mainDispId=cb(mainScreen,"displayIdentity");
        id mgr=nil; if(coord&&mainDispId){ SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,mainDispId); }
        if(!mgr){ RA("no mgr -> abort\n"); RA("==== END ====\n"); if(fd>=0)close(fd); return; }

        id targetHandle = nil;
        id extH=[mgr respondsToSelector:sel_registerName("externalApplicationSceneHandles")]?((id(*)(id,SEL))objc_msgSend)(mgr,sel_registerName("externalApplicationSceneHandles")):nil;
        if(extH) for(id h in extH){
            id sidObj=[h respondsToSelector:sel_registerName("sceneIdentifier")]?((id(*)(id,SEL))objc_msgSend)(h,sel_registerName("sceneIdentifier")):nil;
            NSString *sid = sidObj ? [NSString stringWithFormat:@"%@", sidObj] : @"";
            if([sid containsString:bid]){ targetHandle = h; break; }
        }
        // Fallback: runningApplicationScenes: predicate to find the handle if not external.
        if(!targetHandle){
            SEL runSel=sel_registerName("runningApplicationScenes:");
            if([mgr respondsToSelector:runSel]){
                BOOL(^pred)(id)=^BOOL(id scene){ return YES; };
                id running=((id(*)(id,SEL,id))objc_msgSend)(mgr,runSel,pred);
                if(running) for(id h in running){
                    id sidObj=[h respondsToSelector:sel_registerName("sceneIdentifier")]?((id(*)(id,SEL))objc_msgSend)(h,sel_registerName("sceneIdentifier")):nil;
                    NSString *sid=sidObj?[NSString stringWithFormat:@"%@",sidObj]:@"";
                    if([sid containsString:bid]){ targetHandle=h; break; }
                }
            }
        }
        RAF("target handle: %s\n", targetHandle ? class_getName(object_getClass(targetHandle)) : "nil (NOT FOUND)");
        if(!targetHandle){ RA("no target handle -> abort\n"); RA("==== END ====\n"); if(fd>=0)close(fd); return; }

        // Retain the handle for the duration of the operation.
        CFRetain((__bridge CFTypeRef)targetHandle);

        // 3) Get its live scene and attempt the display reassignment via settings.
        @try {
            id scn=[targetHandle respondsToSelector:sel_registerName("sceneIfExists")]?((id(*)(id,SEL))objc_msgSend)(targetHandle,sel_registerName("sceneIfExists")):nil;
            RAF("scene: %s\n", scn ? class_getName(object_getClass(scn)) : "nil");
            if(scn && carDispId){
                // updateSettingsWithBlock: set the display / displayIdentity on mutable settings.
                SEL updBlk=sel_registerName("updateSettingsWithBlock:");
                if([scn respondsToSelector:updBlk]){
                    __block id blkDispId = carDispId;
                    __block id blkCfg = carCfg;
                    __block int blkFd = fd;
                    void(^diff)(id)=^(id ms){
                        // try several setters for display reassignment; log which exist.
                        if([ms respondsToSelector:sel_registerName("setDisplayIdentity:")]){ ((void(*)(id,SEL,id))objc_msgSend)(ms,sel_registerName("setDisplayIdentity:"),blkDispId); const char*m="  applied setDisplayIdentity:\n"; if(blkFd>=0)write(blkFd,m,strlen(m)); }
                        else if([ms respondsToSelector:sel_registerName("setDisplayConfiguration:")]){ ((void(*)(id,SEL,id))objc_msgSend)(ms,sel_registerName("setDisplayConfiguration:"),blkCfg); const char*m="  applied setDisplayConfiguration:\n"; if(blkFd>=0)write(blkFd,m,strlen(m)); }
                        else { const char*m="  NO display setter on settings (see settings dump)\n"; if(blkFd>=0)write(blkFd,m,strlen(m)); }
                        // keep it foreground/active
                        if([ms respondsToSelector:sel_registerName("setForeground:")]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms,sel_registerName("setForeground:"),YES);
                    };
                    ((void(*)(id,SEL,id))objc_msgSend)(scn, updBlk, diff);
                    RA("updateSettingsWithBlock: applied\n");
                } else {
                    RA("scene has no updateSettingsWithBlock:\n");
                    // dump settings setters so we find the right display setter next
                    id st=[scn respondsToSelector:sel_registerName("settings")]?((id(*)(id,SEL))objc_msgSend)(scn,sel_registerName("settings")):nil;
                    if(st){ Class stc=object_getClass(st); unsigned int n=0; Method*m=class_copyMethodList(stc,&n);
                        RA("  settings setters (display/frame):\n");
                        for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); if(strncmp(sn,"set",3)==0 && (strcasestr(sn,"display")||strcasestr(sn,"frame"))) RAF("    -%s\n",sn); }
                        if(m)free(m); }
                }
            }
        } @catch (NSException *e) { RAF("reassign inner EXC: %s\n", [[e reason] UTF8String]?:"?"); }

        CFRelease((__bridge CFTypeRef)targetHandle);
    } @catch (NSException *e) { RAF("REASSIGN EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    RA("==== END ====\n");
    if(fd>=0) close(fd);
}

// v3.20.9: probe the transition-context API on the live scene (display moves are
// transitions, not settings pokes). Surgical: find handle, CFRetain, read selectors, release.
static void cbrSBProbeTransition(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_txn.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define TP(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define TPF(...) do{ char _b[440]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    TP("==== TRANSITION API PROBE ====\n");
    if(!bid_cstr||!bid_cstr[0]){ TP("no bid\n"); if(fd>=0)close(fd); return; }
    @try {
        NSString *bid=[NSString stringWithUTF8String:bid_cstr];
        Class coordCls=objc_getClass("SBSceneManagerCoordinator");
        id coord=coordCls?((id(*)(id,SEL))objc_msgSend)(coordCls,sel_registerName("sharedInstance")):nil;
        id mainScreen=((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("mainScreen"));
        id mdi=cb(mainScreen,"displayIdentity");
        id mgr=nil; if(coord&&mdi){ SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,mdi); }
        if(!mgr){ TP("no mgr\n"); if(fd>=0)close(fd); return; }
        id targetHandle=nil;
        id extH=[mgr respondsToSelector:sel_registerName("externalApplicationSceneHandles")]?((id(*)(id,SEL))objc_msgSend)(mgr,sel_registerName("externalApplicationSceneHandles")):nil;
        if(extH) for(id h in extH){ id sidObj=[h respondsToSelector:sel_registerName("sceneIdentifier")]?((id(*)(id,SEL))objc_msgSend)(h,sel_registerName("sceneIdentifier")):nil; NSString*sid=sidObj?[NSString stringWithFormat:@"%@",sidObj]:@""; if([sid containsString:bid]){targetHandle=h;break;} }
        if(!targetHandle){ TP("no target handle\n"); if(fd>=0)close(fd); return; }
        CFRetain((__bridge CFTypeRef)targetHandle);
        @try {
            id scn=[targetHandle respondsToSelector:sel_registerName("sceneIfExists")]?((id(*)(id,SEL))objc_msgSend)(targetHandle,sel_registerName("sceneIfExists")):nil;
            TPF("scene: %s\n", scn?class_getName(object_getClass(scn)):"nil");
            if(scn){
                // ALL transition/update/activate/context methods on the scene.
                TP("-- scene transition/activate/update methods --\n");
                Class sc=object_getClass(scn); int d=0;
                while(sc&&strcmp(class_getName(sc),"NSObject")!=0&&d<3){ unsigned int n=0; Method*m=class_copyMethodList(sc,&n);
                    for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); if(strcasestr(sn,"transition")||strcasestr(sn,"activate")||strcasestr(sn,"updateSettings")) TPF("   -%s\n",sn); }
                    if(m)free(m); sc=class_getSuperclass(sc); d++; }
                // The settings object: what identifies its display, and is there a transition-context class?
                id st=[scn respondsToSelector:sel_registerName("settings")]?((id(*)(id,SEL))objc_msgSend)(scn,sel_registerName("settings")):nil;
                TPF("settings: %s\n", st?class_getName(object_getClass(st)):"nil");
                if(st){ Class stc=object_getClass(st); unsigned int n=0; Method*m=class_copyMethodList(stc,&n);
                    TP("  settings display/frame getters+setters:\n");
                    for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); if(strcasestr(sn,"display")||strcasestr(sn,"frame")||strcasestr(sn,"bound")) TPF("    -%s\n",sn); }
                    if(m)free(m); }
                // Does a transition-context factory class exist?
                for(const char*cn:(const char*[]){"FBSSceneTransitionContext","UIApplicationSceneTransitionContext","FBSceneTransitionContext", NULL}){
                    if(!cn)break; Class c=objc_getClass(cn); TPF("class %s: %s\n", cn, c?"EXISTS":"nil"); }
            }
        } @catch(NSException*e){ TPF("inner EXC: %s\n",[[e reason] UTF8String]?:"?"); }
        CFRelease((__bridge CFTypeRef)targetHandle);
    } @catch(NSException*e){ TPF("PROBE EXC: %s\n",[[e reason] UTF8String]?:"?"); }
    TP("==== END ====\n");
    if(fd>=0) close(fd);
}

// v3.20.10: probe FBSSceneTransitionContext - how to build one with a target display,
// so we can activateWithTransitionContext: to migrate the scene to CarPlay.
static void cbrSBProbeTxnCtx(const char *bid_cstr) {
    int fd = open("/var/mobile/CBR_txnctx.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define TC(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define TCF(...) do{ char _b[440]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    TC("==== TRANSITION CONTEXT API ====\n");
    @try {
        // Class methods (factories) + instance setters on FBSSceneTransitionContext.
        for(const char*cn:(const char*[]){"FBSSceneTransitionContext","UIApplicationSceneTransitionContext", NULL}){
            if(!cn)break; Class c=objc_getClass(cn);
            if(!c){ TCF("%s: nil\n",cn); continue; }
            TCF("=== %s ===\n", cn);
            // class (factory) methods
            Class meta=object_getClass((id)c); unsigned int n=0; Method*m=class_copyMethodList(meta,&n);
            TC("  class/factory methods:\n");
            for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); TCF("    +%s\n",sn); }
            if(m)free(m);
            // instance methods mentioning display/target/context
            unsigned int n2=0; Method*m2=class_copyMethodList(c,&n2);
            TC("  instance display/target setters:\n");
            for(unsigned int i=0;i<n2;i++){ const char*sn=sel_getName(method_getName(m2[i])); if(strncmp(sn,"set",3)==0 && (strcasestr(sn,"display")||strcasestr(sn,"target")||strcasestr(sn,"animation")||strcasestr(sn,"context"))) TCF("    -%s\n",sn); }
            if(m2)free(m2);
        }
        // Also: does the SCENE MANAGER have a method to move/reparent a scene to a display?
        Class coordCls=objc_getClass("SBSceneManagerCoordinator");
        id coord=coordCls?((id(*)(id,SEL))objc_msgSend)(coordCls,sel_registerName("sharedInstance")):nil;
        id mainScreen=((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("mainScreen"));
        id mdi=cb(mainScreen,"displayIdentity");
        id mgr=nil; if(coord&&mdi){ SEL s=sel_registerName("sceneManagerForDisplayIdentity:"); if([coord respondsToSelector:s]) mgr=((id(*)(id,SEL,id))objc_msgSend)(coord,s,mdi); }
        if(mgr){ TCF("mgr: %s\n", class_getName(object_getClass(mgr)));
            Class mc=object_getClass(mgr); unsigned int n=0; Method*m=class_copyMethodList(mc,&n);
            TC("  mgr move/transfer/display methods:\n");
            for(unsigned int i=0;i<n;i++){ const char*sn=sel_getName(method_getName(m[i])); if(strcasestr(sn,"move")||strcasestr(sn,"transfer")||strcasestr(sn,"reparent")||strcasestr(sn,"migrat")||(strcasestr(sn,"display")&&strcasestr(sn,"scene"))) TCF("    -%s\n",sn); }
            if(m)free(m); }
    } @catch(NSException*e){ TCF("EXC: %s\n",[[e reason] UTF8String]?:"?"); }
    TC("==== END ====\n");
    if(fd>=0) close(fd);
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
    // v3.20.11: PATH-A + probes REMOVED from the hot path. cbrSBReassignToCarPlay
    // poked the LIVE main-display scene's display config on every tap; the composite
    // never moved, leaving the scene spinning the render server -> load avg 143 runaway.
    // Keep ONLY the grafting host - this is what actually rendered scrollable YouTube.
    // cbrSBProbeSceneHandle(bid);      // diagnostic only - off hot path
    id _cbrHandle = cbrSBCreateSceneHandle(bid);
    cbrSBHostScene(bid, _cbrHandle);
    // cbrSBReassignToCarPlay(bid);     // PATH-A - caused the load runaway - REMOVED
    // cbrSBProbeTransition(bid);       // diagnostic only - off hot path
    // cbrSBProbeTxnCtx(bid);           // diagnostic only - off hot path
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
// v3.20.30: CarPlayApp-SIDE chrome probe. From SpringBoard we could NOT see CarPlay chrome
// (all windows were sameScreen=0 / phone display). CarPlay's chrome is rendered in THIS process
// (CarPlayApp). This probe enumerates CarPlayApp's own scenes/windows/view hierarchy to find the
// sidebar/dock/home-button chrome - the make-or-break for genuine stock-chrome coordination.
static void cbrCPProbeChrome(void) {
    int cf = open("/var/mobile/CBR_cpchrome.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    #define PC(...) do{ char _b[320]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(cf>=0)write(cf,_b,_n);}while(0)
    PC("==== CARPLAYAPP-SIDE CHROME PROBE ====\n");
    @try {
        Class appCls = objc_getClass("UIApplication");
        id app = ((id(*)(id,SEL))objc_msgSend)(appCls, sel_registerName("sharedApplication"));
        // 1) all connected scenes in CarPlayApp + their windows
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? [all count] : 0;
        PC("connectedScenes: %lu\n", (unsigned long)cnt);
        for (NSUInteger i=0;i<cnt;i++){
            id sc = [all objectAtIndex:i];
            const char *scn = class_getName(object_getClass(sc));
            // scene role + session
            id sess = [sc respondsToSelector:sel_registerName("session")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("session")) : nil;
            id role = sess ? ((id(*)(id,SEL))objc_msgSend)(sess, sel_registerName("role")) : nil;
            NSString *roleS = role ? [NSString stringWithFormat:@"%@", role] : @"?";
            PC("  scene[%lu] %s role=%.50s\n", (unsigned long)i, scn, [roleS UTF8String]);
            // windows of this scene
            @try {
                id wins = [sc respondsToSelector:sel_registerName("windows")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("windows")) : nil;
                NSUInteger wc = wins ? [wins count] : 0;
                PC("    windows: %lu\n", (unsigned long)wc);
                for (NSUInteger j=0;j<wc;j++){
                    id w=[wins objectAtIndex:j];
                    CGRect wf=((CGRect(*)(id,SEL))objc_msgSend)(w,sel_registerName("frame"));
                    double lvl=((double(*)(id,SEL))objc_msgSend)(w,sel_registerName("windowLevel"));
                    PC("      win %s level=%.1f frame=%.0fx%.0f\n", class_getName(object_getClass(w)), lvl, wf.size.width, wf.size.height);
                    // walk the rootVC's view tree shallowly, looking for chrome-like view classes
                    id rvc=[w respondsToSelector:sel_registerName("rootViewController")]?((id(*)(id,SEL))objc_msgSend)(w,sel_registerName("rootViewController")):nil;
                    id rv=rvc?((id(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("view")):nil;
                    if(rv){
                        id subs=((id(*)(id,SEL))objc_msgSend)(rv,sel_registerName("subviews"));
                        NSUInteger sc2=subs?[subs count]:0;
                        PC("        rootView %s subviews=%lu\n", class_getName(object_getClass(rv)), (unsigned long)sc2);
                        for(NSUInteger k=0;k<sc2 && k<12;k++){ id v=[subs objectAtIndex:k];
                            const char *vn=class_getName(object_getClass(v));
                            PC("          sub[%lu] %s\n",(unsigned long)k,vn);
                        }
                    }
                }
            } @catch(...) { PC("    (windows enum threw)\n"); }
        }
        // 2) look for known CarPlay chrome classes by name
        PC("-- known chrome classes present? --\n");
        for (const char *cn : (const char*[]){"CARDashboardViewController","CARDashboardChromeViewController","CARSidebarViewController","CARDockViewController","CARStatusBarViewController","CARHomeButton","DBDashboardHomeViewController","DBDashboardViewController","CARDashboardRootViewController","CARChromeViewController", NULL}) {
            if(!cn)break; Class c=objc_getClass(cn); PC("  %s: %s\n", cn, c?"PRESENT":"absent");
        }
    } @catch(NSException *e){ PC("PROBE EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    PC("==== END ====\n");
    if(cf>=0)close(cf);
    #undef PC
}

%hook DBDashboardHomeViewController

- (void)_setupIconModel {
    cbrCPProbeScenes();
    cbrCPProbeCarSceneGuts();
    cbrCPProbeChrome();
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
                CBPostLaunch(bid);   // writes pending bid file (cbrCPRenderTest reads it)
                CBLogFmt("[CBR] Tapped bridged app: %s", bid ?: "?");
                // cbrCPRenderTest(); // v3.20.2 disabled for stability isolation - in-process car-scene window test
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


// v3.20.20: append-only diagnostic log for the keep-alive hooks (what happens at lock).
static void cbrKLLog(const char *fmt, ...) {
    static int klfd = -1;
    if (klfd < 0) klfd = open("/var/mobile/CBR_keepalive.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (klfd < 0) return;
    char buf[512];
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    if (n > 0) write(klfd, buf, (size_t)n > sizeof(buf) ? sizeof(buf) : (size_t)n);
}

%group SPRINGBOARD
// v3.20.18: keep-alive hooks ported from carplay-cast (EthanArbuckle/carplay-cast).
// While an app is hosted on CarPlay, SpringBoard's normal lifecycle would suspend it the
// moment it is no longer the main-screen foreground app, killing the render. These hooks
// refuse to background any scene whose app is in gCBRKeepAlive.
%hook FBScene
- (void)updateSettings:(id)arg1 withTransitionContext:(id)arg2 completion:(void *)arg3 {
    @try {
        if (gCBRKeepAlive && [gCBRKeepAlive count]) {
            // iOS 17: FBScene -client returns nil; -clientProcess returns the FBApplicationProcess.
            id proc = nil;
            if ([(id)self respondsToSelector:sel_registerName("clientProcess")])
                proc = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("clientProcess"));
            if (!proc) {
                id client = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("client"));
                if (client && [client respondsToSelector:sel_registerName("process")])
                    proc = ((id(*)(id,SEL))objc_msgSend)(client, sel_registerName("process"));
            }
            id bid = (proc && [proc respondsToSelector:sel_registerName("bundleIdentifier")]) ? ((id(*)(id,SEL))objc_msgSend)(proc, sel_registerName("bundleIdentifier")) : nil;
            if (bid && [gCBRKeepAlive containsObject:bid]) {
                BOOL respFg = [arg1 respondsToSelector:sel_registerName("isForeground")];
                BOOL isFg = respFg ? ((BOOL(*)(id,SEL))objc_msgSend)(arg1, sel_registerName("isForeground")) : YES;
                cbrKLLog("[fbscene] bid=%s procVia=%s argClass=%s respFg=%d isFg=%d => %s\n",
                         [bid UTF8String], proc?"ok":"nil", object_getClassName(arg1), (int)respFg, (int)isFg, (respFg && !isFg) ? "BLOCK" : "pass");
                if (respFg && !isFg) { return; }   // block the background transition -> keep it live on CarPlay
            }
        }
    } @catch(...) {}
    %orig;
}
%end
%hook SBSuspendedUnderLockManager
- (int)_shouldBeBackgroundUnderLockForScene:(id)arg2 withSettings:(id)arg3 {
    int shouldBackground = %orig;
    @try {
        if (shouldBackground && gCBRKeepAlive && [gCBRKeepAlive count]) {
            id proc = nil;
            if ([arg2 respondsToSelector:sel_registerName("clientProcess")])
                proc = ((id(*)(id,SEL))objc_msgSend)(arg2, sel_registerName("clientProcess"));
            if (!proc) {
                id client = ((id(*)(id,SEL))objc_msgSend)(arg2, sel_registerName("client"));
                proc = client ? ((id(*)(id,SEL))objc_msgSend)(client, sel_registerName("process")) : nil;
            }
            id bid = (proc && [proc respondsToSelector:sel_registerName("bundleIdentifier")]) ? ((id(*)(id,SEL))objc_msgSend)(proc, sel_registerName("bundleIdentifier")) : nil;
            if (bid && [gCBRKeepAlive containsObject:bid]) {
                cbrKLLog("[lockmgr] bid=%s origShould=%d => forcing NO\n", [bid UTF8String], shouldBackground);
                shouldBackground = NO;
            }
        }
    } @catch(...) {}
    return shouldBackground;
}
%end
%end  // group SPRINGBOARD

// v3.20.19: report whether each hooked class+selector actually resolves on THIS
// device (answers "are we blind-hooking on iOS 17?"). Pure C + runtime lookups.
static void cbrLogHook(int fd, const char *clsName, char kind, const char *selName) {
    Class c = objc_getClass(clsName);
    int hasCls = (c != NULL);
    int hasMethod = 0;
    if (c && selName && selName[0]) {
        SEL sel = sel_registerName(selName);
        Method m = (kind == '+') ? class_getClassMethod(c, sel) : class_getInstanceMethod(c, sel);
        hasMethod = (m != NULL);
    }
    int resolved = hasCls && hasMethod;
    char buf[360];
    int n = snprintf(buf, sizeof(buf), "[hook] %-30s %c%-50s class=%-3s method=%-3s => %s\n",
                     clsName, kind, selName,
                     hasCls ? "YES" : "NO", hasMethod ? "YES" : "NO",
                     resolved ? "RESOLVED" : "** MISSING **");
    if (fd >= 0 && n > 0) write(fd, buf, (size_t)n);
}

%ctor {
    // PURE C — no ObjC whatsoever
    if (strcmp(__progname, "CarPlay") == 0) {
        unlink("/var/mobile/CBR_live.txt");
        gLogFD = open("/var/mobile/CBR_live.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666);
        %init(CARPLAY);
        { int hf = open("/var/mobile/CBR_cp_hooks.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
          cbrLogHook(hf, "DashBoard", '+', "_newApplicationLibrary");
          cbrLogHook(hf, "DBEnvironmentConfiguration", '-', "policyForApplicationInfo:");
          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", '-', "effectivePolicyForAppDeclaration:");
          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", '-', "effectivePolicyForAppDeclaration:inVehicleWithCertificateSerial:");
          cbrLogHook(hf, "DBDashboardHomeViewController", '-', "_setupIconModel");
          cbrLogHook(hf, "DBApplicationLaunchInfo", '+', "launchInfoForApplication:withActivationSettings:");
          cbrLogHook(hf, "DBIconView", '-', "didMoveToWindow");
          if (hf >= 0) close(hf); }
        const char msg[] = "[CBR] v3.20.33 init - exit terminates app (fresh-launch reopen renders + audio stops)\n";
        write(gLogFD, msg, sizeof(msg)-1);
        write(2, msg, sizeof(msg)-1);
    }
    else if (strcmp(__progname, "SpringBoard") == 0) {
        %init(SPRINGBOARD);
        cbrSBRegisterListener();
        unlink("/var/mobile/CBR_keepalive.txt");
        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
        if(_sf>=0){const char*m="[CBR-SB] v3.20.33 init - exit terminates app\n";write(_sf,m,strlen(m));
            cbrLogHook(_sf, "FBScene", '-', "updateSettings:withTransitionContext:completion:");
            cbrLogHook(_sf, "SBSuspendedUnderLockManager", '-', "_shouldBeBackgroundUnderLockForScene:withSettings:");
            close(_sf);}
    }
}

#pragma clang diagnostic pop
