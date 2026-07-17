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
#import <notify.h>

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
static uint64_t cbrBidHash(const char *sV);   // v3.51.0 fwd decl (defined below)
static CGFloat gCBRIconCX = 0, gCBRIconCY = 0;   // v3.51.0: last-highlighted dashboard icon center (car window coords)
static double  gCBRIconTS = 0;                   // v3.51.0: when it was captured (monotonic)
static void CBPostLaunch(const char *bid_cstr) {
    if (!bid_cstr) return;
    // v3.51.0 ZOOM ORIGIN: publish the tapped icon's center so SpringBoard can grow the app
    // out of the icon (and shrink it back into it on close), like stock CarPlay. 0 = no recent
    // capture -> SpringBoard falls back to a center zoom.
    @try {
        static int _ict = 0;
        if (!_ict) notify_register_check("com.cbr.icon.center", &_ict);
        uint64_t _icv = 0;
        struct timespec _its; clock_gettime(CLOCK_MONOTONIC, &_its);
        double _inow = _its.tv_sec + _its.tv_nsec/1e9;
        if (gCBRIconTS > 0 && (_inow - gCBRIconTS) < 3.0 && gCBRIconCX >= 0 && gCBRIconCY >= 0)
            _icv = (((uint64_t)(gCBRIconCX + 0.5)) << 16) | ((uint64_t)(gCBRIconCY + 0.5));
        if (_ict) notify_set_state(_ict, _icv);
        if (_icv) CBCarLogFmt("[CBR-CP] v3.51.0 zoom origin published %.0f,%.0f", gCBRIconCX, gCBRIconCY);
    } @catch(...) {}
    // v3.51.0 PRE-SPAWN ARM: publish hash(bid) BEFORE the pending file and the launch
    // notification. Until now the state was only written inside SpringBoard's launch callback,
    // so the app process could win the spawn race, read state=0 at its ctor SYNC-GATE, resolve
    // its FIRST orientation with the real portrait mask, and composite sideways from frame 1
    // (Reddit sometimes, YouTube TV almost always; YouTube won the race, hence always upright).
    // Publishing here means the state exists before ANY spawn path runs. SpringBoard re-publishes
    // the same value moments later (harmless), dismiss + respring still zero it.
    @try {
        static int _pst = 0;
        if (!_pst) notify_register_check("com.cbr.orient.landscape", &_pst);
        if (_pst) { notify_set_state(_pst, cbrBidHash(bid_cstr)); CBCarLogFmt("[CBR-CP] v3.52.0 pre-spawn arm published -> %s hash=%llu", bid_cstr, (unsigned long long)cbrBidHash(bid_cstr));
            int _af=open("/var/mobile/CBR_arm_diag.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_af>=0){ char _ab[320]; int _an=snprintf(_ab,sizeof(_ab),"CP-PRESPAWN bid=[%s] hash=%llu\n", bid_cstr, (unsigned long long)cbrBidHash(bid_cstr)); if(_an>0)write(_af,_ab,(size_t)_an); close(_af);} }
    } @catch(...) {}
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
static id gCBROverlayBtn = nil;     // v3.53.0: the home button living in that overlay window
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
            // v3.30.0: TWO car UIWindowScenes exist (ifo=0 landscape, ifo=1 portrait) - proven by the
            // CarPlay-side probe. Old code took the FIRST car scene, but array order is unstable, so
            // the host window sometimes attached to the PORTRAIT scene -> app rendered sideways (the
            // coin flip). Now prefer a car scene whose ifo != 1 (portrait); fall back to first.
            id carSceneLandscape = nil, carSceneFirst = nil;
            for (NSUInteger i = 0; i < cnt; i++) {
                id s = [all objectAtIndex:i];
                if (![s isKindOfClass:objc_getClass("UIWindowScene")]) continue;
                id scr = cb(s, "screen");
                BOOL isCar = scr ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, sel_registerName("_isCarScreen")) : NO;
                long sio = ((long(*)(id,SEL))objc_msgSend)(s, sel_registerName("interfaceOrientation"));
                char sl[180]; snprintf(sl,sizeof(sl),"[CBR-SB]   scene[%lu] %s car=%d ifo=%ld",
                    (unsigned long)i, class_getName(object_getClass(s)), isCar, sio); cbrSBLog(sl);
                if (isCar) {
                    if (!carSceneFirst) carSceneFirst = s;
                    if (!carSceneLandscape && sio != 1) carSceneLandscape = s;
                }
            }
            carScene = carSceneLandscape ? carSceneLandscape : carSceneFirst;
            { char pk[120]; snprintf(pk,sizeof(pk),"[CBR-SB] PICKED car scene: %s",
                carScene ? (carSceneLandscape ? "LANDSCAPE (ifo!=1)" : "first-fallback") : "none"); cbrSBLog(pk); }
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
static int gCBRHardDismiss = 0;   // v3.60.0: 1 = tear down immediately (no zoom) - set for re-host/foreign/disconnect
static id gCBRAppVC = nil;
static id gCBRActiveTxns = nil;
static id gCBRTxn = nil;         // v3.19.5: strong-hold txn for safe completion
static NSMutableSet *gCBRKeepAlive = nil;  // v3.20.18: bundle IDs whose scenes must NOT be backgrounded while hosted on CarPlay
// v3.42.0 globals.
static NSString *gCBRPendingHostBid = nil;  // bid being hosted - matched by the BORN-LANDSCAPE create hook
static int gCBRHostStateToken = 0;          // notify token: state 3 = hosting (apps read it SYNCHRONOUSLY at ctor)
static int gCBRTruthTokenSB = 0;            // v3.47.0: notify token for com.cbr.app.truth (app publishes its REAL scene orientation)
static int gCBRBounceCount = 0;             // tap-replay attempts this host session
static int gCBRBlindBounce = 0;             // v3.51.0: no-truth blind edges this host session (max 2)
static int gCBRBounceBypass = 0;            // lets our own deactivate edge through the keep-alive hook
static id gCBRContainerView = nil;          // inset app container (right of the dock strip)
static CGFloat gCBRSidebarW = 0;            // v3.44.0 native-chrome reveal: left strip we leave uncovered
static uint64_t gCBROwnBidHash = 0;         // v3.45.0 app-side: hash of THIS app's bundle id
static CGFloat gCBRHomeZoneH = 0;           // v3.46.0: bottom sidebar strip that dismisses (native home button lives here)
static id gCBRHomeButton = nil;             // v3.51.0: the transparent dismiss button - hitTest returns it EXPLICITLY
static int gCBRScaleAnimated = 0;           // v3.52.0: one-shot scene grow-in per host session
// v3.45.0 djb2 hash of a bundle id. The host publishes hash(hostedBid) as the notify state; each app
// compares it to hash(ownBid). Only the app actually being hosted matches - so the landscape override
// can never leak to a phone app (the Photos-went-landscape bug). Never returns 0 (0 = not hosting).
static uint64_t cbrBidHash(const char *sV) {
    if (!sV) return 0;
    uint64_t h = 5381; int c;
    // v3.52.0: lowercase before hashing so a case difference between CarPlays launch-info bid
    // string and the apps own NSBundle bundleIdentifier cannot desync the two hashes (that is
    // why only YouTube - whose strings happened to match exactly - ever armed).
    while ((c = (unsigned char)*sV++)) { if (c >= 'A' && c <= 'Z') c += 32; h = ((h << 5) + h) + (uint64_t)c; }
    return h ? h : 1;
}
// v3.45.0 read the current host state (works in any process: app / SpringBoard / CarPlay).
static uint64_t cbrReadHostState(void) {
    @try {
        static int _tok = 0;
        if (!_tok) { if (notify_register_check("com.cbr.orient.landscape", &_tok) != 0) _tok = 0; }
        uint64_t st = 0;
        if (_tok) notify_get_state(_tok, &st);
        return st;
    } @catch(...) { return 0; }
}
static void cbrSBHostDismiss(void) {
    { int _f=open("/var/mobile/CBR_home.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ const char*m="HOST-DISMISS entered (our exit path running)\n"; write(_f,m,strlen(m)); close(_f);} }   // v3.53.0: proves whether our teardown actually runs on a home tap
    @try { CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.orient.unlock"), NULL, NULL, YES); } @catch(...) {}
    // v3.42.0: stop advertising "hosting" to launching apps + drop the pending create-match + container.
    @try { if (gCBRHostStateToken) notify_set_state(gCBRHostStateToken, 0); gCBRPendingHostBid = nil; gCBRBounceCount = 0; gCBRBounceBypass = 0; } @catch(...) {}   // v3.51.0: container must SURVIVE until the close zoom reads it
    // v3.63.0: snapshot the LIVE app content NOW (before the restore-to-mode-0 + SIGKILL below blank
    // it) and overlay it on the container. The close zoom then animates this real frame - not a dead
    // black one - into the tapped icon (the container's anchor). @try-guarded: if the grafted surface
    // can't be snapshotted, the plain container zoom still runs.
    @try {
        if (gCBRContainerView) {
            id _snapClose = ((id(*)(id,SEL,BOOL))objc_msgSend)(gCBRContainerView, sel_registerName("snapshotViewAfterScreenUpdates:"), NO);
            if (_snapClose) {
                CGRect _cbnd = ((CGRect(*)(id,SEL))objc_msgSend)(gCBRContainerView, sel_registerName("bounds"));
                ((void(*)(id,SEL,CGRect))objc_msgSend)(_snapClose, sel_registerName("setFrame:"), _cbnd);
                ((void(*)(id,SEL,id))objc_msgSend)(gCBRContainerView, sel_registerName("addSubview:"), _snapClose);
            }
        }
    } @catch(...) {}
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

        // v3.51.0 CLOSE ANIMATION: ZOOM-OUT - the last rendered frame shrinks to the center
        // (0.25) and fades, then the CAPTURED window hides in the completion (a re-host started
        // mid-animation gets a fresh window and is never touched). Instant-hide on throw.
        int _hard = gCBRHardDismiss; gCBRHardDismiss = 0;   // v3.60.0: consume the hard-dismiss flag
        @try {
            id _cont = gCBRContainerView;
            id _win = gCBRRootWindow;
            if (_hard) {
                // v3.60.0: re-host / foreign-launch / disconnect -> tear down IMMEDIATELY (no zoom) so
                // the new host never overlaps a lingering old window (the won't-open / double-foreground
                // / sideways failure). The zoom below is only for the user's home-button exit.
                if (_win) ((void(*)(id,SEL,BOOL))objc_msgSend)(_win, sel_registerName("setHidden:"), YES);
            } else if (_cont && _win) {
                void (^_out)(void) = ^{
                    ((void(*)(id,SEL,CGFloat))objc_msgSend)(_cont, sel_registerName("setAlpha:"), (CGFloat)0.0);
                    ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(_cont, sel_registerName("setTransform:"), CGAffineTransformMakeScale(0.25, 0.25));
                };
                void (^_done)(BOOL) = ^(BOOL fin){ @try { ((void(*)(id,SEL,BOOL))objc_msgSend)(_win, sel_registerName("setHidden:"), YES); } @catch(...) {} };
                ((void(*)(Class,SEL,double,double,NSUInteger,void(^)(void),void(^)(BOOL)))objc_msgSend)(
                    objc_getClass("UIView"), sel_registerName("animateWithDuration:delay:options:animations:completion:"),
                    0.40, 0.0, (NSUInteger)(1UL<<16) /*EaseIn - v3.63.0 slower, zooms the live snapshot into the icon*/, _out, _done);
            } else if (_win) {
                ((void(*)(id,SEL,BOOL))objc_msgSend)(_win, sel_registerName("setHidden:"), YES);
            }
        } @catch(...) { if (gCBRRootWindow) { ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBRRootWindow, sel_registerName("setHidden:"), YES); } }
        @try { if (gCBROverlayWindow) { ((void(*)(id,SEL,BOOL))objc_msgSend)(gCBROverlayWindow, sel_registerName("setHidden:"), YES); gCBROverlayWindow = nil; } } @catch(...) {}
        gCBRRootWindow = nil; gCBRAppVC = nil; gCBRActiveTxns = nil; gCBRSceneHandle = nil; gCBRContainerView = nil; gCBRHomeButton = nil;   // v3.51.0: release the grafted scene handle (leak = CarPlay content still composited after disconnect -> phone screenshot duplication) + container + button
        // v3.20.32: NOW release keep-alive (the .25 retain kept the app running -> audio continued +
        // left it in a half-state that black-screened on reopen). Releasing lets it suspend cleanly.
        @try { if (gCBRKeepAlive) [gCBRKeepAlive removeAllObjects]; } @catch(...) {}
        DD("[host] dismissed (backgrounded + keep-alive released)\n");
        { int _lf=open("/var/mobile/CBR_lifecycle.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_lf>=0){ char _lb[80]; int _ln=snprintf(_lb,sizeof(_lb),"[HOST-END] hard=%d\n", _hard); if(_ln>0)write(_lf,_lb,(size_t)_ln); close(_lf);} }   // v3.60.0
        if(fd>=0)close(fd);
        #undef DD
    } @catch(...) {}
}

// v3.20.23: target object for the CarPlay exit button (UIButton needs an ObjC target+selector).
@interface CBRExitTarget : NSObject
@end
@implementation CBRExitTarget
- (void)cbrExitTapped { int _f=open("/var/mobile/CBR_home.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ const char*m="EXIT-TAPPED fired -> dismiss\n"; write(_f,m,strlen(m)); close(_f);} cbrSBHostDismiss(); }   // v3.52.0 home diag
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


static int gCBRZoomDone = 0;   // v3.64.0: 1 once the open zoom has fired for this host
// v3.64.0 OPEN-ANIM HEARTBEAT: the grafted scene renders async, so we can't zoom at mount (empty
// box). Poll the scene view every 50ms; when it has real content, fire the zoom-in of the LIVE app
// out of the icon (0.8s fallback so it never sticks tiny). Logs the timing for tuning.
static void cbrAnimHeartbeat(int n) {
    if (n > 40) return;   // ~2s cap
    @try {
        id cont = gCBRContainerView;
        id dvc = gCBRAppVC ? getIvar(gCBRAppVC, "_deviceAppViewController") : nil;
        id sv  = dvc ? getIvar(dvc, "_sceneView") : nil;
        CGRect svb = sv ? ((CGRect(*)(id,SEL))objc_msgSend)(sv, sel_registerName("bounds")) : CGRectZero;
        id svl = sv ? ((id(*)(id,SEL))objc_msgSend)(sv, sel_registerName("layer")) : nil;
        id subs = svl ? ((id(*)(id,SEL))objc_msgSend)(svl, sel_registerName("sublayers")) : nil;
        NSUInteger nsub = subs ? ((NSUInteger(*)(id,SEL))objc_msgSend)(subs, sel_registerName("count")) : 0;
        CGAffineTransform ct = CGAffineTransformIdentity;
        if (cont) { id l = ((id(*)(id,SEL))objc_msgSend)(cont, sel_registerName("layer")); if (l) ct = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(l, sel_registerName("affineTransform")); }
        // v3.65.0: also inspect the mounted appVC.view (some apps render there, not on the scene
        // view) + tag the bid, so a WORKING app (TrollStore/Dropbox) can be diffed against an abrupt one.
        const char *_bid = gCBRLastBidStr ? ((const char*(*)(id,SEL))objc_msgSend)(gCBRLastBidStr, sel_registerName("UTF8String")) : "?";
        id _vcv = gCBRAppVC ? ((id(*)(id,SEL))objc_msgSend)(gCBRAppVC, sel_registerName("view")) : nil;
        CGRect _vcb = _vcv ? ((CGRect(*)(id,SEL))objc_msgSend)(_vcv, sel_registerName("bounds")) : CGRectZero;
        id _vcl = _vcv ? ((id(*)(id,SEL))objc_msgSend)(_vcv, sel_registerName("layer")) : nil;
        id _vsubs = _vcl ? ((id(*)(id,SEL))objc_msgSend)(_vcl, sel_registerName("sublayers")) : nil;
        NSUInteger _vnsub = _vsubs ? ((NSUInteger(*)(id,SEL))objc_msgSend)(_vsubs, sel_registerName("count")) : 0;
        int fd = open("/var/mobile/CBR_anim_heartbeat.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (fd >= 0) { char _b[340]; int _l = snprintf(_b,sizeof(_b),"hb[%d] bid=%s zoomDone=%d contScale=%.2f sv=%s %.0fx%.0f svSub=%lu vcView=%s %.0fx%.0f vcSub=%lu\n", n, _bid, gCBRZoomDone, ct.a, sv?object_getClassName(sv):"nil", svb.size.width, svb.size.height, (unsigned long)nsub, _vcv?object_getClassName(_vcv):"nil", _vcb.size.width, _vcb.size.height, (unsigned long)_vnsub); if(_l>0) write(fd,_b,(size_t)_l); close(fd); }
        int _ready = (nsub > 0 || _vnsub > 0 || svb.size.width > 100.0 || _vcb.size.width > 100.0);
        if (!gCBRZoomDone && cont && (_ready || n >= 16)) {
            gCBRZoomDone = 1;
            void (^_anim)(void) = ^{
                ((void(*)(id,SEL,CGFloat))objc_msgSend)(cont, sel_registerName("setAlpha:"), (CGFloat)1.0);
                ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(cont, sel_registerName("setTransform:"), CGAffineTransformIdentity);
            };
            ((void(*)(Class,SEL,double,double,NSUInteger,void(^)(void),void(^)(BOOL)))objc_msgSend)(
                objc_getClass("UIView"), sel_registerName("animateWithDuration:delay:options:animations:completion:"),
                0.40, 0.0, (NSUInteger)(2UL<<16), _anim, (void(^)(BOOL))nil);
            return;   // zoom fired - stop the heartbeat
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.05*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrAnimHeartbeat(n+1); });
    } @catch(...) {}
}
static void cbrSBHostScene(const char *bid_cstr, id handle) {
    int fd = open("/var/mobile/CBR_sb_host.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    #define HH(s)  do{ if(fd>=0) write(fd,(s),strlen(s)); }while(0)
    #define HHF(...) do{ char _b[420]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,_n);}while(0)
    HH("==== HOST SCENE v3.18.0 (port) ====\n");
    if (!bid_cstr || !bid_cstr[0]) { HH("no bid\n"); if(fd>=0)close(fd); return; }
    if (!handle) { HH("no handle -> abort\n"); if(fd>=0)close(fd); return; }
    { int _lf=open("/var/mobile/CBR_lifecycle.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_lf>=0){ char _lb[240]; int _ln=snprintf(_lb,sizeof(_lb),"[HOST-START] bid=%s prevRootWin=%d prevScene=%d keepAlive=%lu\n", bid_cstr, gCBRRootWindow?1:0, gCBRSceneHandle?1:0, (unsigned long)(gCBRKeepAlive?[gCBRKeepAlive count]:0)); if(_ln>0)write(_lf,_lb,(size_t)_ln); close(_lf);} }   // v3.60.0 lifecycle probe
    // v3.20.3: don't blind-toggle on a possibly-stale global. Tear down old window and
    // continue hosting the freshly-tapped app. Fixes "worked once, black after".
    if (gCBRRootWindow) { HH("was hosting -> dismiss old, re-host fresh\n"); gCBRHardDismiss = 1; cbrSBHostDismiss(); }
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
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.orient.landscape"), NULL, NULL, YES);
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
        // v3.20.77 GAMBLE: host at the car screen's TRUE landscape size instead of portrait 281x472.
        @try {
            id _scr=((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("screens"));
            NSUInteger _sn=_scr?((NSUInteger(*)(id,SEL))objc_msgSend)(_scr,sel_registerName("count")):0;
            for(NSUInteger _i=0;_i<_sn;_i++){ id _s=((id(*)(id,SEL,NSUInteger))objc_msgSend)(_scr,sel_registerName("objectAtIndex:"),_i);
                int _c=[_s respondsToSelector:sel_registerName("_isCarScreen")]?((BOOL(*)(id,SEL))objc_msgSend)(_s,sel_registerName("_isCarScreen")):0;
                if(_c){ CGRect _cb=((CGRect(*)(id,SEL))objc_msgSend)(_s,sel_registerName("bounds"));
                    CGFloat _lw=_cb.size.width>_cb.size.height?_cb.size.width:_cb.size.height;
                    CGFloat _lh=_cb.size.width>_cb.size.height?_cb.size.height:_cb.size.width;
                    if(_lw>0){ ((void(*)(id,SEL,CGRect))objc_msgSend)(rootWindow,sel_registerName("setBounds:"),CGRectMake(0,0,_lw,_lh));
                        ((void(*)(id,SEL,CGRect))objc_msgSend)(rootWindow,sel_registerName("setFrame:"),CGRectMake(0,0,_lw,_lh));
                        // v3.50.0: prefer the CarPlay-measured sidebar width (com.cbr.sidebar.w);
                        // fall back to 10% only if nothing has been published yet.
                        { uint64_t _mw = 0; static int _mt = 0;
                          if (!_mt) notify_register_check("com.cbr.sidebar.w", &_mt);
                          if (_mt) notify_get_state(_mt, &_mw);
                          if (_mw > 0) { gCBRSidebarW = (CGFloat)_mw; HHF("[v3.50.0] sidebar width MEASURED = %.0fpt\n", gCBRSidebarW); }
                          else { gCBRSidebarW = (CGFloat)((int)(_lw * 0.10 + 0.5)); HHF("[v3.50.0] sidebar width fallback (no measurement) = %.0fpt\n", gCBRSidebarW); } }
                        HHF("[GAMBLE] window car landscape %.0fx%.0f sidebar=%.0f\n",_lw,_lh,gCBRSidebarW); }
                    break; } }
        } @catch(...) { HH("[GAMBLE] window resize threw\n"); }
        @try { id layer = cb(rootWindow, "layer"); ((void(*)(id,SEL,CGFloat))objc_msgSend)(layer, sel_registerName("setCornerRadius:"), (CGFloat)13.0); ((void(*)(id,SEL,BOOL))objc_msgSend)(layer, sel_registerName("setMasksToBounds:"), YES); } @catch(...) {}
        // v3.44.0 NATIVE-CHROME REVEAL. Colin confirmed the CarPlay chrome (clock/signal/recents/
        // dashboard button) is ALIVE UNDERNEATH our host window - a prior bad-render boot showed it
        // through - so this is pure occlusion, not teardown. Make the host window transparent so the
        // uncovered sidebar strip composites the real chrome through, instead of drawing our own dock.
        @try {
            ((void(*)(id,SEL,BOOL))objc_msgSend)(rootWindow, sel_registerName("setOpaque:"), NO);
            id _cl = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
            ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("setBackgroundColor:"), _cl);
            HH("[v3.44.0] host window transparent - reveal native chrome beneath\n");
        } @catch(...) {}
        // v3.20.26: force the WINDOW itself to landscape (orientation 3); scene orientation
        // alone leaves it portrait on auto-launch. Guarded + logged for iOS 17.
        @try {
            SEL _rot = sel_registerName("_rotateWindowToOrientation:updateStatusBar:duration:skipCallbacks:");
            if ([rootWindow respondsToSelector:_rot]) {
                (void)_rot;
                HH("[GAMBLE] window rotation SKIPPED (native landscape host)\n");
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
            // v3.44.0: inset the app container by the SIDEBAR width so the app never covers the native
            // chrome strip on the left. The strip is left transparent (window is clear) so the real
            // CarPlay sidebar shows through, and hitTest passes its touches down (see UIRootSceneWindow
            // hook), so the native dashboard button - not a custom one - is what returns to the dash.
            // v3.52.0 CHROME-OVERLAP: inset the app ~10pt LESS than the chrome width so its opaque
            // left edge extends UNDER the chrome and covers the dashboard sliver that showed in the
            // seam. 47pt landed the edge in the gap on every prior build; overlapping kills it. If
            // the chrome glyph ever looks clipped, lower _overlap; if a sliver returns, raise it.
            CGFloat _chromeW = gCBRSidebarW > 0 ? gCBRSidebarW : wf.size.width * 0.11;
            // v3.53.0: 10pt reached into the sidebar and covered the recents icons (couldn't tap
            // them). 4pt still swallows the thin dashboard sliver without intruding on the icons.
            CGFloat _overlap = 4.0;
            CGFloat sbW = _chromeW - _overlap; if (sbW < 0) sbW = 0;
            HHF("[v3.53.0] chrome overlap: chromeW=%.0f overlap=%.0f -> app inset=%.0f\n", _chromeW, _overlap, sbW);
            Class UIViewCls = objc_getClass("UIView");
            id container = ((id(*)(id,SEL,CGRect))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(UIViewCls, sel_registerName("alloc")), sel_registerName("initWithFrame:"), CGRectMake(sbW, 0, wf.size.width - sbW, wf.size.height));
            id clear = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
            ((void(*)(id,SEL,id))objc_msgSend)(container, sel_registerName("setBackgroundColor:"), clear);
            ((void(*)(id,SEL,BOOL))objc_msgSend)(container, sel_registerName("setClipsToBounds:"), YES);
            ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("addSubview:"), container);
            gCBRContainerView = container;
            id vcView = cb(appVC, "view");
            ((void(*)(id,SEL,CGRect))objc_msgSend)(vcView, sel_registerName("setFrame:"), CGRectMake(0, 0, wf.size.width - sbW, wf.size.height));
            ((void(*)(id,SEL,id))objc_msgSend)(container, sel_registerName("addSubview:"), vcView);
            HHF("mounted appVC.view inset by %.0fpt sidebar (native chrome revealed)\n", sbW);
            // v3.51.0 OPEN ANIMATION: ZOOM-FROM-ICON, not fade. Anchor the container's zoom at
            // the tapped dashboard icon (published by CarPlay over com.cbr.icon.center; center
            // fallback), so the app grows out of the icon and the close zoom shrinks back into
            // it - stock CarPlay behavior.
            @try {
                @try {
                    uint64_t _icv = 0; static int _ict2 = 0;
                    if (!_ict2) notify_register_check("com.cbr.icon.center", &_ict2);
                    if (_ict2) notify_get_state(_ict2, &_icv);
                    id _clyr2 = ((id(*)(id,SEL))objc_msgSend)(container, sel_registerName("layer"));
                    CGRect _cf2 = ((CGRect(*)(id,SEL))objc_msgSend)(container, sel_registerName("frame"));
                    if (_clyr2 && _cf2.size.width > 0 && _cf2.size.height > 0) {
                        CGFloat _ax = 0.5, _ay = 0.5;
                        if (_icv) {
                            CGFloat _ix = (CGFloat)((_icv >> 16) & 0xFFFF), _iy = (CGFloat)(_icv & 0xFFFF);
                            _ax = (_ix - _cf2.origin.x) / _cf2.size.width; _ay = _iy / _cf2.size.height;
                            if (_ax < 0.02) _ax = 0.02; if (_ax > 0.98) _ax = 0.98;
                            if (_ay < 0.02) _ay = 0.02; if (_ay > 0.98) _ay = 0.98;
                        }
                        ((void(*)(id,SEL,CGPoint))objc_msgSend)(_clyr2, sel_registerName("setAnchorPoint:"), CGPointMake(_ax, _ay));
                        ((void(*)(id,SEL,CGPoint))objc_msgSend)(_clyr2, sel_registerName("setPosition:"), CGPointMake(_cf2.origin.x + _ax*_cf2.size.width, _cf2.origin.y + _ay*_cf2.size.height));
                        HHF("[v3.51.0] zoom origin %s ax=%.2f ay=%.2f\n", _icv ? "ICON" : "center(fallback)", _ax, _ay);
                    }
                } @catch(...) {}
                ((void(*)(id,SEL,CGFloat))objc_msgSend)(container, sel_registerName("setAlpha:"), (CGFloat)0.35);
                CGAffineTransform _start = CGAffineTransformMakeScale(0.30, 0.30);
                ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(container, sel_registerName("setTransform:"), _start);
                // v3.64.0: DON'T animate now - the grafted scene renders async so this would zoom an
                // EMPTY box. Hold at 0.30 (small, at the icon) and let the heartbeat fire the zoom-in
                // once the scene view has real content, so the LIVE app grows out of the icon.
                gCBRZoomDone = 0;
                { int _hf=open("/var/mobile/CBR_anim_heartbeat.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_hf>=0){ char _hb2[160]; int _hn=snprintf(_hb2,sizeof(_hb2),"==== OPEN bid=%s ====\n", bid_cstr?bid_cstr:"?"); if(_hn>0)write(_hf,_hb2,(size_t)_hn); close(_hf);} }   // v3.65.0: per-open header, accumulate so working vs abrupt apps can be compared
                cbrAnimHeartbeat(0);
            } @catch(...) {}
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
                                            // v3.20.35: sync the app's content FRAME to the actual car window size so
                                            // app-content-space == rendered-view-space == touch-space. Fixes zoom (content
                                            // was 430x932 squished into a 240x400 view) AND touch-offset (scroll landed on
                                            // the video because touch coords mapped through the wrong content size).
                                            @try {
                                                CGRect _wb = gCBRRootWindow ? ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds")) : CGRectZero;
                                                if (_wb.size.width > 0 && _wb.size.height > 0) {
                                                    // v3.20.36: use LANDSCAPE dims. Display config reports portrait point
                                                    // space (e.g. 240x400) but the physical car screen is landscape, so the
                                                    // app must render at the SWAPPED size (400x240) to fill it instead of a
                                                    // portrait strip (screenshot showed correct content but portrait-shaped).
                                                    SEL _sf = sel_registerName("setFrame:");
                                                    // v3.26.5: BORN-CORRECT. Set the PHONE-PORTRAIT canvas at CREATION (derived from the
                                                    // live screen, no fallback), not car-landscape, so the app is never born sideways.
                                                    CGFloat _ppw=0,_pph=0;
                                                    @try { id _ms=((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIScreen"),sel_registerName("mainScreen"));
                                                        if(_ms){ CGRect _mb=((CGRect(*)(id,SEL))objc_msgSend)(_ms,sel_registerName("bounds"));
                                                            _ppw=_mb.size.width<_mb.size.height?_mb.size.width:_mb.size.height;
                                                            _pph=_mb.size.width<_mb.size.height?_mb.size.height:_mb.size.width; } } @catch(...) {}
                                                    if ([mutableSettings respondsToSelector:_sf] && _ppw>0) {
                                                        // v3.28.0: LANDSCAPE canvas. A portrait canvas must be rotated 90deg to fit the
                                                        // landscape car window -> sideways, unless the app rotates itself (Amazon does;
                                                        // YouTube/YT-TV are portrait-locked and don't). Landscape matches the car aspect.
                                                        // Capture proof: window 932x430 = UPRIGHT, 430x932 = SIDEWAYS (identity xforms).
                                                        // v3.42.0 CANVAS UNIFICATION. Three writers touched settings.frame: this
                                                        // block (932x430 since v3.28.0), the keep-alive frame guard (430x932) and
                                                        // the 1s re-drive (430x932). The last two run continuously, so the scene
                                                        // lived at 430x932 FIXED-space + ifo=3 anyway - which IS the good steady
                                                        // state (DRV probes: GOOD = frame 430x932 + window 932x430; the window
                                                        // derives landscape from ifo=3, the frame stays in fixed portrait space).
                                                        // This block writing 932x430 only injected a competing shape for the first
                                                        // second - a re-layout trigger at the worst possible moment - before being
                                                        // stomped. Write the SAME fixed canvas as every other writer.
                                                        ((void(*)(id,SEL,CGRect))objc_msgSend)(mutableSettings, _sf, CGRectMake(0,0,_ppw,_pph));
                                                        CHF("[FIX-GEOM] settings.frame set PHONE-FIXED %.0fx%.0f ifo=3 (car %.0fx%.0f)\n", _ppw, _pph, _wb.size.width, _wb.size.height);
                                                    }
                                                }
                                            } @catch(...) { CH("[FIX-GEOM] frame sync threw\n"); }
                                            // [FIX-CRS] v3.20.28: content reference size = the CAR's size (dynamic per vehicle),
                                            // so the app re-lays-out for the real display instead of stretching a phone-sized render.
                                            @try {
                                                CGRect _cwb = gCBRRootWindow ? ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds")) : CGRectZero;
                                                if (_cwb.size.width > 0 && _cwb.size.height > 0) {
                                                    // v3.20.32: setFrame/orientation-lock REMOVED - the car bounds came back
                                                    // portrait (281x472) so setFrame made the app render phone-portrait (stretch bug).
                                                    // Window rotation alone handled orientation correctly in earlier builds.

                                                    // v3.20.60: RE-ENABLED two-arg canvas+orientation (CarBridge's linchpin).
                                                    // Prior disable (v3.20.32) passed RAW portrait size (281x472) -> stretch bug.
                                                    // Fix: pass LANDSCAPE-swapped size + orientation 3, like the [FIX-GEOM] block above.
                                                    CGFloat _clw = _cwb.size.width, _clh = _cwb.size.height;
                                                    if (_clh > _clw) { CGFloat _t=_clw; _clw=_clh; _clh=_t; }  // ensure landscape (w>h)
                                                    // v3.20.61: iOS17 has NO setContentReferenceSize; use ANGLE-based API (from settings dump).
                                                    SEL _angM = sel_registerName("setHostReferenceAngleMode:");
                                                    SEL _sbi  = sel_registerName("setScreenBoundsIgnoresSceneOrientation:");
                                                    SEL _ang  = sel_registerName("setAngleFromHostReferenceUprightDirection:");
                                                    // v3.27.0 THE ROTATION BUG. Leftover CALIBRATION loop from v3.20.61: it cycled
                                                    // setAngleFromHostReferenceUprightDirection: through idx0=0deg idx1=+90deg
                                                    // idx2=-90deg idx3=180deg, advancing ONE STEP PER APP OPEN via a static counter,
                                                    // and was never finalized. That IS the "random" rotation - idx1 (+pi/2) is the
                                                    // 90-degrees-left render. It also explains why a RESPRING always fixed it: respring
                                                    // restarts SpringBoard, the static resets to 0, first open gets angle 0 (upright).
                                                    // FIX: pin the angle to 0 (upright) and stop cycling.
                                                    double _use = 0.0;
                                                    if ([mutableSettings respondsToSelector:_sbi]) ((void(*)(id,SEL,BOOL))objc_msgSend)(mutableSettings, _sbi, YES);
                                                    if ([mutableSettings respondsToSelector:_angM]) ((void(*)(id,SEL,NSInteger))objc_msgSend)(mutableSettings, _angM, (NSInteger)1);
                                                    SEL _crs = _ang;
                                                    if ([mutableSettings respondsToSelector:_crs]) {
                                                        ((void(*)(id,SEL,double))objc_msgSend)(mutableSettings, _ang, _use);
                                                        CHF("[FIX-CRS] iOS17 angle PINNED %.4f (upright, no calibration cycle)\n", _use);
                                                    } else {
                                                        SEL _crs2 = sel_registerName("setContentReferenceSize:");
                                                        if ([mutableSettings respondsToSelector:_crs2]) { ((void(*)(id,SEL,CGSize))objc_msgSend)(mutableSettings, _crs2, CGSizeMake(_clw,_clh)); CH("[FIX-CRS] fallback 1-arg setContentReferenceSize applied\n"); }
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
                                        // v3.42.0: size to the inset container so the render sits right of the dock.
                                        id szHost = gCBRContainerView ?: gCBRRootWindow;
                                        CGRect wf = ((CGRect(*)(id,SEL))objc_msgSend)(szHost, sel_registerName("bounds"));
                                        ((void(*)(id,SEL,CGRect))objc_msgSend)(rdSv, sel_registerName("setFrame:"), CGRectMake(0,0,wf.size.width,wf.size.height));
                                        CH("REDRIVE(comp) sized live sceneView to app container\n");
                                        // v3.20.34: GEOMETRY PROBE - capture actual coordinate spaces so we fix
                                        // the zoom/touch-offset correctly (last setFrame guess used portrait bounds).
                                        @try {
                                            int gf = open("/var/mobile/CBR_geom.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
                                            #define GG(...) do{ char _b[300]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(gf>=0)write(gf,_b,_n);}while(0)
                                            GG("==== GEOMETRY PROBE ====\n");
                                            if (gCBRRootWindow) {
                                                CGRect wb=((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow,sel_registerName("bounds"));
                                                CGRect wf=((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow,sel_registerName("frame"));
                                                GG("window bounds=%.0fx%.0f frame=%.0f,%.0f %.0fx%.0f\n", wb.size.width,wb.size.height, wf.origin.x,wf.origin.y,wf.size.width,wf.size.height);
                                                @try { CGAffineTransform t=((CGAffineTransform(*)(id,SEL))objc_msgSend)(gCBRRootWindow,sel_registerName("transform")); GG("window transform=[%.2f %.2f %.2f %.2f %.1f %.1f]\n", t.a,t.b,t.c,t.d,t.tx,t.ty); } @catch(...) {}
                                            }
                                            id dvc = gCBRAppVC ? getIvar(gCBRAppVC, "_deviceAppViewController") : nil;
                                            id sv = dvc ? getIvar(dvc, "_sceneView") : nil;
                                            if (sv) {
                                                CGRect sb=((CGRect(*)(id,SEL))objc_msgSend)(sv,sel_registerName("bounds"));
                                                CGRect sf=((CGRect(*)(id,SEL))objc_msgSend)(sv,sel_registerName("frame"));
                                                GG("sceneView bounds=%.0fx%.0f frame=%.0f,%.0f %.0fx%.0f\n", sb.size.width,sb.size.height, sf.origin.x,sf.origin.y,sf.size.width,sf.size.height);
                                                @try { CGAffineTransform t=((CGAffineTransform(*)(id,SEL))objc_msgSend)(sv,sel_registerName("transform")); GG("sceneView transform=[%.2f %.2f %.2f %.2f %.1f %.1f]\n", t.a,t.b,t.c,t.d,t.tx,t.ty); } @catch(...) {}
                                            }
                                            // the scene settings' current frame + orientation
                                            if (scn) {
                                                id st=[scn respondsToSelector:sel_registerName("settings")]?((id(*)(id,SEL))objc_msgSend)(scn,sel_registerName("settings")):nil;
                                                if (st) {
                                                    @try { CGRect stf=((CGRect(*)(id,SEL))objc_msgSend)(st,sel_registerName("frame")); GG("settings.frame=%.0f,%.0f %.0fx%.0f\n", stf.origin.x,stf.origin.y,stf.size.width,stf.size.height); } @catch(...) {}
                                                    @try { NSInteger io=((NSInteger(*)(id,SEL))objc_msgSend)(st,sel_registerName("interfaceOrientation")); GG("settings.interfaceOrientation=%ld\n",(long)io); } @catch(...) {}
                                                }
                                            }
                                            GG("==== END ====\n");
                                            if(gf>=0)close(gf);
                                            #undef GG
                                        } @catch(...) {}
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

        // v3.44.0: custom dock REMOVED - the native CarPlay chrome shows through the transparent strip.
        HH("[v3.44.0] native chrome reveal - custom dock not drawn\n");
        // v3.46.0 HOME BUTTON. The native home/dashboard button (bottom of the sidebar) can't work via
        // pure passthrough: CarPlay thinks it is ALREADY on the dashboard (our host window is invisible
        // to it), so its home tap is a no-op. Overlay a transparent dismiss target on exactly that spot -
        // the user still sees the native glyph, and tapping it tears our window down = back to the dash.
        // The rest of the sidebar (status, recents) still passes through (recents launch handoff works).
        @try {
            if (!gCBRExitTarget) gCBRExitTarget = [[CBRExitTarget alloc] init];
            CGRect _wb = ((CGRect(*)(id,SEL))objc_msgSend)(rootWindow, sel_registerName("bounds"));
            CGFloat _hz = 50.0; gCBRHomeZoneH = _hz;
            CGFloat _sbw = gCBRSidebarW > 0 ? gCBRSidebarW : 47.0;
            id _hb = ((id(*)(Class,SEL,long))objc_msgSend)(objc_getClass("UIButton"), sel_registerName("buttonWithType:"), (long)0);
            ((void(*)(id,SEL,CGRect))objc_msgSend)(_hb, sel_registerName("setFrame:"), CGRectMake(0, _wb.size.height - _hz, _sbw, _hz));
            id _clr = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
            ((void(*)(id,SEL,id))objc_msgSend)(_hb, sel_registerName("setBackgroundColor:"), _clr);
            ((void(*)(id,SEL,id,SEL,unsigned long))objc_msgSend)(_hb, sel_registerName("addTarget:action:forControlEvents:"), gCBRExitTarget, sel_registerName("cbrExitTapped"), (unsigned long)(1UL<<6));
            ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("addSubview:"), _hb);
            ((void(*)(id,SEL,id))objc_msgSend)(rootWindow, sel_registerName("bringSubviewToFront:"), _hb);
            gCBRHomeButton = _hb;   // v3.51.0: kept so hitTest can return it explicitly
            HH("[v3.51.0] home-button dismiss zone added + stored (bottom sidebar)\n");
        } @catch(...) { HH("home zone failed\n"); }
        // v3.53.0 HOME BUTTON via SEPARATE OVERLAY WINDOW - the v3.20.31 mechanism Colin confirmed
        // PROVABLY exited the app. The subview button above fails because it sits UNDER the app's
        // full-screen scene view in the SAME window, which swallows the tap. A separate
        // UIRootSceneWindow at level 100 sits ABOVE the scene view so its button actually gets the
        // tap. Transparent; its hitTest (below) passes everything except the home zone through, so
        // recents + app are untouched. No makeKeyAndVisible (keeps the app scene's active state
        // clean for the orientation work).
        @try {
            if (!gCBRExitTarget) gCBRExitTarget = [[CBRExitTarget alloc] init];
            CGRect _owb = ((CGRect(*)(id,SEL))objc_msgSend)(rootWindow, sel_registerName("bounds"));
            // v3.54.0: overlay window DISABLED - zero OVERLAY-HIT in the logs (the CarPlay chrome
            // owns the sidebar touches, not our SpringBoard window stack), and a full-display
            // level-100 window only risked the recents inconsistency. Home needs a CarPlay-side hook.
            id _ovl = nil;
            if (_ovl) {
                gCBROverlayWindow = _ovl;
                ((void(*)(id,SEL,double))objc_msgSend)(_ovl, sel_registerName("setWindowLevel:"), (double)100.0);
                ((void(*)(id,SEL,BOOL))objc_msgSend)(_ovl, sel_registerName("setOpaque:"), NO);
                id _oclr = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIColor"), sel_registerName("clearColor"));
                ((void(*)(id,SEL,id))objc_msgSend)(_ovl, sel_registerName("setBackgroundColor:"), _oclr);
                CGFloat _obw = gCBRSidebarW > 0 ? gCBRSidebarW : 47.0;
                CGFloat _obz = gCBRHomeZoneH > 0 ? gCBRHomeZoneH : 50.0;
                id _obtn = ((id(*)(Class,SEL,long))objc_msgSend)(objc_getClass("UIButton"), sel_registerName("buttonWithType:"), (long)0);
                ((void(*)(id,SEL,CGRect))objc_msgSend)(_obtn, sel_registerName("setFrame:"), CGRectMake(0, _owb.size.height - _obz, _obw, _obz));
                ((void(*)(id,SEL,id))objc_msgSend)(_obtn, sel_registerName("setBackgroundColor:"), _oclr);
                ((void(*)(id,SEL,id,SEL,unsigned long))objc_msgSend)(_obtn, sel_registerName("addTarget:action:forControlEvents:"), gCBRExitTarget, sel_registerName("cbrExitTapped"), (unsigned long)(1UL<<6));
                ((void(*)(id,SEL,id))objc_msgSend)(_ovl, sel_registerName("addSubview:"), _obtn);
                gCBROverlayBtn = _obtn;
                ((void(*)(id,SEL,BOOL))objc_msgSend)(_ovl, sel_registerName("setHidden:"), NO);
                HH("[v3.53.0] home button in SEPARATE overlay window level 100 (proven exit mechanism)\n");
            } else { HH("[v3.53.0] overlay window alloc failed - subview button is the fallback\n"); }
        } @catch(...) { HH("overlay home button failed\n"); }
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

static CGFloat gCBRPhoneW = 0, gCBRPhoneH = 0;   // phone PORTRAIT canvas - derived from the live screen
static void cbrEnsurePhoneSize(void) {
    if (gCBRPhoneW > 0) return;
    @try {
        id ms = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIScreen"), sel_registerName("mainScreen"));
        if (!ms) return;
        CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(ms, sel_registerName("bounds"));
        CGFloat w = b.size.width, h = b.size.height;
        if (w <= 0 || h <= 0) return;
        gCBRPhoneW = (w < h) ? w : h;
        gCBRPhoneH = (w < h) ? h : w;
    } @catch(...) {}
}
// v3.35.0 THE CARPLAY-CAST MECHANISM. CBR tried to make the CarPlay COMPOSITOR produce the right
// rotation via scene geometry (frame/bounds/orientation/angle/activation) - seven levers, all dead.
// carplay-cast renders upright 100% of the time and never asks the compositor to rotate anything:
//   1. the APP rotates itself to landscape (_setRotatableViewOrientation on the key window, force=1)
//   2. SpringBoard SCALES the content view onto the car display with a plain affine scale:
//        content = _sceneContentContainerView of the app's _sceneView
//        mainSz  = [UIScreen.main boundsForOrientation:3]     (932x430)
//        scale   = carSize / mainSz                            (400/932, 240/430)
//        [content setTransform:CGAffineTransformMakeScale(w,h)]
// No compositor rotation is requested at all - which is why it cannot come out sideways.
static void cbrApplyCarplayCastScale(void) {
    @try {
        if (!gCBRAppVC || !gCBRRootWindow) return;
        id dvc = getIvar(gCBRAppVC, "_deviceAppViewController");
        id sv  = dvc ? getIvar(dvc, "_sceneView") : nil;
        if (!sv) return;
        // v3.35.1: the ivar is NOT always _sceneContentContainerView - CBR's own render path already
        // falls back to _contentContainerView. v3.35.0 had no fallback, so getIvar returned nil and
        // the scale bailed silently (zero CPC-SCALE lines). Our scene view is
        // SBDeviceApplicationSceneView (carplay-cast asserts SBSceneView) so names differ.
        id content = getIvar(sv, "_sceneContentContainerView");
        if (!content) content = getIvar(sv, "_contentContainerView");
        if (!content) content = getIvar(sv, "_contentView");
        if (!content) {
            int _f = open("/var/mobile/CBR_sb_host.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
            if (_f >= 0) { char _b[200]; int _n = snprintf(_b,sizeof(_b),
                "[CPC-SCALE] NO content ivar on %s - dumping ivars\n", object_getClassName(sv));
                if(_n>0) write(_f,_b,(size_t)_n);
                unsigned int _c=0; Ivar *_iv = class_copyIvarList(object_getClass(sv), &_c);
                for (unsigned int _i=0;_i<_c;_i++){ int _m=snprintf(_b,sizeof(_b),"    ivar: %s\n", ivar_getName(_iv[_i])); if(_m>0) write(_f,_b,(size_t)_m); }
                if(_iv) free(_iv);
                close(_f); }
            return;
        }
        // v3.42.0: scale to the INSET container (car width minus the dock), not the full window.
        id scaleHost = gCBRContainerView ?: gCBRRootWindow;
        CGRect carB = ((CGRect(*)(id,SEL))objc_msgSend)(scaleHost, sel_registerName("bounds"));
        if (carB.size.width <= 0 || carB.size.height <= 0) return;
        id mainScr = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIScreen"), sel_registerName("mainScreen"));
        if (!mainScr) return;
        CGSize msz;
        SEL bfo = sel_registerName("boundsForOrientation:");
        if ([mainScr respondsToSelector:bfo]) {
            msz = ((CGRect(*)(id,SEL,int))objc_msgSend)(mainScr, bfo, 3).size;
        } else {
            CGRect mb = ((CGRect(*)(id,SEL))objc_msgSend)(mainScr, sel_registerName("bounds"));
            msz.width  = mb.size.width > mb.size.height ? mb.size.width  : mb.size.height;
            msz.height = mb.size.width > mb.size.height ? mb.size.height : mb.size.width;
        }
        if (msz.width <= 0 || msz.height <= 0) return;
        // v3.52.0: REVERTED the v3.51 anchor-pin + content-bounds divisor. Using the content's OWN
        // (already-scaled) bounds as the divisor made this frames scale depend on last frames scale
        // - a feedback loop that shrank the app a little more every FBScene tick (the runaway Colin
        // saw). Back to the stable v3.50 math: fixed main-screen landscape size, center anchor. The
        // chrome gap is now closed by the container OVERLAP inset instead (see cbrSBHostScene).
        CGFloat wScale = carB.size.width  / msz.width;
        CGFloat hScale = carB.size.height / msz.height;
        CGAffineTransform cur = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(content, sel_registerName("transform"));
        if (fabs(cur.a - wScale) > 0.001 || fabs(cur.d - hScale) > 0.001) {
            CGAffineTransform _final = CGAffineTransformMakeScale(wScale, hScale);
            if (!gCBRScaleAnimated) {
                // v3.52.0 SCENE GROW-IN: the container zoom animates the chrome frame, but the apps
                // render surface attaches async AFTER that and popped in. The first time we scale it
                // this host, start ~12% smaller and grow to final so the surface has its own entrance.
                gCBRScaleAnimated = 1;
                @try {
                    ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(content, sel_registerName("setTransform:"), CGAffineTransformScale(_final, 0.88, 0.88));
                    void (^_grow)(void) = ^{ ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(content, sel_registerName("setTransform:"), _final); };
                    ((void(*)(Class,SEL,double,double,NSUInteger,void(^)(void),void(^)(BOOL)))objc_msgSend)(
                        objc_getClass("UIView"), sel_registerName("animateWithDuration:delay:options:animations:completion:"),
                        0.30, 0.0, (NSUInteger)(2UL<<16) /*EaseOut*/, _grow, (void(^)(BOOL))nil);
                } @catch(...) { ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(content, sel_registerName("setTransform:"), _final); }
            } else
            ((void(*)(id,SEL,CGAffineTransform))objc_msgSend)(content, sel_registerName("setTransform:"),
                _final);
            static int _sc=0;
            if (_sc++ < 12) {
                // CHF() needs a local cfd that only exists in the host block - write directly.
                int _f = open("/var/mobile/CBR_sb_host.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
                if (_f >= 0) {
                    char _b[300];
                    int _n = snprintf(_b, sizeof(_b),
                        "[CPC-SCALE v3.52.0] content %s scaled %.3f x %.3f (host %.0fx%.0f / main-landscape %.0fx%.0f stable)\n",
                        object_getClassName(content), wScale, hScale,
                        carB.size.width, carB.size.height, msz.width, msz.height);
                    if (_n > 0) write(_f, _b, (size_t)_n);
                    close(_f);
                }
            }
        }
    } @catch(...) {}
}

static void cbrSBSilentActivate(void);
// v3.42.0 BOUNCE - the programmatic phone-tap. The scene's CLIENT settings are the one feedback
// channel that reports how the app's UIKit ACTUALLY laid out (server settings are what we ASKED
// for; client settings are what the app DID). If, after launch settles, the app still reports
// portrait, replay the tap's activation edge: a real deactivate->reactivate VALUE CHANGE. The 1s
// re-drive never fixed a sideways boot because it wrote identical values every time - FBScene
// diffs settings and a no-change update never reaches the app. An EDGE does.
static void cbrSBBounceCheck(void) {
    @try {
        static double _lastChk = 0; struct timespec _dts; clock_gettime(CLOCK_MONOTONIC, &_dts);   // v3.49.0 chain-collapse
        double _dnow = _dts.tv_sec + _dts.tv_nsec/1e9;
        if (_dnow - _lastChk < 2.0) return;
        _lastChk = _dnow;
        int fd = open("/var/mobile/CBR_bounce.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        #define BB(...) do{ char _b[300]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(fd>=0)write(fd,_b,(size_t)_n);}while(0)
        id scn = gCBRSceneHandle ? ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("sceneIfExists")) : nil;
        if (!scn || !gCBRRootWindow) { BB("BOUNCE-CHECK no scene/host - stop\n"); if(fd>=0)close(fd); return; }
        long cifo = -99;
        @try {
            id cs = [scn respondsToSelector:sel_registerName("clientSettings")] ? ((id(*)(id,SEL))objc_msgSend)(scn, sel_registerName("clientSettings")) : nil;
            if (cs && [cs respondsToSelector:sel_registerName("interfaceOrientation")])
                cifo = ((long(*)(id,SEL))objc_msgSend)(cs, sel_registerName("interfaceOrientation"));
        } @catch(...) {}
        // v3.47.0: clientSettings proved to be an ACK of OUR writes (always 3), not what the
        // app's UIKit actually did - that false green is why no bounce ever fired while every
        // boot stayed sideways. Decide on the app-published TRUTH instead; log both so the
        // divergence (clientIfo=3 vs truth=1) is the smoking gun in this file.
        uint64_t _enc = 0;
        if (!gCBRTruthTokenSB) notify_register_check("com.cbr.app.truth", &gCBRTruthTokenSB);
        if (gCBRTruthTokenSB) notify_get_state(gCBRTruthTokenSB, &_enc);
        long tifo = (long)(_enc % 10); int tland = (int)((_enc / 10) % 10); long tvio = (long)((_enc / 100) % 10);   // v3.51.0 decode
        int contentPortrait = (tvio == 1 || tvio == 2);   // v3.51.0: rootVC laid out portrait = sideways composite
        { static uint64_t _le = 999999; static int _bc2 = 0;   // v3.49.0: log on change or 1-in-12
          if (_enc != _le || (_bc2++ % 12) == 0) BB("BOUNCE-CHECK clientIfo=%ld truth=%llu (ifo=%ld winLandscape=%d vio=%ld cp=%d) bounces=%d\n", cifo, (unsigned long long)_enc, tifo, tland, tvio, contentPortrait, gCBRBounceCount);
          _le = _enc; }
        if (_enc == 0) {
            static int _nt = 0;
            if (_nt++ < 4) { BB("no truth published yet - re-check in 3s (%d/4)\n", _nt); if(fd>=0)close(fd);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(3.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBBounceCheck(); });
                return; }
            // v3.51.0 BLIND-BOUNCE: an armed app publishes truth every second, so sustained
            // silence means the app never armed or its main queue never ran - exactly the
            // population that boots sideways. The edge is the proven manual-tap replay and a
            // no-op on a healthy app, so after the retries drive it anyway (max 2 per session);
            // the edge also resumes a stalled main queue, which un-blocks probe arming itself.
            if (gCBRBlindBounce < 2 && gCBRBounceCount < 3) {
                gCBRBlindBounce++;
                BB("BLIND-BOUNCE %d/2: no truth after retries - driving the edge anyway\n", gCBRBlindBounce);
            } else {
                static int _rl = 0; if ((_rl++ % 12) == 0) BB("truth never arrived - refusing to bounce blind (watching every 5s)\n");   // v3.49.0
                if(fd>=0)close(fd);
                dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(5.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBBounceCheck(); });
                return;
            }
        }
        if ((tifo == 3 || tifo == 4) && tland && !contentPortrait) {   // v3.51.0: the CONTENT must agree, not just the scene
            gCBRBounceCount = 0;   // v3.49.0: fresh 3-bounce budget per incident
            static int _hl = 0; if ((_hl++ % 12) == 0) BB("app TRULY landscape - upright; watching every 5s (budget reset)\n");
            if(fd>=0)close(fd);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(5.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBBounceCheck(); });
            return;
        }
        if (gCBRBounceCount >= 3) {
            static int _mx = 0; if ((_mx++ % 6) == 0) BB("max bounces reached for this incident - re-checking every 30s\n");   // v3.49.0
            if(fd>=0)close(fd);
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(30.0*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBBounceCheck(); });
            return; }
        gCBRBounceCount++;
        BB("BOUNCE#%d: driving deactivate edge (%s)\n", gCBRBounceCount, contentPortrait ? "CONTENT-PORTRAIT sideways composite" : (_enc == 0 ? "blind - no truth" : "scene portrait"));
        if (fd>=0) close(fd);
        #undef BB
        gCBRBounceBypass = 1;
        SEL upd = sel_registerName("updateSettingsWithBlock:");
        if ([scn respondsToSelector:upd]) {
            void (^down)(id) = ^(id ms){
                SEL s2 = sel_registerName("setDeactivated:");
                if ([ms respondsToSelector:s2]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms, s2, YES);
                s2 = sel_registerName("setDeactivationReasons:");
                if ([ms respondsToSelector:s2]) ((void(*)(id,SEL,NSUInteger))objc_msgSend)(ms, s2, (NSUInteger)0x2);
            };
            ((void(*)(id,SEL,id))objc_msgSend)(scn, upd, down);
        }
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.35*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
            gCBRBounceBypass = 0;
            cbrSBSilentActivate();   // the reactivate half: fg-ACTIVE + dr=0 + ifo=3 + phone frame
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(2.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBBounceCheck(); });
        });
    } @catch(...) { gCBRBounceBypass = 0; }
}
static void cbrSBSilentActivate(void) {
    @try {
        cbrEnsurePhoneSize();
        if (!gCBRSceneHandle) return;
        id scn = ((id(*)(id,SEL))objc_msgSend)(gCBRSceneHandle, sel_registerName("sceneIfExists"));
        if (!scn) return;
        SEL upd = sel_registerName("updateSettingsWithBlock:");
        if (![scn respondsToSelector:upd]) return;
        // v3.25.7 PROBE: capture scene + window state BEFORE each drive, so a good-open log can be
        // diffed against a bad-open log. The re-drive holds whatever state exists at open, so the
        // START state at the first drives is what decides upright vs sideways. Fully additive.
        static int _drv = 0; _drv++;
        @try {
            struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
            double _t = _ts.tv_sec + _ts.tv_nsec/1e9;
            id st = [scn respondsToSelector:sel_registerName("settings")] ? ((id(*)(id,SEL))objc_msgSend)(scn, sel_registerName("settings")) : nil;
            long sIfo = (st && [st respondsToSelector:sel_registerName("interfaceOrientation")]) ? ((long(*)(id,SEL))objc_msgSend)(st, sel_registerName("interfaceOrientation")) : -99;
            int sFg  = (st && [st respondsToSelector:sel_registerName("isForeground")]) ? ((BOOL(*)(id,SEL))objc_msgSend)(st, sel_registerName("isForeground")) : -1;
            int sDe  = (st && [st respondsToSelector:sel_registerName("isDeactivated")]) ? ((BOOL(*)(id,SEL))objc_msgSend)(st, sel_registerName("isDeactivated")) : -1;
            int sOc  = (st && [st respondsToSelector:sel_registerName("isOccluded")]) ? ((BOOL(*)(id,SEL))objc_msgSend)(st, sel_registerName("isOccluded")) : -1;
            unsigned long sDr = (st && [st respondsToSelector:sel_registerName("deactivationReasons")]) ? ((unsigned long(*)(id,SEL))objc_msgSend)(st, sel_registerName("deactivationReasons")) : 0;
            CGRect sFrame = (st && [st respondsToSelector:sel_registerName("frame")]) ? ((CGRect(*)(id,SEL))objc_msgSend)(st, sel_registerName("frame")) : CGRectZero;
            CGRect rwB = CGRectZero;
            if (gCBRRootWindow) rwB = ((CGRect(*)(id,SEL))objc_msgSend)(gCBRRootWindow, sel_registerName("bounds"));
            char ytLine[220]; ytLine[0]=0;
            @try {
                id dvc = gCBRAppVC ? getIvar(gCBRAppVC, "_deviceAppViewController") : nil;
                id sv  = dvc ? getIvar(dvc, "_sceneView") : nil;
                if (sv) {
                    CGRect svb = ((CGRect(*)(id,SEL))objc_msgSend)(sv, sel_registerName("bounds"));
                    snprintf(ytLine, sizeof(ytLine), "sceneView=%s %.0fx%.0f", object_getClassName(sv), svb.size.width, svb.size.height);
                } else {
                    snprintf(ytLine, sizeof(ytLine), "sceneView=nil (appVC=%d dvc=%d)", gCBRAppVC?1:0, dvc?1:0);
                }
            } @catch(...) { snprintf(ytLine, sizeof(ytLine), "yt-probe-threw"); }
            int pfd = open("/var/mobile/CBR_drive.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
            if (pfd >= 0) {
                char _pb[640];
                int n = snprintf(_pb, sizeof(_pb),
                    "DRV#%d t=%.2f | SCENE ifo=%ld fg=%d deact=%d occ=%d dr=%lu frame=%.0fx%.0f | carWin=%.0fx%.0f phone=%.0fx%.0f | %s\n",
                    _drv, _t, sIfo, sFg, sDe, sOc, sDr, sFrame.size.width, sFrame.size.height,
                    rwB.size.width, rwB.size.height, gCBRPhoneW, gCBRPhoneH, ytLine);
                if (n > 0) write(pfd, _pb, (size_t)n);
                close(pfd);
            }
        } @catch(...) {}
        void (^b)(id) = ^(id ms){
            SEL s;
            s=sel_registerName("setForeground:");          if([ms respondsToSelector:s]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms,s,YES);
            s=sel_registerName("setBackgrounded:");        if([ms respondsToSelector:s]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms,s,NO);
            s=sel_registerName("setDeactivated:");         if([ms respondsToSelector:s]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms,s,NO);
            s=sel_registerName("setOccluded:");            if([ms respondsToSelector:s]) ((void(*)(id,SEL,BOOL))objc_msgSend)(ms,s,NO);
            // v3.34.0 THE ACTIVATION FIX. Every SIDEWAYS boot sits at act=1 (FG-INACTIVE); the phone-tap
            // - the only thing that has EVER reliably fixed the render - drives the scene FG-ACTIVE
            // (act=0). A scene with deactivationReasons != 0 CANNOT be FG-ACTIVE. Nothing in this
            // codebase ever cleared them, and the keep-alive hook BLOCKED any update that would
            // (if dr != 0 -> return, never calling %orig), freezing the scene inactive forever.
            // Clear the reasons so the scene can actually reach FG-ACTIVE, like the tap does.
            s=sel_registerName("setDeactivationReasons:"); if([ms respondsToSelector:s]) ((void(*)(id,SEL,NSUInteger))objc_msgSend)(ms,s,(NSUInteger)0);
            s=sel_registerName("setInterfaceOrientation:");if([ms respondsToSelector:s]) ((void(*)(id,SEL,NSInteger))objc_msgSend)(ms,s,(NSInteger)3);
            // v3.26.0: THE FIX. GOOD (upright+stretched) frame=430x932 (phone portrait);
            // BAD (sideways) frame=472x281 (car landscape). All else identical. Drive the phone frame.
            s=sel_registerName("setFrame:");
            if([ms respondsToSelector:s] && gCBRPhoneW>0) ((void(*)(id,SEL,CGRect))objc_msgSend)(ms,s,CGRectMake(0,0,gCBRPhoneW,gCBRPhoneH));
        };
        ((void(*)(id,SEL,id))objc_msgSend)(scn, upd, b);
        cbrApplyCarplayCastScale();   // v3.35.0
        int fd=open("/var/mobile/CBR_silent.txt",O_WRONLY|O_CREAT|O_APPEND,0644);
        if(fd>=0){const char*m="[silent] foreground-activate delivered\n";write(fd,m,strlen(m));close(fd);}
    } @catch(...) {}
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
    // v3.42.0: publish "hosting" as notify STATE (apps read it synchronously at ctor - kills the
    // loaded-ping round-trip race) and remember the bid for the BORN-LANDSCAPE create hook.
    @try {
        if (bid[0]) gCBRPendingHostBid = [NSString stringWithUTF8String:bid];
        gCBRBounceCount = 0; gCBRBlindBounce = 0; gCBRScaleAnimated = 0;   // v3.51.0/v3.52.0: fresh blind budget + grow-in per host session
        if (!gCBRHostStateToken) notify_register_check("com.cbr.orient.landscape", &gCBRHostStateToken);
        // v3.45.0: publish hash(hostedBid) so ONLY the hosted app matches - the override can no longer
        // leak to phone apps (Photos went landscape because every app read the old constant state=3).
        if (gCBRHostStateToken) notify_set_state(gCBRHostStateToken, cbrBidHash(bid[0] ? bid : ""));
        // v3.47.0: zero the truth channel for the new host session (stale landscape from the
        // last app would wrongly suppress the bounce).
        if (!gCBRTruthTokenSB) notify_register_check("com.cbr.app.truth", &gCBRTruthTokenSB);
        if (gCBRTruthTokenSB) notify_set_state(gCBRTruthTokenSB, 0);
        { char _pb[320]; int _pn=snprintf(_pb,sizeof(_pb),"[CBR-SB] v3.52.0 host published bid=[%s] hash=%llu", bid[0]?bid:"(empty)", (unsigned long long)cbrBidHash(bid[0]?bid:"")); if(_pn>0) cbrSBLog(_pb);
          int _af=open("/var/mobile/CBR_arm_diag.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_af>=0){ char _ab[320]; int _an=snprintf(_ab,sizeof(_ab),"SB-PUBLISH bid=[%s] hash=%llu\n", bid[0]?bid:"(empty)", (unsigned long long)cbrBidHash(bid[0]?bid:"")); if(_an>0)write(_af,_ab,(size_t)_an); close(_af);} }
    } @catch(...) {}
    // v3.20.11: PATH-A + probes REMOVED from the hot path. cbrSBReassignToCarPlay
    // poked the LIVE main-display scene's display config on every tap; the composite
    // never moved, leaving the scene spinning the render server -> load avg 143 runaway.
    // Keep ONLY the grafting host - this is what actually rendered scrollable YouTube.
    // cbrSBProbeSceneHandle(bid);      // diagnostic only - off hot path
    id _cbrHandle = cbrSBCreateSceneHandle(bid);
    cbrSBHostScene(bid, _cbrHandle);
    // v3.25.7: wipe the drive log at host time so EACH open is a clean, self-contained capture.
    unlink("/var/mobile/CBR_drive.txt");
    for (int _i=0; _i<4; _i++) { double _d = 1.5 + _i*1.5;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(_d*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ cbrSBSilentActivate(); }); }
    // v3.43.0: RE-POST the landscape request AFTER launch settles (the carplay-cast
    // moment - it posts inside _executeBlockAfterLaunchCompletes:). The host-time post at
    // the top of cbrSBHostScene fires before the app's key window exists; these later
    // posts reach the app once its UIKit is live so the app-side kick has a window to
    // rotate. Cheap + idempotent.
    for (int _i=0; _i<3; _i++) { double _d = 2.0 + _i*2.0;
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(_d*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
            CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.orient.landscape"), NULL, NULL, YES);
        }); }
    // v3.42.0: after launch settles, ask the client settings how the app REALLY laid out; bounce if portrait.
    // v3.51.0: the v3.50 auto-replay edges are REMOVED. cbrSBSilentActivate already fires 4x at
    // host time (1.5/3/4.5/6s) and never fixed a sideways boot: a same-value settings write
    // produces NO diff, so it never reaches the app. The lever that matches the manual phone tap
    // is the bounce's deactivate->reactivate EDGE - which finally fires now that truth carries
    // the content orientation (vio) and no-truth sessions escalate blind.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(8.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ cbrSBBounceCheck(); });
    // v3.47.0: slow launchers (YouTube TV) may not have published truth by +8s; check again late.
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(16.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ cbrSBBounceCheck(); });
    // cbrSBReassignToCarPlay(bid);     // PATH-A - caused the load runaway - REMOVED
    // cbrSBProbeTransition(bid);       // diagnostic only - off hot path
    // cbrSBProbeTxnCtx(bid);           // diagnostic only - off hot path
}
// v3.45.0 BUG2: the CarPlay process posts this when the user launches a DIFFERENT (native) app while
// we are hosting, so we tear our window down and hand the car display back instead of leaving two apps
// foregrounded (YouTube on top, Maps peeking through the sidebar gap).
static void cbrSBDismissCallback(CFNotificationCenterRef c, void *obs, CFStringRef name, const void *o, CFDictionaryRef ui) {
    dispatch_async(dispatch_get_main_queue(), ^{ @try { if (gCBRRootWindow) { cbrSBLog("[CBR-SB] host.dismiss received - tearing down for native app"); gCBRHardDismiss = 1; cbrSBHostDismiss(); } } @catch(...) {} });
}
static void cbrSBRegisterListener(void) {
    cbrSBLog("[CBR-SB] v3.14.0 listener registering in SpringBoard");
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
        NULL, cbrSBLaunchCallback, CFSTR("com.carbridgereborn.launch"),
        NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(),
        NULL, cbrSBDismissCallback, CFSTR("com.cbr.host.dismiss"),
        NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
    // v3.51.0 DISCONNECT TEARDOWN: nothing ever tore the host down when the car screen went
    // away - the grafted scene + root window survived the disconnect, kept compositing, and
    // showed up in PHONE screenshots (the screenshot-duplication bug). Tear down the moment the
    // car screen disconnects while we host.
    @try {
        id _nc = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSNotificationCenter"), sel_registerName("defaultCenter"));
        if (_nc) {
            void (^_dis)(id) = ^(id note){
                @try {
                    id _scr = note ? ((id(*)(id,SEL))objc_msgSend)(note, sel_registerName("object")) : nil;
                    SEL _ic = sel_registerName("_isCarScreen");
                    BOOL _car = (_scr && [_scr respondsToSelector:_ic]) ? ((BOOL(*)(id,SEL))objc_msgSend)(_scr, _ic) : YES;
                    { char _b[140]; int _n=snprintf(_b,sizeof(_b),"[CBR-SB] v3.53.0 UIScreenDidDisconnect FIRED isCar=%d hosting=%d", (int)_car, gCBRRootWindow?1:0); if(_n>0) cbrSBLog(_b); }   // v3.53.0: does the observer even fire on CarPlay disconnect? (screenshot leak)
                    if (!_car) return;
                } @catch(...) {}
                dispatch_async(dispatch_get_main_queue(), ^{
                    @try { if (gCBRRootWindow) { cbrSBLog("[CBR-SB] v3.51.0 car screen disconnected while hosting -> teardown"); gCBRHardDismiss = 1; cbrSBHostDismiss(); } } @catch(...) {}
                });
            };
            ((id(*)(id,SEL,id,id,id,void(^)(id)))objc_msgSend)(_nc,
                sel_registerName("addObserverForName:object:queue:usingBlock:"),
                @"UIScreenDidDisconnectNotification", nil, nil, _dis);
            cbrSBLog("[CBR-SB] v3.51.0 screen-disconnect teardown observer registered");
        }
    } @catch(...) {}
    cbrSBLog("[CBR-SB] observers registered (launch + host.dismiss + screen-disconnect)");
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
// v3.29.0 CARPLAY-SIDE ROTATION PROBE. SpringBoard and the app show BYTE-IDENTICAL state on
// upright vs sideways (canvas 932x430, window 932x430, vcIfo=3, identity xforms, angle 0.0), so
// the rotation is decided in THIS process - never instrumented. Dump what the car scene ACTUALLY
// has applied (effective angle/mode), not what we asked for. Repeats, so boots can be diffed.
static void cbrCPRotationSchedule(void);
static void cbrCPRotationTick(void) {
    @try {
        int fd = open("/var/mobile/CBR_cp_rotation.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (fd < 0) return;
        #define CPR(...) do{ char _b[420]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(_n>0) write(fd,_b,(size_t)_n);}while(0)
        static int _t = 0; _t++;
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? ((NSUInteger(*)(id,SEL))objc_msgSend)(all, sel_registerName("count")) : 0;
        for (NSUInteger i = 0; i < cnt; i++) {
            id sc = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(all, sel_registerName("objectAtIndex:"), i);
            if (!sc) continue;
            id scr = ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("screen"));
            SEL _ic = sel_registerName("_isCarScreen");
            BOOL isCar = (scr && [scr respondsToSelector:_ic]) ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, _ic) : NO;
            if (!isCar) continue;
            CGRect sb = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));
            long io = ((long(*)(id,SEL))objc_msgSend)(sc, sel_registerName("interfaceOrientation"));
            double ang = -999; long angMode = -999; int sbi = -1;
            @try {
                id st = [sc respondsToSelector:sel_registerName("settings")] ? ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("settings")) : nil;
                if (st) {
                    SEL _a = sel_registerName("angleFromHostReferenceUprightDirection");
                    SEL _m = sel_registerName("hostReferenceAngleMode");
                    SEL _b = sel_registerName("screenBoundsIgnoresSceneOrientation");
                    if ([st respondsToSelector:_a]) ang = ((double(*)(id,SEL))objc_msgSend)(st, _a);
                    if ([st respondsToSelector:_m]) angMode = ((long(*)(id,SEL))objc_msgSend)(st, _m);
                    if ([st respondsToSelector:_b]) sbi = ((BOOL(*)(id,SEL))objc_msgSend)(st, _b);
                }
            } @catch(...) {}
            CPR("T%d car scene=%s screen=%.0fx%.0f ifo=%ld | EFFECTIVE angle=%.4f mode=%ld ignoreBounds=%d\n",
                _t, object_getClassName(sc), sb.size.width, sb.size.height, io, ang, angMode, sbi);
            @try {
                id wins = ((id(*)(id,SEL))objc_msgSend)(sc, sel_registerName("windows"));
                NSUInteger wc = wins ? ((NSUInteger(*)(id,SEL))objc_msgSend)(wins, sel_registerName("count")) : 0;
                for (NSUInteger w = 0; w < wc; w++) {
                    id win = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins, sel_registerName("objectAtIndex:"), w);
                    if (!win) continue;
                    CGRect wb = ((CGRect(*)(id,SEL))objc_msgSend)(win, sel_registerName("bounds"));
                    id ly = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("layer"));
                    CGAffineTransform tf = ly ? ((CGAffineTransform(*)(id,SEL))objc_msgSend)(ly, sel_registerName("affineTransform")) : CGAffineTransformIdentity;
                    CPR("   win[%lu] %s bounds=%.0fx%.0f xf=[%.2f %.2f %.2f %.2f]\n",
                        (unsigned long)w, object_getClassName(win), wb.size.width, wb.size.height, tf.a, tf.b, tf.c, tf.d);
                }
            } @catch(...) {}
        }
        #undef CPR
        close(fd);
    } @catch(...) {}
}
static void cbrCPRotationSchedule(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(1.0*NSEC_PER_SEC)),dispatch_get_main_queue(),^{
        cbrCPRotationTick();
        cbrCPRotationSchedule();
    });
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
static double gCBRHomeDownMs = 0;   // v3.58.0: DBStatusBarHomeButton press-start time (short vs long press)
%group CARPLAY

// v3.58.0 HOME BUTTON FIX (confirmed target from the v3.57 probe: DBStatusBarHomeButton on
// DBRootStatusBarViewController fires homeButtonDown:/homeButtonUp:). A SHORT press while we host
// returns to the CarPlay DASHBOARD (tear our host down), not the homescreen. A LONG press is left
// untouched so Siri - which fires on the HOLD, between down and up - still works.
%hook DBRootStatusBarViewController
- (void)homeButtonDown:(id)arg1 {
    @try { struct timespec _t; clock_gettime(CLOCK_MONOTONIC,&_t); gCBRHomeDownMs = _t.tv_sec*1000.0 + _t.tv_nsec/1000000.0; } @catch(...) {}
    %orig;
}
- (void)homeButtonUp:(id)arg1 {
    uint64_t _hs = 0; double _dur = 99999.0;
    @try {
        _hs = cbrReadHostState();
        double _now; { struct timespec _t; clock_gettime(CLOCK_MONOTONIC,&_t); _now = _t.tv_sec*1000.0 + _t.tv_nsec/1000000.0; }
        _dur = (gCBRHomeDownMs > 0) ? (_now - gCBRHomeDownMs) : 99999.0;
    } @catch(...) {}
    // v3.62.0 HOME EXIT (from the class dump): on a SHORT press while hosting, CANCEL the native
    // home press so the Siri hold-timer dies (homeButtonCancel: + invalidate homeButtonTimer - Siri
    // fired because swallowing left the timer running), post our dismiss (return to the dashboard),
    // and SWALLOW the native go-to-grid nav (no abrupt zoom-left). Long press / not hosting -> %orig.
    if (_hs != 0 && _dur < 500.0) {
        @try { ((void(*)(id,SEL,id))objc_msgSend)(self, sel_registerName("homeButtonCancel:"), arg1); } @catch(...) {}
        @try { id _tm = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("homeButtonTimer")); if (_tm && [_tm respondsToSelector:sel_registerName("invalidate")]) ((void(*)(id,SEL))objc_msgSend)(_tm, sel_registerName("invalidate")); } @catch(...) {}
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.host.dismiss"), NULL, NULL, YES);
        @try { int _hf = open("/var/mobile/CBR_home_probe.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
               if (_hf >= 0) { char _b[180]; int _n = snprintf(_b,sizeof(_b),"[HOME-UP] SHORT hosting dur=%.0fms -> homeButtonCancel + invalidate timer + dismiss + swallow (no Siri, dashboard)\n", _dur); if(_n>0) write(_hf,_b,(size_t)_n); close(_hf); } } @catch(...) {}
        return;   // swallow - no grid nav
    }
    %orig;   // not hosting, or long press -> native (Siri on a long hold)
    @try {
        int _hf = open("/var/mobile/CBR_home_probe.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (_hf >= 0) { char _b[120]; int _n = snprintf(_b,sizeof(_b),"[HOME-UP] dur=%.0fms hosting=%d -> %%orig (native)\n", _dur, _hs!=0?1:0); if(_n>0) write(_hf,_b,(size_t)_n); close(_hf); }
    } @catch(...) {}
}
%end

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

// v3.56.0 HOME-BUTTON PROBE (SAFE, log-only). carplay-cast returns to the dashboard by sending a
// CAREvent type 1 ("Close carplay app") to the dashboard via handleEvent:. Log every event (type +
// class + whether CBR is hosting) so we can confirm the iOS-17 home-press path BEFORE acting on it
// - a wrong CarPlay hook drops CarPlay into safe mode, so we capture first. Always calls %orig,
// never swallows, so it cannot change navigation. If DashBoard has no handleEvent: this is inert.
- (void)handleEvent:(id)event {
    @try {
        long _et = (event && [event respondsToSelector:sel_registerName("type")]) ? ((long(*)(id,SEL))objc_msgSend)(event, sel_registerName("type")) : -1;
        uint64_t _hs = cbrReadHostState();
        int _f = open("/var/mobile/CBR_home_probe.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (_f >= 0) { char _b[240]; int _n = snprintf(_b,sizeof(_b),"[DashBoard handleEvent] type=%ld hosting=%d event=%s\n", _et, _hs!=0?1:0, event?object_getClassName(event):"nil"); if(_n>0) write(_f,_b,(size_t)_n); close(_f); }
    } @catch(...) {}
    %orig;
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
// v3.61.0 HOME-INTERNALS PROBE: dump a class's method names so we can find the Siri-cancel +
// show-dashboard selectors the home button uses (to exit to the dashboard, not the home grid).
static void cbrDumpClassMethods(const char *clsname, int fd) {
    @try {
        Class c = objc_getClass(clsname);
        if (!c) { char _b[110]; int _n=snprintf(_b,sizeof(_b),"==== %s NOT FOUND ====\n", clsname); if(_n>0)write(fd,_b,(size_t)_n); return; }
        { char _b[110]; int _n=snprintf(_b,sizeof(_b),"==== %s methods ====\n", clsname); if(_n>0)write(fd,_b,(size_t)_n); }
        unsigned int cnt=0; Method *ms = class_copyMethodList(c, &cnt);
        for (unsigned int i=0;i<cnt;i++){ const char *sn = sel_getName(method_getName(ms[i])); char _b[240]; int _l=snprintf(_b,sizeof(_b),"  %s\n", sn); if(_l>0)write(fd,_b,(size_t)_l); }
        if(ms) free(ms);
    } @catch(...) {}
}
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

// v3.20.43: CHROME GEOMETRY probe - walk CarPlayApp's view tree on the car window and log
// every view's class + frame, so we find the sidebar/dock position+width to crop our app window
// around it (revealing CarPlay's native chrome instead of an exit button).
// v3.50.0: measure the REAL CarPlay sidebar width and hand it to SpringBoard, replacing the
// hardcoded 0.10 inset guess that left a dashboard sliver. Publishes over notify state.
static void cbrCPPublishSidebarW(CGFloat w) {
    @try {
        if (w <= 0) return;
        static int _tok = 0;
        if (!_tok) notify_register_check("com.cbr.sidebar.w", &_tok);
        if (_tok) notify_set_state(_tok, (uint64_t)(w + 0.5));
        int lf = open("/var/mobile/CBR_sidebar_w.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
        if (lf >= 0) { char _b[80]; int _n = snprintf(_b, sizeof(_b), "measured sidebar right-edge = %.0fpt\n", w); if (_n>0) write(lf,_b,(size_t)_n); close(lf); }
    } @catch(...) {}
}
static void cbrCPProbeChromeGeom(void) {
    int cf = open("/var/mobile/CBR_chromegeom.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    CGFloat _sbEdge = 0; CGFloat _winW = 0, _winH = 0;   // v3.50.0 sidebar measurement
    #define CG(...) do{ char _b[360]; int _n=snprintf(_b,sizeof(_b),__VA_ARGS__); if(cf>=0)write(cf,_b,_n);}while(0)
    CG("==== CHROME GEOMETRY PROBE ====\n");
    @try {
        id app = ((id(*)(id,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        id conns = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes")) : nil;
        id all = conns ? ((id(*)(id,SEL))objc_msgSend)(conns, sel_registerName("allObjects")) : nil;
        NSUInteger cnt = all ? [all count] : 0;
        for (NSUInteger i=0;i<cnt;i++){
            id sc=[all objectAtIndex:i];
            id wins=[sc respondsToSelector:sel_registerName("windows")]?((id(*)(id,SEL))objc_msgSend)(sc,sel_registerName("windows")):nil;
            NSUInteger wc=wins?[wins count]:0;
            for (NSUInteger j=0;j<wc;j++){
                id w=[wins objectAtIndex:j];
                CGRect wf=((CGRect(*)(id,SEL))objc_msgSend)(w,sel_registerName("frame"));
                CG("WINDOW %s frame=%.0f,%.0f %.0fx%.0f\n", class_getName(object_getClass(w)), wf.origin.x,wf.origin.y,wf.size.width,wf.size.height);
                if (wf.size.width > _winW) { _winW = wf.size.width; _winH = wf.size.height; }   // v3.50.0: car window size
                // recursively walk the view tree, logging class+frame, depth-limited
                id rvc=[w respondsToSelector:sel_registerName("rootViewController")]?((id(*)(id,SEL))objc_msgSend)(w,sel_registerName("rootViewController")):nil;
                id rv=rvc?((id(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("view")):nil;
                if (rv) {
                    // iterative DFS with depth
                    typedef struct { id v; int d; } _Node;
                    NSMutableArray *stack = [NSMutableArray array];
                    [stack addObject:@[rv, @0]];
                    int _count=0;
                    while ([stack count] > 0 && _count < 200) {
                        NSArray *node = [stack lastObject]; [stack removeLastObject];
                        id v = node[0]; int d = [node[1] intValue]; _count++;
                        @try {
                            CGRect vf=((CGRect(*)(id,SEL))objc_msgSend)(v,sel_registerName("frame"));
                            const char *vn=class_getName(object_getClass(v));
                            // indent by depth
                            char ind[24]; int ii; for(ii=0;ii<d && ii<10;ii++) ind[ii]=' '; ind[ii]=0;
                            // only log views wider/taller than trivial + name hints of chrome
                            const char *_mk = "";
                            if (vn && (strcasestr(vn,"button")||strcasestr(vn,"home")||strcasestr(vn,"dashboard")||strcasestr(vn,"dock"))) _mk = "   <== BTN/HOME/DASH?";   // v3.52.0: greppable for the supported-vs-unsupported home/chrome comparison
                            CG("  %s%s frame=%.0f,%.0f %.0fx%.0f%s\n", ind, vn, vf.origin.x,vf.origin.y,vf.size.width,vf.size.height, _mk);
                            // v3.50.0 sidebar test: left-anchored (x<=2), narrow (20..140), tall (>=70% of window height).
                            if (_winH > 0 && vf.origin.x <= 2.0 && vf.size.width >= 20.0 && vf.size.width <= 140.0
                                && vf.size.height >= _winH * 0.70) {
                                CGFloat _edge = vf.origin.x + vf.size.width;
                                if (_edge > _sbEdge) _sbEdge = _edge;   // widest qualifying strip wins
                            }
                            if (d < 4) {
                                id subs=((id(*)(id,SEL))objc_msgSend)(v,sel_registerName("subviews"));
                                NSUInteger sn=subs?[subs count]:0;
                                for (NSUInteger k=0;k<sn;k++){ [stack addObject:@[[subs objectAtIndex:k], @(d+1)]]; }
                            }
                        } @catch(...) {}
                    }
                }
            }
        }
    } @catch(NSException *e){ CG("PROBE EXC: %s\n", [[e reason] UTF8String]?:"?"); }
    // v3.50.0: publish the measured sidebar edge; if nothing qualified, publish 10% so SB still
    // gets a concrete value rather than falling to its internal guess.
    if (_sbEdge <= 0 && _winW > 0) { _sbEdge = (CGFloat)((int)(_winW * 0.10 + 0.5)); CG("no sidebar view matched - publishing 10%% fallback = %.0f\n", _sbEdge); }
    else CG("measured sidebar edge = %.0f (win %.0fx%.0f)\n", _sbEdge, _winW, _winH);
    cbrCPPublishSidebarW(_sbEdge);
    CG("==== END ====\n");
    if(cf>=0)close(cf);
    #undef CG
}

%hook DBDashboardHomeViewController

- (void)_setupIconModel {
    cbrCPProbeScenes();
    cbrCPProbeChromeGeom();
    { static int _mi=0; if(!_mi){ _mi=1; int _f=open("/var/mobile/CBR_home_internals.txt",O_WRONLY|O_CREAT|O_TRUNC,0644); if(_f>=0){ cbrDumpClassMethods("DBRootStatusBarViewController",_f); cbrDumpClassMethods("DBStatusBarHomeButton",_f); cbrDumpClassMethods("DBDashboardHomeViewController",_f); cbrDumpClassMethods("DashBoard",_f); close(_f);} } }   // v3.61.0 home-internals probe
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

    // v3.45.0 BUG2: a NON-bridged (native) app is launching. If we are currently hosting a DIFFERENT
    // app, ask SpringBoard to dismiss our window so the native app takes the car display cleanly
    // instead of rendering under our still-foregrounded scene.
    @try {
        if (!handled) {
            uint64_t _hs = cbrReadHostState();
            if (_hs != 0) {
                id _bo = cb(appInfo, "bundleIdentifier");
                const char *_bid = _bo ? ((const char*(*)(id,SEL))objc_msgSend)(_bo, sel_registerName("UTF8String")) : NULL;
                if (!_bid || cbrBidHash(_bid) != _hs) {
                    CBCarLogFmt("[CBR-CP] foreign launch %s while hosting -> request dismiss", _bid ?: "?");
                    CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.host.dismiss"), NULL, NULL, YES);
                }
            }
        }
    } @catch(...) {}

    if (handled) return nil;
    return %orig;
}

%end


// ── DBIconView — long press ───────────────────────────────────────────────────
%hook DBIconView

// v3.51.0 ZOOM ORIGIN capture: record the icon's center (window coords) the moment it
// highlights; CBPostLaunch publishes it if the launch follows within 3s. If DBIconView has no
// setHighlighted: this hook is a silent no-op and the zoom falls back to center.
- (void)setHighlighted:(BOOL)h {
    %orig;
    @try {
        if (h) {
            CGRect _b = ((CGRect(*)(id,SEL))objc_msgSend)(self, sel_registerName("bounds"));
            CGRect _wr = ((CGRect(*)(id,SEL,CGRect,id))objc_msgSend)(self, sel_registerName("convertRect:toView:"), _b, (id)nil);
            gCBRIconCX = _wr.origin.x + _wr.size.width/2.0; gCBRIconCY = _wr.origin.y + _wr.size.height/2.0;
            struct timespec _hts; clock_gettime(CLOCK_MONOTONIC, &_hts); gCBRIconTS = _hts.tv_sec + _hts.tv_nsec/1e9;
        }
    } @catch(...) {}
}

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
        @try {
            CGRect _b = ((CGRect(*)(id,SEL))objc_msgSend)(self, sel_registerName("bounds"));
            CGRect _wr = ((CGRect(*)(id,SEL,CGRect,id))objc_msgSend)(self, sel_registerName("convertRect:toView:"), _b, (id)nil);
            gCBRIconCX = _wr.origin.x + _wr.size.width/2.0; gCBRIconCY = _wr.origin.y + _wr.size.height/2.0;
            struct timespec _lts; clock_gettime(CLOCK_MONOTONIC, &_lts); gCBRIconTS = _lts.tv_sec + _lts.tv_nsec/1e9;
        } @catch(...) {}
        CBCarLogFmt("[CBR-CP] tap(longpress) -> %s", bid ?: "?");
        CBPostLaunch(bid);
        CBLogFmt("[CBR] Long press: %s", bid ?: "?");
        CBOpenApp(bid);
    } @catch(...) {}
}

%end

// v3.57.0 HOME-BUTTON PROBE v2: DashBoard.handleEvent: never fired, so log every UIControl tap in
// the CarPlay process (action selector + target class + the control's own class + hosting). The
// home/dashboard button is a control, so pressing it reveals exactly what to hook + call for the fix.
%hook UIControl
- (void)sendAction:(SEL)action to:(id)target forEvent:(id)event
{
    @try {
        uint64_t _hs = cbrReadHostState();
        int _f = open("/var/mobile/CBR_home_probe.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (_f >= 0) { char _b[300]; int _n = snprintf(_b,sizeof(_b),"[UIControl] action=%s target=%s control=%s hosting=%d\n", action?sel_getName(action):"nil", target?object_getClassName(target):"nil", object_getClassName(self), _hs!=0?1:0); if(_n>0) write(_f,_b,(size_t)_n); close(_f); }
    } @catch(...) {}
    %orig;
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
// v3.42.0 BORN-LANDSCAPE. Every sideways boot shares one shape: the app's FIRST surface commit
// happens while its scene still carries the portrait defaults SpringBoard mints for main-display
// scenes; every later correction (updateSettings writes, 1s re-drives, app-side hooks) arrives
// after the surface shape has latched. The app cannot rotate itself - requestGeometryUpdate is
// DENIED for hosted scenes (BSActionErrorDomain 1) - so the SERVER (this process) must mint the
// scene landscape AT CREATION. Rewrite the INITIAL parameters when the scene being created
// belongs to the app we are hosting: interfaceOrientation=3 (+ best-effort client echo). The
// frame is deliberately left alone: fixed portrait space is correct, ifo drives orientation.
%hook FBSceneManager
- (id)createSceneWithDefinition:(id)definition initialParameters:(id)parameters {
    @try {
        if (gCBRPendingHostBid && definition && parameters) {
            NSString *ident = nil;
            @try {
                id idy = [definition respondsToSelector:sel_registerName("identity")] ? ((id(*)(id,SEL))objc_msgSend)(definition, sel_registerName("identity")) : nil;
                ident = idy ? ((id(*)(id,SEL))objc_msgSend)(idy, sel_registerName("description")) : nil;
            } @catch(...) {}
            int match = (ident && [ident rangeOfString:gCBRPendingHostBid].location != NSNotFound) ? 1 : 0;
            int bfd = open("/var/mobile/CBR_create_scene.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
            if (bfd>=0){ char _b[520]; int _n=snprintf(_b,sizeof(_b),"CREATE-SCENE ident=[%s] pending=[%s] match=%d\n", ident?[ident UTF8String]:"nil", [gCBRPendingHostBid UTF8String], match); if(_n>0)write(bfd,_b,(size_t)_n); close(bfd); }
            if (match) {
                id mp = ((id(*)(id,SEL))objc_msgSend)(parameters, sel_registerName("mutableCopy"));
                id st = (mp && [mp respondsToSelector:sel_registerName("settings")]) ? ((id(*)(id,SEL))objc_msgSend)(mp, sel_registerName("settings")) : nil;
                id ms = st ? ((id(*)(id,SEL))objc_msgSend)(st, sel_registerName("mutableCopy")) : nil;
                long before = (ms && [ms respondsToSelector:sel_registerName("interfaceOrientation")]) ? ((long(*)(id,SEL))objc_msgSend)(ms, sel_registerName("interfaceOrientation")) : -99;
                if (ms && [ms respondsToSelector:sel_registerName("setInterfaceOrientation:")] && [mp respondsToSelector:sel_registerName("setSettings:")]) {
                    ((void(*)(id,SEL,NSInteger))objc_msgSend)(ms, sel_registerName("setInterfaceOrientation:"), (NSInteger)3);
                    if ([ms respondsToSelector:sel_registerName("setDeviceOrientation:")])
                        ((void(*)(id,SEL,NSInteger))objc_msgSend)(ms, sel_registerName("setDeviceOrientation:"), (NSInteger)3);
                    // v3.56.0 CONTENT-REFERENCE-SIZE (CarBridge RE linchpin): set the app's content
                    // canvas + orientation TOGETHER so EVERY window it creates (main/keyboard/player/
                    // launch) inherits landscape - the value UIKit propagates to the whole layout,
                    // which frame-only setting never reaches. iOS17 may lack it; respondsToSelector-
                    // gated + logged so it is inert if absent, never a regression.
                    @try {
                        cbrEnsurePhoneSize();
                        CGFloat _crw = (gCBRPhoneH > gCBRPhoneW) ? gCBRPhoneH : gCBRPhoneW;
                        CGFloat _crh = (gCBRPhoneH > gCBRPhoneW) ? gCBRPhoneW : gCBRPhoneH;
                        SEL _crs2 = sel_registerName("setContentReferenceSize:withInterfaceOrientation:");
                        int _crf = open("/var/mobile/CBR_create_scene.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
                        if (_crw > 0 && [ms respondsToSelector:_crs2]) {
                            ((void(*)(id,SEL,CGSize,NSInteger))objc_msgSend)(ms, _crs2, CGSizeMake(_crw,_crh), (NSInteger)3);
                            if (_crf>=0){ char _b[140]; int _n=snprintf(_b,sizeof(_b),"[v3.56.0 CRS2] setContentReferenceSize %.0fx%.0f io=3 APPLIED\n", _crw, _crh); if(_n>0)write(_crf,_b,(size_t)_n); }
                        } else if (_crf>=0) { const char*_m="[v3.56.0 CRS2] setContentReferenceSize:withInterfaceOrientation: NOT available on this iOS\n"; write(_crf,_m,strlen(_m)); }
                        if (_crf>=0) close(_crf);
                    } @catch(...) {}
                    ((void(*)(id,SEL,id))objc_msgSend)(mp, sel_registerName("setSettings:"), ms);
                    @try {
                        id ct = [mp respondsToSelector:sel_registerName("clientSettings")] ? ((id(*)(id,SEL))objc_msgSend)(mp, sel_registerName("clientSettings")) : nil;
                        id mc = ct ? ((id(*)(id,SEL))objc_msgSend)(ct, sel_registerName("mutableCopy")) : nil;
                        if (mc && [mc respondsToSelector:sel_registerName("setInterfaceOrientation:")] && [mp respondsToSelector:sel_registerName("setClientSettings:")]) {
                            ((void(*)(id,SEL,NSInteger))objc_msgSend)(mc, sel_registerName("setInterfaceOrientation:"), (NSInteger)3);
                            ((void(*)(id,SEL,id))objc_msgSend)(mp, sel_registerName("setClientSettings:"), mc);
                        }
                    } @catch(...) {}
                    int bfd2 = open("/var/mobile/CBR_create_scene.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
                    if (bfd2>=0){ char _b2[240]; int _n2=snprintf(_b2,sizeof(_b2),"BORN-LANDSCAPE applied: ifo %ld -> 3\n", before); if(_n2>0)write(bfd2,_b2,(size_t)_n2); close(bfd2); }
                    return %orig(definition, mp);
                }
            }
        }
    } @catch(...) {}
    return %orig;
}
%end
%hook FBScene
- (void)updateSettings:(id)arg1 withTransitionContext:(id)arg2 completion:(void *)arg3 {
    if (gCBRBounceBypass) {
        cbrKLLog("[fbscene] BOUNCE bypass -> orig\n");
        %orig;
        return;
    }
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
                // v3.25.0: hold the scene ACTIVE, not just foreground. The phone-tap's real effect is
                // foreground-ACTIVE; CBR's scene stays foreground but gets DEACTIVATED (wrong render).
                SEL gDeact = sel_registerName("isDeactivated");
                BOOL isDeact = [arg1 respondsToSelector:gDeact] ? ((BOOL(*)(id,SEL))objc_msgSend)(arg1, gDeact) : NO;
                SEL gDR = sel_registerName("deactivationReasons");
                NSUInteger dr = [arg1 respondsToSelector:gDR] ? ((NSUInteger(*)(id,SEL))objc_msgSend)(arg1, gDR) : 0;
                const char *_act = (respFg && !isFg) ? "BLOCK-bg" : ((isDeact || dr) ? "BLOCK-deact" : "pass");
                cbrKLLog("[fbscene] bid=%s argClass=%s isFg=%d deact=%d dr=%lu => %s\n",
                         [bid UTF8String], object_getClassName(arg1), (int)isFg, (int)isDeact, (unsigned long)dr, _act);
                if (respFg && !isFg) { return; }         // block background
                // v3.34.0: do NOT block dr!=0 updates - blocking them froze deactivationReasons in place,
                // pinning the scene FG-INACTIVE (act=1) forever = the sideways state. Block explicit
                // deactivation only; the async re-drive clears the reasons and drives FG-ACTIVE.
                if (isDeact) { return; }                 // block explicit deactivation only
                // v3.26.0: FRAME GUARD. The dr=0 "pass" updates rewrite the scene frame from the
                // phone-portrait 430x932 (upright+stretched) to car-landscape 472x281 (sideways).
                // Don't block them - just re-assert the phone frame so the good geometry survives.
                @try {
                    SEL _gf = sel_registerName("frame");
                    SEL _sf = sel_registerName("setFrame:");
                    if ([arg1 respondsToSelector:_gf] && [arg1 respondsToSelector:_sf]) {
                        CGRect _cf = ((CGRect(*)(id,SEL))objc_msgSend)(arg1, _gf);
                        cbrEnsurePhoneSize();
                        if (gCBRPhoneW>0 && (fabs(_cf.size.width - gCBRPhoneW) > 1.0 || fabs(_cf.size.height - gCBRPhoneH) > 1.0)) {
                            cbrKLLog("[frame] rewriting %.0fx%.0f -> %.0fx%.0f\n", _cf.size.width, _cf.size.height, gCBRPhoneW, gCBRPhoneH);
                            ((void(*)(id,SEL,CGRect))objc_msgSend)(arg1, _sf, CGRectMake(0,0,gCBRPhoneW,gCBRPhoneH));
                        }
                    }
                } @catch(...) {}
                // v3.26.2: ORIENTATION correction - ASYNC ONLY. Modifying the orientation setting
                // INLINE here traps in FBSSettings _setValue:forSetting: during the launch commit
                // (safe mode). Detect ifo!=3 drift and correct it async on the LIVE scene (off this
                // transaction) via the drive that already works, debounced to avoid a flood.
                @try {
                    SEL _gio = sel_registerName("interfaceOrientation");
                    if ([arg1 respondsToSelector:_gio]) {
                        NSInteger _io = ((NSInteger(*)(id,SEL))objc_msgSend)(arg1, _gio);
                        if (_io != 3) {
                            cbrKLLog("[orient] ifo=%ld drift -> async re-drive\n", (long)_io);
                            static CFAbsoluteTime _lastOr = 0; CFAbsoluteTime _now = CFAbsoluteTimeGetCurrent();
                            if (_now - _lastOr > 0.25) { _lastOr = _now; dispatch_async(dispatch_get_main_queue(), ^{ cbrSBSilentActivate(); }); }
                        }
                    }
                } @catch(...) {}
                // v3.32.0 CRASH FIX: this set interfaceOrientation INLINE on arg1 - the exact thing
                // the v3.26.2 comment above warns against ("_setValue:forSetting: traps during the
                // launch commit = safe mode"). Crash log confirms SpringBoard died there during
                // YouTube TV launch. The async re-drive above already fixes orientation safely.
                // Removed (redundant + the crash).
                // v3.25.6: PERSISTENCE. Re-drive the LIVE scene (fresh block via cbrSBSilentActivate,
                // the call that works at startup) after each pass, so the correct render is held for
                // the whole session instead of only the first 6s. Async (no re-entry) + debounced.
                {
                    static double _lastRedrive = 0;
                    struct timespec _ts; clock_gettime(CLOCK_MONOTONIC, &_ts);
                    double _now = _ts.tv_sec + _ts.tv_nsec / 1e9;
                    if (_now - _lastRedrive > 0.9) {
                        _lastRedrive = _now;
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.05*NSEC_PER_SEC)),dispatch_get_main_queue(),^{ cbrSBSilentActivate(); });
                    }
                }
            }
        }
    } @catch(...) {}
    %orig;
}
%end
// v3.44.0: pass touches in the left sidebar strip THROUGH our host window to the native CarPlay
// chrome beneath (its dashboard button is the real exit). Gated to our exact host window instance so
// no other UIRootSceneWindow is affected.
%hook UIRootSceneWindow
- (id)hitTest:(CGPoint)point withEvent:(id)event {
    @try {
        // v3.53.0: the overlay home window (level 100, above the scene view). Home zone -> our
        // button; everything else -> nil so the app + recents below stay fully interactive.
        if ((id)self == gCBROverlayWindow) {
            CGRect _ob = ((CGRect(*)(id,SEL))objc_msgSend)(self, sel_registerName("bounds"));
            CGFloat _ozw = gCBRSidebarW > 0 ? gCBRSidebarW : 47.0;
            CGFloat _ozh = gCBRHomeZoneH > 0 ? gCBRHomeZoneH : 50.0;
            if (point.x < _ozw && point.y >= (_ob.size.height - _ozh)) {
                { static int _ol=0; if(_ol++ < 40){ int _f=open("/var/mobile/CBR_home.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ char _b[160]; int _n=snprintf(_b,sizeof(_b),"OVERLAY-HIT home x=%.0f y=%.0f -> overlay button\n", point.x, point.y); if(_n>0)write(_f,_b,(size_t)_n); close(_f);} } }
                if (gCBROverlayBtn) return gCBROverlayBtn;
            }
            return nil;
        }
        if ((id)self == gCBRRootWindow && gCBRSidebarW > 0.0 && point.x < gCBRSidebarW) {
            // v3.46.0: bottom home-button zone -> let our transparent dismiss button take the tap.
            CGRect _hb = ((CGRect(*)(id,SEL))objc_msgSend)(self, sel_registerName("bounds"));
            // v3.50.0: the bottom home-button zone must NOT pass through - passing through triggers
            // CarPlay's own go-home transition (visible in the sliver) and lands on the CarPlay
            // homescreen, not the dashboard we opened from. Route the tap to OUR dismiss target,
            // whose teardown returns to the dashboard. Return self so the tap hits our overlay
            // button (added at rootWindow level in cbrSBHostScene), not the app beneath.
            if (gCBRHomeZoneH > 0.0 && point.y >= (_hb.size.height - gCBRHomeZoneH)) {
                { static int _hl=0; if(_hl++ < 40){ int _f=open("/var/mobile/CBR_home.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ char _b[200]; int _n=snprintf(_b,sizeof(_b),"HITTEST home-zone x=%.0f y=%.0f winH=%.0f sbW=%.0f zoneH=%.0f btn=%d\n", point.x, point.y, _hb.size.height, gCBRSidebarW, gCBRHomeZoneH, gCBRHomeButton?1:0); if(_n>0)write(_f,_b,(size_t)_n); close(_f);} } }   // v3.52.0 home diag
                // v3.51.0: return our dismiss button EXPLICITLY. Both prior behaviors were wrong:
                // %orig let the tap fall to CarPlay's native go-home underneath (homescreen, not
                // dashboard) and our dismiss never fired - the v3.50 "fix" kept %orig and changed
                // nothing. An explicit return removes every hit-testing failure mode at once.
                if (gCBRHomeButton) return gCBRHomeButton;
                return %orig;
            }
            // status + recents strip (above the home zone): still pass through for recents handoff.
            { static int _rl=0; if(_rl++ < 40){ int _f=open("/var/mobile/CBR_home.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ char _b[160]; int _n=snprintf(_b,sizeof(_b),"HITTEST recents-strip x=%.0f y=%.0f sbW=%.0f -> passthrough(nil)\n", point.x, point.y, gCBRSidebarW); if(_n>0)write(_f,_b,(size_t)_n); close(_f);} } }   // v3.53.0 recents diag
            return nil;
        }
    } @catch(...) {}
    return %orig;
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

// v3.20.44: APP-SIDE orientation lock (carplay-cast technique, into YouTube via filter).
static int gCBROrientOverride = -1;
static int gCBRWasArmed = 0;   // v3.54.0: this process was hosted (armed) at least once
static double gCBRLastUnlock = 0;   // v3.55.0: monotonic ms of the last unlock (re-arm grace)
static int gCBRVCFired = 0;
static void cbrSBAppsideCallback(CFNotificationCenterRef c, void *obs, CFStringRef name, const void *o, CFDictionaryRef ui) {
    @try {
        char nm[128]; nm[0]=0; if(name) CFStringGetCString(name,nm,sizeof(nm),kCFStringEncodingUTF8);
        int fd=open("/var/mobile/CBR_appside_sb.txt",O_WRONLY|O_CREAT|O_APPEND,0644);
        if(fd>=0){char l[200];int n=snprintf(l,sizeof(l),"[appside] %s hosting=%d\n",nm,gCBRRootWindow?1:0);if(n>0)write(fd,l,(size_t)n);close(fd);}
        if (strstr(nm,"loaded") && gCBRRootWindow) { CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.orient.landscape"), NULL, NULL, YES); }
    } @catch(...) {}
}
// v3.37.0 DEEP TRANSFORM SCAN. Every probe stopped at the WINDOW / root view - all identity, all
// landscape - yet the dash renders sideways. vcIfo=1 while scene/window/root-view are all landscape
// (ifo=3) means YTAppViewControllerImpl OVERRIDES interfaceOrientation with its own state: YouTube
// runs its own orientation manager, believes it is portrait, and lays out accordingly inside a
// landscape window. If it rotates a CHILD view 90deg, we never saw it. Walk the whole tree.
static void cbrScanTransforms(id view, int depth, FILE *f, int *found) {
    if (!view || depth > 12) return;
    @try {
        CGAffineTransform t = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(view, sel_registerName("transform"));
        CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(view, sel_registerName("bounds"));
        BOOL ident = (fabs(t.a-1.0)<0.001 && fabs(t.b)<0.001 && fabs(t.c)<0.001 && fabs(t.d-1.0)<0.001);
        if (!ident) {
            (*found)++;
            fprintf(f, "    %*sROT? %s bounds=%.0fx%.0f xf=[%.3f %.3f %.3f %.3f]\n",
                    depth*2, "", object_getClassName(view), b.size.width, b.size.height, t.a, t.b, t.c, t.d);
        }
        id subs = ((id(*)(id,SEL))objc_msgSend)(view, sel_registerName("subviews"));
        NSUInteger n = subs ? ((NSUInteger(*)(id,SEL))objc_msgSend)(subs, sel_registerName("count")) : 0;
        for (NSUInteger i = 0; i < n && i < 40; i++) {
            id sv = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(subs, sel_registerName("objectAtIndex:"), i);
            cbrScanTransforms(sv, depth+1, f, found);
        }
    } @catch(...) {}
}

static void cbrYTGeomProbe(const char *tag) {
    @try {
        NSString *path = [NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_yt_geom.txt"];
        FILE *f = fopen([path fileSystemRepresentation], "a"); if (!f) return;
        fprintf(f, "==== YT WINDOWS [%s] t=%ld ====\n", tag, (long)time(NULL));
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        id arr = ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(app,sel_registerName("connectedScenes")), sel_registerName("allObjects"));
        NSUInteger sc = ((NSUInteger(*)(id,SEL))objc_msgSend)(arr, sel_registerName("count"));
        for (NSUInteger i=0;i<sc;i++){
            id scene = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr, sel_registerName("objectAtIndex:"), i);
            if (!strstr(object_getClassName(scene),"WindowScene")) continue;
            id ss = ((id(*)(id,SEL))objc_msgSend)(scene, sel_registerName("screen"));
            CGRect sb = ss ? ((CGRect(*)(id,SEL))objc_msgSend)(ss, sel_registerName("bounds")) : CGRectZero;
            long io = ((long(*)(id,SEL))objc_msgSend)(scene, sel_registerName("interfaceOrientation"));
            fprintf(f,"  scene screen=%.0fx%.0f io=%ld\n",sb.size.width,sb.size.height,io);
            id wins = ((id(*)(id,SEL))objc_msgSend)(scene, sel_registerName("windows"));
            NSUInteger wc = wins?((NSUInteger(*)(id,SEL))objc_msgSend)(wins, sel_registerName("count")):0;
            for (NSUInteger w=0; w<wc; w++){
                id win = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins, sel_registerName("objectAtIndex:"), w);
                CGRect wb = ((CGRect(*)(id,SEL))objc_msgSend)(win, sel_registerName("bounds"));
                CGAffineTransform t = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(win, sel_registerName("transform"));
                id rvc = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("rootViewController"));
                const char *rc = rvc?object_getClassName(rvc):"(nil)";
                BOOL key = ((BOOL(*)(id,SEL))objc_msgSend)(win, sel_registerName("isKeyWindow"));
                BOOL hid = ((BOOL(*)(id,SEL))objc_msgSend)(win, sel_registerName("isHidden"));
                long wl = ((long(*)(id,SEL))objc_msgSend)(win, sel_registerName("windowLevel"));
                fprintf(f,"    win[%lu]%s%s %s lvl=%ld bounds=%.0fx%.0f xform=[%.2f %.2f %.2f %.2f] rootVC=%s\n",
                        (unsigned long)w, key?"*KEY*":"", hid?"(hidden)":"", object_getClassName(win), wl,
                        wb.size.width,wb.size.height, t.a,t.b,t.c,t.d, rc);
                { int _found = 0;
                  cbrScanTransforms(win, 0, f, &_found);
                  fprintf(f, "    [deep-scan] non-identity transforms in tree: %d\n", _found); }
            }
        }
        fprintf(f, "==== END ====\n"); fclose(f);
    } @catch(...) {}
}

// v3.43.0 THE CARPLAY-CAST KICK. This is handleRotationRequest: from carplay-cast
// (src/hooks/UIApplication.xm) line-for-line: fetch the LIVE keyWindow and force it to
// the single override orientation with force:1. carplay-cast calls exactly this, from a
// notification SpringBoard posts inside _executeBlockAfterLaunchCompletes: - i.e. AFTER
// the app process has launched and its key window exists. We can't hook that private
// FBProcess block from the app side, so we approximate "after launch completes" by
// firing on the landscape notification AND re-firing a few times across the first ~4s;
// whichever call lands first once keyWindow is non-nil wins, and the rest are cheap
// idempotent no-ops (the _setRotatableViewOrientation hook already forces the value).
static void cbrEvent(const char *fmt, ...);   // v3.43.0: fwd decl - cbrEvent is defined
                                               // ~120 lines below; this function and its
                                               // callers sit above that definition.
static void cbrAppKickLandscape(int depth) {
    @try {
        if (gCBROrientOverride <= 0) return;   // dismissed / not hosted -> stop
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        id keyWin = app ? ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("keyWindow")) : nil;
        if (keyWin) {
            SEL _sro = sel_registerName("_setRotatableViewOrientation:duration:force:");
            if ([keyWin respondsToSelector:_sro]) {
                ((void(*)(id,SEL,int,float,int))objc_msgSend)(keyWin, _sro, gCBROrientOverride, 0.0f, 1);
                static int _k=0; if(_k++ < 16) cbrEvent("KICK _setRotatableViewOrientation:%d force:1 on keyWindow=%s (depth %d)", gCBROrientOverride, object_getClassName(keyWin), depth);
            }
        } else {
            static int _nk=0; if(_nk++ < 8) cbrEvent("KICK keyWindow nil (depth %d) - will retry", depth);
        }
        // Re-fire across the launch window so a slow starter (YouTube TV) still gets a
        // kick once its window is finally live. Matches carplay-cast firing after launch.
        if (depth < 8) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW,(int64_t)(0.5*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrAppKickLandscape(depth+1); });
        }
    } @catch(...) {}
}
static void cbrAppOrientCallback(CFNotificationCenterRef c, void *obs, CFStringRef name, const void *o, CFDictionaryRef ui) {
    @try {
        char nm[128]; nm[0]=0; if(name) CFStringGetCString(name,nm,sizeof(nm),kCFStringEncodingUTF8);
        if (strstr(nm,"unlock")) { static int _ud=0; if(_ud++ < 20) cbrEvent("UNLOCK-DISARM received -> ovr=-1 (was %d)", gCBROrientOverride); { struct timespec _ut; clock_gettime(CLOCK_MONOTONIC,&_ut); gCBRLastUnlock = _ut.tv_sec*1000.0 + _ut.tv_nsec/1000000.0; } gCBROrientOverride = -1; return; }
        // v3.45.0: the landscape notification is broadcast to EVERY injected app. Only react if the
        // host state matches THIS app's hash - otherwise a phone app (Photos) launched while we host
        // on the car would flip landscape on the phone. This is the second half of the leak fix.
        if (gCBROwnBidHash == 0) {
            @try {
                id _mb = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSBundle"), sel_registerName("mainBundle"));
                id _bo = _mb ? ((id(*)(id,SEL))objc_msgSend)(_mb, sel_registerName("bundleIdentifier")) : nil;
                const char *_bc = _bo ? ((const char*(*)(id,SEL))objc_msgSend)(_bo, sel_registerName("UTF8String")) : NULL;
                gCBROwnBidHash = cbrBidHash(_bc);
            } @catch(...) {}
        }
        { uint64_t _hs = cbrReadHostState();
          if (_hs == 0 || _hs != gCBROwnBidHash) {
              // v3.49.0: log the verdict instead of vanishing.
              static int _mm = 0; if (_mm++ < 6) cbrEvent("ORIENT-NOTE ignored: state=%llu own=%llu (not the hosted app)", (unsigned long long)_hs, (unsigned long long)gCBROwnBidHash);
              return;
          } }
        gCBROrientOverride = 3;
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        id arr = ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(app,sel_registerName("connectedScenes")), sel_registerName("allObjects"));
        NSUInteger sc = ((NSUInteger(*)(id,SEL))objc_msgSend)(arr, sel_registerName("count"));
        for (NSUInteger i=0;i<sc;i++){
            id scene=((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr,sel_registerName("objectAtIndex:"),i);
            if (!strstr(object_getClassName(scene),"WindowScene")) continue;
            id ss=((id(*)(id,SEL))objc_msgSend)(scene,sel_registerName("screen"));
            CGRect sb= ss?((CGRect(*)(id,SEL))objc_msgSend)(ss,sel_registerName("bounds")):CGRectZero;
            CGFloat sw=sb.size.width, sh=sb.size.height;
            CGFloat lw=(sw>sh)?sw:sh, lh=(sw>sh)?sh:sw;
            int carScene = (lw>0 && lw<=520);
            if (!carScene) continue;   // v3.45.0: only force orientation on the CAR scene, never the phone scene
            id wins=((id(*)(id,SEL))objc_msgSend)(scene,sel_registerName("windows"));
            NSUInteger wc= wins?((NSUInteger(*)(id,SEL))objc_msgSend)(wins,sel_registerName("count")):0;
            for (NSUInteger w=0; w<wc; w++){
                id win=((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins,sel_registerName("objectAtIndex:"),w);
                SEL _sro=sel_registerName("_setRotatableViewOrientation:duration:force:");
                if ([win respondsToSelector:_sro]) ((void(*)(id,SEL,int,float,int))objc_msgSend)(win,_sro,3,0.0f,1);
                // v3.28.0: app-side PORTRAIT window pin REMOVED - it forced the sideways shape and
                // would directly undo the new landscape canvas.
                if (0) {
                    ((void(*)(id,SEL,CGRect))objc_msgSend)(win,sel_registerName("setBounds:"),CGRectMake(0,0,lh,lw));
                    ((void(*)(id,SEL,CGRect))objc_msgSend)(win,sel_registerName("setFrame:"),CGRectMake(0,0,lh,lw));
                }
                id rvc=((id(*)(id,SEL))objc_msgSend)(win,sel_registerName("rootViewController"));
                if (rvc){
                    // v3.24.0: root-view landscape force DISABLED - UIKit sizes it to the window.
                    if (0) { id v=((id(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("view"));
                        if (v) ((void(*)(id,SEL,CGRect))objc_msgSend)(v,sel_registerName("setFrame:"),CGRectMake(0,0,lw,lh)); }
                    SEL _upd=sel_registerName("setNeedsUpdateOfSupportedInterfaceOrientations");
                    if ([rvc respondsToSelector:_upd]) ((void(*)(id,SEL))objc_msgSend)(rvc,_upd);
                }
            }
        }
        cbrYTGeomProbe("orient");
        // v3.43.0: start the carplay-cast keyWindow kick chain (force landscape on the
        // live key window, repeatedly across launch). This is the mechanism that makes
        // carplay-cast upright 100% of the time; the window walk above is CBR legacy.
        cbrAppKickLandscape(0);
    } @catch(...) {}
}

static void cbrDumpV(FILE *f, id v, int depth) {
    if (!v || depth>60) return;
    @try {
        CGRect b=((CGRect(*)(id,SEL))objc_msgSend)(v,sel_registerName("bounds"));
        if (b.size.width>250.0 || b.size.height>250.0) {
            CGAffineTransform t=((CGAffineTransform(*)(id,SEL))objc_msgSend)(v,sel_registerName("transform"));
            id lyr=((id(*)(id,SEL))objc_msgSend)(v,sel_registerName("layer"));
            const char *lc = lyr?object_getClassName(lyr):"-";
            const char *rot=(t.b!=0.0||t.c!=0.0)?"  <<<ROT":"";
            fprintf(f,"%*s%s b=%.0fx%.0f xf=[%.2f %.2f %.2f %.2f] layer=%s%s\n",depth*2,"",object_getClassName(v),b.size.width,b.size.height,t.a,t.b,t.c,t.d,lc,rot);
        }
        id subs=((id(*)(id,SEL))objc_msgSend)(v,sel_registerName("subviews"));
        NSUInteger n=subs?((NSUInteger(*)(id,SEL))objc_msgSend)(subs,sel_registerName("count")):0;
        for(NSUInteger k=0;k<n;k++){ id sv=((id(*)(id,SEL,NSUInteger))objc_msgSend)(subs,sel_registerName("objectAtIndex:"),k); cbrDumpV(f,sv,depth+1); }
    } @catch(...) {}
}
static void cbrDumpLayers(FILE *f, id layer, int depth) {
    if (!layer || depth>60) return;
    @try {
        CGRect b=((CGRect(*)(id,SEL))objc_msgSend)(layer,sel_registerName("bounds"));
        CGAffineTransform t=((CGAffineTransform(*)(id,SEL))objc_msgSend)(layer,sel_registerName("affineTransform"));
        const char *cn=object_getClassName(layer);
        int rot=(t.b!=0.0||t.c!=0.0);
        int big=(b.size.width>150.0||b.size.height>150.0);
        int interesting = rot || strcasestr(cn,"player")||strcasestr(cn,"video")||strcasestr(cn,"sample")||strcasestr(cn,"mdx")||strcasestr(cn,"host")||strcasestr(cn,"context")||strcasestr(cn,"remote")||strcasestr(cn,"stream");
        if (big || interesting) {
            CGRect cr=((CGRect(*)(id,SEL))objc_msgSend)(layer,sel_registerName("contentsRect"));
            id cg=((id(*)(id,SEL))objc_msgSend)(layer,sel_registerName("contentsGravity"));
            char cgs[64]; cgs[0]=0; if(cg) CFStringGetCString((CFStringRef)cg,cgs,sizeof(cgs),kCFStringEncodingUTF8);
            const char *rr=rot?"  <<<LAYERROT":"";
            fprintf(f,"%*sL:%s b=%.0fx%.0f af=[%.2f %.2f %.2f %.2f] cr=[%.2f %.2f %.1fx%.1f] g=%s%s\n",depth*2,"",cn,b.size.width,b.size.height,t.a,t.b,t.c,t.d,cr.origin.x,cr.origin.y,cr.size.width,cr.size.height,cgs,rr);
        }
        id subs=((id(*)(id,SEL))objc_msgSend)(layer,sel_registerName("sublayers"));
        NSUInteger n=subs?((NSUInteger(*)(id,SEL))objc_msgSend)(subs,sel_registerName("count")):0;
        for(NSUInteger k=0;k<n;k++){ id sl=((id(*)(id,SEL,NSUInteger))objc_msgSend)(subs,sel_registerName("objectAtIndex:"),k); cbrDumpLayers(f,sl,depth+1); }
    } @catch(...) {}
}

static void cbrViewProbe(void) {
    @try {
        NSString *path=[NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_yt_views.txt"];
        FILE *f=fopen([path fileSystemRepresentation],"a"); if(!f) return;
        fprintf(f,"==== VIEWS t=%ld ====\n",(long)time(NULL));
        id app=((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"),sel_registerName("sharedApplication"));
        id arr=((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(app,sel_registerName("connectedScenes")),sel_registerName("allObjects"));
        NSUInteger sc=((NSUInteger(*)(id,SEL))objc_msgSend)(arr,sel_registerName("count"));
        for(NSUInteger i=0;i<sc;i++){ id scene=((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr,sel_registerName("objectAtIndex:"),i);
            if(!strstr(object_getClassName(scene),"WindowScene")) continue;
            id wins=((id(*)(id,SEL))objc_msgSend)(scene,sel_registerName("windows"));
            NSUInteger wc=wins?((NSUInteger(*)(id,SEL))objc_msgSend)(wins,sel_registerName("count")):0;
            for(NSUInteger w=0;w<wc;w++){ id win=((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins,sel_registerName("objectAtIndex:"),w);
                BOOL key=((BOOL(*)(id,SEL))objc_msgSend)(win,sel_registerName("isKeyWindow"));
                if(!key) continue;
                id rvc=((id(*)(id,SEL))objc_msgSend)(win,sel_registerName("rootViewController"));
                fprintf(f,"  KEY %s rootVC=%s\n",object_getClassName(win),rvc?object_getClassName(rvc):"(nil)");
                if(rvc){ id rv=((id(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("view")); if(rv){ cbrDumpV(f,rv,2); id ly=((id(*)(id,SEL))objc_msgSend)(rv,sel_registerName("layer")); if(ly){ fprintf(f,"  -- LAYER TREE --\n"); cbrDumpLayers(f,ly,2); } } }
            }
        }
        fprintf(f,"==== END ====\n"); fclose(f);
    } @catch(...) {}
}

static void cbrNoteLandscape(void) {
    @try {
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        if (!app) return;
        SEL note = sel_registerName("noteInterfaceOrientationChanged:duration:updateMirroredDisplays:force:logMessage:");
        if ([app respondsToSelector:note])
            ((void(*)(id,SEL,long,double,BOOL,BOOL,id))objc_msgSend)(app, note, (long)3, (double)0.0, (BOOL)YES, (BOOL)YES, @"CBR");
    } @catch(...) {}
}
// ===================== v3.22.1 READ-ONLY PROBE =====================
// Observe-only. Writes the full orientation/geometry state to a FIXED path every 1s while
// hosted, so the good-boot and sideways-boot states can be captured and diffed. Nothing here
// mutates the app -- no bounds pinning, no orientation kick, no screen/safe-area hooks.
#import <stdarg.h>
static CGFloat gCBRCarW = 0, gCBRCarH = 0;
static int gCBRSroCalls = 0;
static int gCBRSroLastVal = -99;
static long gCBRLastVcIfo = -99;
static long gCBRLastAct = -99;
static double gCBRT0 = 0;
static double cbrNowMs(void) { struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts); return ts.tv_sec*1000.0 + ts.tv_nsec/1000000.0; }
static void cbrEvent(const char *fmt, ...) {
    @try {
        if (gCBRT0 == 0) gCBRT0 = cbrNowMs();
        char line[300]; va_list ap; va_start(ap, fmt); int n = vsnprintf(line, sizeof(line), fmt, ap); va_end(ap);
        if (n <= 0) return;
        char stamped[360]; int m = snprintf(stamped, sizeof(stamped), "[+%8.1fms] %s\n", cbrNowMs()-gCBRT0, line);
        NSString *pp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_events.txt"];
        FILE *f = fopen([pp fileSystemRepresentation], "a"); if (f) { fwrite(stamped,1,(size_t)m,f); fclose(f); }
    } @catch(...) {}
}

static void cbrProbeDiscover(id app) {
    if (gCBRCarW > 0 || !app) return;
    @try {
        // 1) the correct way: a connected scene whose screen is the car screen
        id scenes = ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes"));
        id arr = scenes ? ((id(*)(id,SEL))objc_msgSend)(scenes, sel_registerName("allObjects")) : nil;
        NSUInteger sc = arr ? ((NSUInteger(*)(id,SEL))objc_msgSend)(arr, sel_registerName("count")) : 0;
        SEL _iscar = sel_registerName("_isCarScreen");
        for (NSUInteger i = 0; i < sc; i++) {
            id scene = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr, sel_registerName("objectAtIndex:"), i);
            if (!scene || ![scene isKindOfClass:objc_getClass("UIWindowScene")]) continue;
            id scr = ((id(*)(id,SEL))objc_msgSend)(scene, sel_registerName("screen"));
            BOOL isCar = scr && [scr respondsToSelector:_iscar] ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, _iscar) : NO;
            if (isCar) {
                CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));
                gCBRCarW = b.size.width > b.size.height ? b.size.width : b.size.height;
                gCBRCarH = b.size.width > b.size.height ? b.size.height : b.size.width;
                return;
            }
        }
        // 2) fallback: our hosted key window IS the car-landscape window
        id kw = ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("keyWindow"));
        if (kw) {
            CGRect b = ((CGRect(*)(id,SEL))objc_msgSend)(kw, sel_registerName("bounds"));
            CGFloat mx = b.size.width > b.size.height ? b.size.width : b.size.height;
            CGFloat mn = b.size.width > b.size.height ? b.size.height : b.size.width;
            if (mx > 0 && mx <= 520) { gCBRCarW = mx; gCBRCarH = mn; }
        }
    } @catch(...) {}
}

static void cbrProbeSchedule(void);
// v3.24.4: iOS16 PUBLIC orientation command. requestGeometryUpdateWithPreferences: actively rotates
// the scene (the same thing a phone-tap triggers) - unlike _setRotatableViewOrientation, which we
// proved is a dead lever. Command LandscapeRight (vcIfo=3, the good-boot value) until it sticks.
static void cbrSwizzleLandscape(Class cls) {
    @try {
        if (!cls) return;
        const char *cn = class_getName(cls);
        // v3.27.1: the YTAppViewControllerImpl EXCLUSION IS THE BUG. It overrides
        // supportedInterfaceOrientations and hard-returns 0x2 (portrait). Probe caught it:
        //     rvc=YTAppViewControllerImpl supp=0x2 __supp=0x18
        // __supp=0x18 = our %hook UIViewController works; supp=0x2 = the SUBCLASS override
        // bypasses it (a %hook on UIViewController never sees a subclass's own impl).
        // Portrait layout on the phone canvas -> compositor lands it SIDEWAYS; landscape -> UPRIGHT.
        // This is why YouTube + YouTube TV (both Google, same VC class) are sideways while Amazon
        // (no override -> our hook applies) is always upright. Swizzle it like every other class.
        static NSMutableSet *done = nil;
        if (!done) done = [[NSMutableSet alloc] init];
        NSString *key = [NSString stringWithUTF8String:cn];
        if ([done containsObject:key]) return;
        [done addObject:key];
        const char *sels[2] = {"supportedInterfaceOrientations", "__supportedInterfaceOrientations"};
        for (int i=0;i<2;i++){
            SEL sel = sel_registerName(sels[i]);
            Method m = class_getInstanceMethod(cls, sel);
            if (!m) continue;
            IMP orig = method_getImplementation(m);
            IMP newImp = imp_implementationWithBlock(^NSUInteger(id sf){
                // v3.43.0: LandscapeRight ONLY (0x8). carplay-cast forces a SINGLE
                // orientation (3) and never hooks supportedInterfaceOrientations at all;
                // returning BOTH landscapes (0x18) let UIKit pick LandscapeLeft, which
                // composites sideways on YouTube/YT-TV. One orientation = no wrong choice.
                if (gCBROrientOverride > 0) return (NSUInteger)(1UL<<3);
                return ((NSUInteger(*)(id,SEL))orig)(sf, sel);
            });
            const char *types = method_getTypeEncoding(m);
            if (!class_addMethod(cls, sel, newImp, types)) method_setImplementation(m, newImp);
        }
        cbrEvent("swizzled landscape on %s", cn);
    } @catch(...) {}
}
// v3.44.0: swizzle supportedInterfaceOrientations across the WHOLE view-controller tree, not just
// the window's root VC. YouTube TV's portrait-locked content VC is a CHILD/PRESENTED controller, so
// the root-only swizzle never reached it - which is why override=3 forced landscape everywhere except
// the one class that actually decides YT TV's layout. Recurses children + presented, re-asks UIKit.
static void cbrSwizzleVCTree(id vc, int depth) {
    if (!vc || depth > 8) return;
    @try {
        cbrSwizzleLandscape(object_getClass(vc));
        SEL snu = sel_registerName("setNeedsUpdateOfSupportedInterfaceOrientations");
        if ([vc respondsToSelector:snu]) ((void(*)(id,SEL))objc_msgSend)(vc, snu);
        id kids = [vc respondsToSelector:sel_registerName("childViewControllers")] ? ((id(*)(id,SEL))objc_msgSend)(vc, sel_registerName("childViewControllers")) : nil;
        NSUInteger kc = kids ? ((NSUInteger(*)(id,SEL))objc_msgSend)(kids, sel_registerName("count")) : 0;
        for (NSUInteger i=0;i<kc;i++) cbrSwizzleVCTree(((id(*)(id,SEL,NSUInteger))objc_msgSend)(kids,sel_registerName("objectAtIndex:"),i), depth+1);
        id pres = [vc respondsToSelector:sel_registerName("presentedViewController")] ? ((id(*)(id,SEL))objc_msgSend)(vc, sel_registerName("presentedViewController")) : nil;
        if (pres) cbrSwizzleVCTree(pres, depth+1);
    } @catch(...) {}
}
static void cbrForceLandscapeGeometry(id win) {
    @try {
        id rvc = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("rootViewController"));
        if (!rvc) return;
        // v3.36.0 THE iOS 16+ ROTATION API. Apple's iOS 16 release notes: apps request rotation via
        // [UIWindowScene requestGeometryUpdate:errorHandler:] with UIWindowSceneGeometryPreferencesIOS.
        // shouldAutorotate is deprecated/unsupported; attemptRotationToDeviceOrientation is deprecated,
        // replaced by setNeedsUpdateOfSupportedInterfaceOrientations. That is why every legacy lever
        // failed here: _setRotatableViewOrientation called 4x with force:1 (sroCalls=4) and vcIfo STAYED
        // 1; attemptRotation is a no-op; the supportedInterfaceOrientations swizzle only PERMITS
        // landscape, it never REQUESTS it. requestGeometryUpdate is the only API that rotates on iOS16+,
        // and CBR never called it (a v3.24.4 comment names it but the call was never written).
        // Order matters: setNeedsUpdate... FIRST so UIKit re-reads our swizzled landscape mask, THEN
        // request - else it fails "None of the requested orientations are supported by the view controller".
        SEL snu = sel_registerName("setNeedsUpdateOfSupportedInterfaceOrientations");
        if ([rvc respondsToSelector:snu]) ((void(*)(id,SEL))objc_msgSend)(rvc, snu);

        id ws = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("windowScene"));
        SEL reqSel = sel_registerName("requestGeometryUpdateWithPreferences:errorHandler:");
        Class prefCls = objc_getClass("UIWindowSceneGeometryPreferencesIOS");
        if (ws && prefCls && [ws respondsToSelector:reqSel]) {
            // UIInterfaceOrientationMaskLandscapeRight = 1 << 3 = 8. vcIfo=3 is the confirmed upright state.
            id prefs = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(
                ((id(*)(Class,SEL))objc_msgSend)(prefCls, sel_registerName("alloc")),
                sel_registerName("initWithInterfaceOrientations:"), (NSUInteger)(1UL << 3));
            if (prefs) {
                void (^errh)(id) = ^(id e){
                    if (e) {
                        id d = ((id(*)(id,SEL))objc_msgSend)(e, sel_registerName("localizedDescription"));
                        cbrEvent("GEOM-REQ FAILED: %s", d ? [(NSString *)d UTF8String] : "?");
                    }
                };
                ((void(*)(id,SEL,id,id))objc_msgSend)(ws, reqSel, prefs, errh);
                static int _gq=0; if(_gq++ < 12) cbrEvent("GEOM-REQ requestGeometryUpdate LandscapeRight on %s", object_getClassName(ws));
            }
        } else {
            static int _nx=0; if(_nx++ < 4) cbrEvent("GEOM-REQ UNAVAILABLE ws=%d prefCls=%d responds=%d",
                ws?1:0, prefCls?1:0, (ws && [ws respondsToSelector:reqSel])?1:0);
        }
        static int _rq=0; if(_rq++ < 8) cbrEvent("reeval landscape on %s", object_getClassName(rvc));
    } @catch(...) {}
}
static inline int cbrIsHostedLandscapeWindow(id win);   // v3.48.0 fwd decl (defined in the UIWindow hook below)
// v3.53.0 ORIENT3 PROBE. Colin's repro is 3 clean states: (S1) boot SIDEWAYS, (S2) tap the app
// on the PHONE -> UPRIGHT, (S3) fullscreen a video then exit -> SIDEWAYS again. The phone tap is
// the one lever that always works; we have never captured what it flips that our silent-activate
// does not. This logs one compact, diffable line of the biggest window's真 state so S1 vs S2 vs S3
// can be diffed directly. vTf b/c != 0 == the view is rotated 90 (sideways composite); vio is the
// content orientation; act=0 is foreground-ACTIVE (what the phone tap achieves).
static void cbrOrient3(const char *trig, int force) {
    @try {
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        if (!app) return;
        id arr = ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(app,sel_registerName("connectedScenes")), sel_registerName("allObjects"));
        NSUInteger sc = arr ? ((NSUInteger(*)(id,SEL))objc_msgSend)(arr, sel_registerName("count")) : 0;
        id bestScene=nil, bestWin=nil; CGFloat bestA=0;
        for (NSUInteger i=0;i<sc;i++){
            id scene=((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr,sel_registerName("objectAtIndex:"),i);
            if (!scene || ![scene isKindOfClass:objc_getClass("UIWindowScene")]) continue;
            id wins=((id(*)(id,SEL))objc_msgSend)(scene,sel_registerName("windows"));
            NSUInteger wc=wins?((NSUInteger(*)(id,SEL))objc_msgSend)(wins,sel_registerName("count")):0;
            for (NSUInteger w=0;w<wc;w++){
                id win=((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins,sel_registerName("objectAtIndex:"),w);
                if(!win) continue;
                CGRect wb=((CGRect(*)(id,SEL))objc_msgSend)(win,sel_registerName("bounds"));
                CGFloat a=wb.size.width*wb.size.height;
                if(a>bestA){bestA=a;bestWin=win;bestScene=scene;}
            }
        }
        if(!bestScene||!bestWin) return;
        long act=((long(*)(id,SEL))objc_msgSend)(bestScene,sel_registerName("activationState"));
        long sIfo=((long(*)(id,SEL))objc_msgSend)(bestScene,sel_registerName("interfaceOrientation"));
        CGRect wb=((CGRect(*)(id,SEL))objc_msgSend)(bestWin,sel_registerName("bounds"));
        id rvc=((id(*)(id,SEL))objc_msgSend)(bestWin,sel_registerName("rootViewController"));
        long vio=rvc?((long(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("interfaceOrientation")):-1;
        NSUInteger supp=rvc?((NSUInteger(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("supportedInterfaceOrientations")):0;
        CGAffineTransform vtf=CGAffineTransformIdentity; CGRect vb=CGRectZero;
        if(rvc){ id v=((id(*)(id,SEL))objc_msgSend)(rvc,sel_registerName("view")); if(v){ vtf=((CGAffineTransform(*)(id,SEL))objc_msgSend)(v,sel_registerName("transform")); vb=((CGRect(*)(id,SEL))objc_msgSend)(v,sel_registerName("bounds")); } }
        static long _lh=0;
        long h = act + sIfo*10 + vio*100 + (long)(wb.size.width>wb.size.height?1:0)*1000 + (long)supp*10000 + (long)((vtf.b!=0||vtf.c!=0)?1:0)*100000;
        if(!force && h==_lh) return; _lh=h;
        const char *actn=(act==0?"FG-ACTIVE":(act==1?"FG-INACTIVE":(act==2?"BG":"UNATT")));
        char line[440];
        int n=snprintf(line,sizeof(line),"[ORIENT3 %s] ovr=%d act=%ld(%s) sIfo=%ld win=%.0fx%.0f rvc=%s vio=%ld supp=0x%lx vTf=[%.2f %.2f %.2f %.2f] vB=%.0fx%.0f\n",
            trig, gCBROrientOverride, act, actn, sIfo, wb.size.width, wb.size.height, rvc?object_getClassName(rvc):"nil", vio, (unsigned long)supp, vtf.a,vtf.b,vtf.c,vtf.d, vb.size.width, vb.size.height);
        if(n>0){ @try { NSString *p=[NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_orient3.txt"]; int fd=open([p fileSystemRepresentation],O_WRONLY|O_CREAT|O_APPEND,0644); if(fd>=0){write(fd,line,(size_t)n); close(fd);} } @catch(...) {} }
    } @catch(...) {}
}
// v3.61.0 ORIENT-DETAIL PROBE: full VC-tree dump so a SIDEWAYS app (Messenger) can be diffed vs an
// UPRIGHT one to find the exact VC/mask that differs. tf b/c != 0 == the view is rotated 90.
static void cbrOrientDetailVC(id vc, int fd, int depth) {
    if (!vc || depth > 12) return;
    @try {
        NSUInteger supp = ((NSUInteger(*)(id,SEL))objc_msgSend)(vc, sel_registerName("supportedInterfaceOrientations"));
        SEL _pv = sel_registerName("__supportedInterfaceOrientations");
        NSUInteger psupp = [vc respondsToSelector:_pv] ? ((NSUInteger(*)(id,SEL))objc_msgSend)(vc, _pv) : 0;
        long vio = ((long(*)(id,SEL))objc_msgSend)(vc, sel_registerName("interfaceOrientation"));
        id v = ((id(*)(id,SEL))objc_msgSend)(vc, sel_registerName("view"));
        CGAffineTransform tf = v ? ((CGAffineTransform(*)(id,SEL))objc_msgSend)(v, sel_registerName("transform")) : CGAffineTransformIdentity;
        CGRect vb = v ? ((CGRect(*)(id,SEL))objc_msgSend)(v, sel_registerName("bounds")) : CGRectZero;
        char _ind[28]; int _i; for(_i=0;_i<depth&&_i<12;_i++) _ind[_i]=' '; _ind[_i]=0;
        char _b[440]; int _n=snprintf(_b,sizeof(_b),"%s%s supp=0x%lx __supp=0x%lx vio=%ld vb=%.0fx%.0f tf=[%.2f %.2f %.2f %.2f]\n", _ind, object_getClassName(vc), (unsigned long)supp, (unsigned long)psupp, vio, vb.size.width, vb.size.height, tf.a,tf.b,tf.c,tf.d);
        if(_n>0) write(fd,_b,(size_t)_n);
        id kids = ((id(*)(id,SEL))objc_msgSend)(vc, sel_registerName("childViewControllers"));
        NSUInteger kc = kids ? ((NSUInteger(*)(id,SEL))objc_msgSend)(kids, sel_registerName("count")) : 0;
        for (NSUInteger k=0;k<kc && k<20;k++) cbrOrientDetailVC(((id(*)(id,SEL,NSUInteger))objc_msgSend)(kids,sel_registerName("objectAtIndex:"),k), fd, depth+1);
        id pres = ((id(*)(id,SEL))objc_msgSend)(vc, sel_registerName("presentedViewController"));
        if (pres && pres != vc) cbrOrientDetailVC(pres, fd, depth+1);
    } @catch(...) {}
}
static void cbrOrientDetail(id win, id scene) {
    @try {
        NSString *p = [NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_orient_detail.txt"];
        int fd = open([p fileSystemRepresentation], O_WRONLY|O_CREAT|O_APPEND, 0644);
        if (fd < 0) return;
        id mb = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSBundle"), sel_registerName("mainBundle"));
        id bo = mb ? ((id(*)(id,SEL))objc_msgSend)(mb, sel_registerName("bundleIdentifier")) : nil;
        const char *bid = bo ? ((const char*(*)(id,SEL))objc_msgSend)(bo, sel_registerName("UTF8String")) : "?";
        long sIfo = ((long(*)(id,SEL))objc_msgSend)(scene, sel_registerName("interfaceOrientation"));
        CGRect wb = ((CGRect(*)(id,SEL))objc_msgSend)(win, sel_registerName("bounds"));
        char _hb[320]; int _hn=snprintf(_hb,sizeof(_hb),"==== ORIENT-DETAIL bid=%s ovr=%d sceneIfo=%ld win=%s %.0fx%.0f ====\n", bid, gCBROrientOverride, sIfo, object_getClassName(win), wb.size.width, wb.size.height);
        if(_hn>0) write(fd,_hb,(size_t)_hn);
        id rvc = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("rootViewController"));
        cbrOrientDetailVC(rvc, fd, 0);
        const char *_e="==== END ====\n"; write(fd,_e,strlen(_e));
        close(fd);
    } @catch(...) {}
}
static void cbrProbeTick(void) {
    // v3.22.2: NO early bail. v3.22.1 returned here whenever the gate was shut, so "no file"
    // was ambiguous between "probe never ran" and "never hosted". Always write; the dump
    // reports override so we can tell which.
    // v3.49.0 HOST-STATE ARM: see patch header. Runs BEFORE the main probe body so an
    // exception anywhere in the dump can never starve the arming path.
    if (gCBROrientOverride > 0) gCBRWasArmed = 1;   // v3.54.0: remember we were hosted this process
    @try {
        if (gCBROrientOverride <= 0) {
            if (gCBROwnBidHash == 0) {
                id _mb = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSBundle"), sel_registerName("mainBundle"));
                id _bo = _mb ? ((id(*)(id,SEL))objc_msgSend)(_mb, sel_registerName("bundleIdentifier")) : nil;
                const char *_bc = _bo ? ((const char*(*)(id,SEL))objc_msgSend)(_bo, sel_registerName("UTF8String")) : NULL;
                gCBROwnBidHash = cbrBidHash(_bc);
            }
            uint64_t _hs2 = cbrReadHostState();
            // v3.54.0 RE-ARM: sideways == ovr disarmed by a spurious unlock while STILL hosted.
            // Read the biggest window's SCENE orientation; a hosted app's scene is landscape (3/4,
            // we set BORN-LANDSCAPE), a phone app's is portrait (1). Landscape scene + (armed this
            // process OR host state still matches) == still hosted -> re-arm and re-force landscape.
            long _armSIfo = -1; CGFloat _armBest = 0;
            @try {
                id _aapp = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
                id _aarr = _aapp ? ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(_aapp, sel_registerName("connectedScenes")), sel_registerName("allObjects")) : nil;
                NSUInteger _asc = _aarr ? ((NSUInteger(*)(id,SEL))objc_msgSend)(_aarr, sel_registerName("count")) : 0;
                for (NSUInteger _ai=0; _ai<_asc; _ai++){
                    id _asce = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(_aarr, sel_registerName("objectAtIndex:"), _ai);
                    if (!_asce || ![_asce isKindOfClass:objc_getClass("UIWindowScene")]) continue;
                    long _aio = ((long(*)(id,SEL))objc_msgSend)(_asce, sel_registerName("interfaceOrientation"));
                    id _awins = ((id(*)(id,SEL))objc_msgSend)(_asce, sel_registerName("windows"));
                    NSUInteger _awc = _awins ? ((NSUInteger(*)(id,SEL))objc_msgSend)(_awins, sel_registerName("count")) : 0;
                    for (NSUInteger _aw=0; _aw<_awc; _aw++){
                        id _awin = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(_awins, sel_registerName("objectAtIndex:"), _aw);
                        if(!_awin) continue;
                        CGRect _awb = ((CGRect(*)(id,SEL))objc_msgSend)(_awin, sel_registerName("bounds"));
                        CGFloat _aa = _awb.size.width*_awb.size.height;
                        if(_aa > _armBest){ _armBest=_aa; _armSIfo=_aio; }
                    }
                }
            } @catch(...) {}
            int _hostMatch = (_hs2 != 0 && _hs2 == gCBROwnBidHash);
            // v3.55.0: the wasArmed re-arm recovers a SPURIOUS unlock (app disarmed but still hosted)
            // but must NOT fire during a GENUINE exit, or it re-arms + keep-alives a dying app and
            // fights the teardown (= can't-exit, 2 overlapping scenes, YouTube zombie that won't
            // re-host). A genuine dismiss SIGKILLs the app in ~1-2s, so wait 3s after the last unlock
            // before re-arming on wasArmed alone. hostMatch (a real re-host republished the state)
            // still re-arms immediately.
            double _nowU; { struct timespec _nt; clock_gettime(CLOCK_MONOTONIC,&_nt); _nowU = _nt.tv_sec*1000.0 + _nt.tv_nsec/1000000.0; }
            int _graceOK = (gCBRLastUnlock == 0 || (_nowU - gCBRLastUnlock) > 3000.0);
            int _stillHosted = ((_armSIfo == 3 || _armSIfo == 4) && ((gCBRWasArmed && _graceOK) || _hostMatch));
            if (_hostMatch || _stillHosted) {
                gCBROrientOverride = 3;
                gCBRWasArmed = 1;
                cbrEvent("%s -> override=3 (hostMatch=%d sceneIfo=%ld wasArmed=%d)", _hostMatch ? "HOST-STATE armed at probe tick" : "RE-ARM still-hosted (spurious unlock recovered)", _hostMatch, _armSIfo, gCBRWasArmed);
                cbrAppKickLandscape(0);
                // v3.51.0 ARM-NUDGE: arming at a probe tick means we armed AFTER the app's first
                // layout (warm app / lost race). The mask hooks now answer landscape-only but
                // UIKit never re-asks on its own - force a re-resolution on every rootVC.
                @try {
                    id _napp = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
                    id _narr = _napp ? ((id(*)(id,SEL))objc_msgSend)(((id(*)(id,SEL))objc_msgSend)(_napp, sel_registerName("connectedScenes")), sel_registerName("allObjects")) : nil;
                    NSUInteger _nsc = _narr ? ((NSUInteger(*)(id,SEL))objc_msgSend)(_narr, sel_registerName("count")) : 0;
                    for (NSUInteger _ni = 0; _ni < _nsc; _ni++) {
                        id _nsce = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(_narr, sel_registerName("objectAtIndex:"), _ni);
                        if (!_nsce || ![_nsce isKindOfClass:objc_getClass("UIWindowScene")]) continue;
                        id _nwins = ((id(*)(id,SEL))objc_msgSend)(_nsce, sel_registerName("windows"));
                        NSUInteger _nwc = _nwins ? ((NSUInteger(*)(id,SEL))objc_msgSend)(_nwins, sel_registerName("count")) : 0;
                        for (NSUInteger _nw = 0; _nw < _nwc; _nw++) {
                            id _nwin = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(_nwins, sel_registerName("objectAtIndex:"), _nw);
                            id _nrvc = _nwin ? ((id(*)(id,SEL))objc_msgSend)(_nwin, sel_registerName("rootViewController")) : nil;
                            SEL _nupd = sel_registerName("setNeedsUpdateOfSupportedInterfaceOrientations");
                            if (_nrvc && [_nrvc respondsToSelector:_nupd]) {
                                static int _an = 0; if (_an++ < 6) cbrEvent("ARM-NUDGE re-resolution on %s", object_getClassName(_nrvc));
                                ((void(*)(id,SEL))objc_msgSend)(_nrvc, _nupd);
                            }
                            SEL _nhi = sel_registerName("setNeedsUpdateOfHomeIndicatorAutoHidden");   // v3.54.0: refresh the pill hide now that we are armed
                            if (_nrvc && [_nrvc respondsToSelector:_nhi]) ((void(*)(id,SEL))objc_msgSend)(_nrvc, _nhi);
                        }
                    }
                } @catch(...) {}
            }
        }
    } @catch(...) {}
    @try {
        id app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
        if (!app) return;
        cbrProbeDiscover(app);

        static int _tick = 0; _tick++;
        cbrEvent("tick %d (heartbeat)", _tick);
        cbrOrient3("tick", 0);   // v3.53.0: steady-state, logs only on change
        NSMutableString *out = [NSMutableString string];
        [out appendFormat:@"=== CBR PROBE v3.24.0 tick=%d override=%d hosted=%s car=%.0fx%.0f sroCalls=%d lastAsk=%d ===\n",
            _tick, gCBROrientOverride, (gCBROrientOverride > 0 ? "YES" : "no"), gCBRCarW, gCBRCarH, gCBRSroCalls, gCBRSroLastVal];

        id ms = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIScreen"), sel_registerName("mainScreen"));
        CGRect mb = ((CGRect(*)(id,SEL))objc_msgSend)(ms, sel_registerName("bounds"));
        CGFloat msc = ((CGFloat(*)(id,SEL))objc_msgSend)(ms, sel_registerName("scale"));
        [out appendFormat:@"UIScreen.main bounds=%.0fx%.0f scale=%.1f\n", mb.size.width, mb.size.height, msc];

        // v3.47.0 TRUTH CHANNEL locals: track the LARGEST window across all scenes (the app's
        // real main window - phone-canvas ~430x932/932x430 dwarfs any 472x281 template window)
        // and remember ITS scene's interfaceOrientation. That pair is the app's actual layout
        // truth; clientSettings proved to be an ACK of what we wrote, not what UIKit did.
        long _truthIfo = 0, _truthVio = 0; CGFloat _truthW = 0, _truthH = 0, _truthBest = 0;   // v3.51.0: content orientation joins the truth
        id scenes = ((id(*)(id,SEL))objc_msgSend)(app, sel_registerName("connectedScenes"));
        id arr = scenes ? ((id(*)(id,SEL))objc_msgSend)(scenes, sel_registerName("allObjects")) : nil;
        NSUInteger sc = arr ? ((NSUInteger(*)(id,SEL))objc_msgSend)(arr, sel_registerName("count")) : 0;
        for (NSUInteger i = 0; i < sc; i++) {
            id scene = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(arr, sel_registerName("objectAtIndex:"), i);
            if (!scene || ![scene isKindOfClass:objc_getClass("UIWindowScene")]) continue;
            id scr = ((id(*)(id,SEL))objc_msgSend)(scene, sel_registerName("screen"));
            SEL _iscar = sel_registerName("_isCarScreen");
            BOOL isCar = scr && [scr respondsToSelector:_iscar] ? ((BOOL(*)(id,SEL))objc_msgSend)(scr, _iscar) : NO;
            long io = ((long(*)(id,SEL))objc_msgSend)(scene, sel_registerName("interfaceOrientation"));
            long act = ((long(*)(id,SEL))objc_msgSend)(scene, sel_registerName("activationState"));
            const char *actn = (act==0?"FG-ACTIVE":(act==1?"FG-INACTIVE":(act==2?"BACKGROUND":"UNATTACHED")));
            [out appendFormat:@"scene[%lu] %s car=%d ifo=%ld act=%ld(%s)\n", (unsigned long)i, object_getClassName(scene), isCar, io, act, actn];
            if (act != gCBRLastAct) {
                cbrEvent("scene activationState %ld -> %ld (%s)", gCBRLastAct, act, actn);
                // v3.31.0 TAP CAPTURE: the manual phone-tap fixes sideways->upright 100%, and the tap
                // IS the scene going foreground-ACTIVE. We've only ever compared steady states (found
                // identical); dump the full window/layer tree the instant activation changes so a
                // sideways->active dump can be diffed against pre-active to see what the tap mutates.
                @try { char _tag[64]; snprintf(_tag,sizeof(_tag),"ACT-TRANSITION-%ld-to-%ld",gCBRLastAct,act); cbrYTGeomProbe(_tag); } @catch(...) {}
                @try { char _o3[48]; snprintf(_o3,sizeof(_o3),"ACT-%ld->%ld",gCBRLastAct,act); cbrOrient3(_o3, 1); } @catch(...) {}   // v3.53.0: the phone-tap edge
                gCBRLastAct = act;
            }
            id wins = ((id(*)(id,SEL))objc_msgSend)(scene, sel_registerName("windows"));
            NSUInteger wc = wins ? ((NSUInteger(*)(id,SEL))objc_msgSend)(wins, sel_registerName("count")) : 0;
            for (NSUInteger w = 0; w < wc; w++) {
                id win = ((id(*)(id,SEL,NSUInteger))objc_msgSend)(wins, sel_registerName("objectAtIndex:"), w);
                if (!win) continue;
                CGRect wb = ((CGRect(*)(id,SEL))objc_msgSend)(win, sel_registerName("bounds"));
                id rvc = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("rootViewController"));
                long vio = rvc ? ((long(*)(id,SEL))objc_msgSend)(rvc, sel_registerName("interfaceOrientation")) : -1;
                // v3.47.0: truth tracking - biggest window wins; its scene ifo is the app's truth.
                if (gCBROrientOverride > 0) {
                    CGFloat _a = wb.size.width * wb.size.height;
                    if (_a > _truthBest) { _truthBest = _a; _truthIfo = io; _truthW = wb.size.width; _truthH = wb.size.height; _truthVio = (vio > 0 && vio <= 4) ? vio : 0; }   // v3.51.0: capture content orientation too
                }
                // v3.27.2: log WINDOW + rootVC-view TRANSFORM for EVERY window (not just YTMainWindow).
                // Amazon renders upright, all others sideways, but we've only ever logged YTMainWindow -
                // so we've never seen what Amazon does differently. supportedInterfaceOrientations is
                // proven dead (swizzle set supp=0x18, vcIfo stayed 1). The discriminator must be the
                // transform/geometry: a compositor rotation of a portrait canvas shows as 90deg here.
                CGAffineTransform _wtf = CGAffineTransformIdentity, _vtf = CGAffineTransformIdentity;
                @try { id _wl = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("layer"));
                    if (_wl) _wtf = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(_wl, sel_registerName("affineTransform")); } @catch(...) {}
                @try { if (rvc) { id _v = ((id(*)(id,SEL))objc_msgSend)(rvc, sel_registerName("view"));
                    if (_v) _vtf = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(_v, sel_registerName("transform")); } } @catch(...) {}
                [out appendFormat:@"  win[%lu] %s bounds=%.0fx%.0f rootVC=%s vcIfo=%ld wxf=[%.2f %.2f %.2f %.2f] vxf=[%.2f %.2f %.2f %.2f]\n",
                    (unsigned long)w, object_getClassName(win), wb.size.width, wb.size.height,
                    rvc ? object_getClassName(rvc) : "nil", vio,
                    _wtf.a,_wtf.b,_wtf.c,_wtf.d, _vtf.a,_vtf.b,_vtf.c,_vtf.d];
                { static int _od=0; if (rvc && _od++ < 16) cbrOrientDetail(win, scene); }   // v3.61.0 ORIENT-DETAIL: full VC-tree dump (Messenger vs upright)
                // v3.57.0 PILL PROBE: walk the childViewControllerForHomeIndicatorAutoHidden chain -
                // the VCs UIKit resolves the pill from. The LEAF is what to hook (like CBR hooks
                // YTAppViewControllerImpl for orientation). leafHidden=0 means the leaf overrides
                // prefersHomeIndicatorAutoHidden and returns NO (bypassing our base hook = pill shows).
                if (rvc) {   // v3.58.0: ungated - the pill shows when DISARMED, so capture the chain regardless of ovr (ovr is logged)
                    static int _ppw = 0;
                    if (_ppw++ < 10) {
                        @try {
                            id _cur = rvc; int _d = 0; char _chain[400]; int _co = 0;
                            SEL _scHI = sel_registerName("childViewControllerForHomeIndicatorAutoHidden");
                            while (_cur && _d < 8) {
                                int _wr = snprintf(_chain+_co, sizeof(_chain)-_co, "%s%s", _d?" -> ":"", object_getClassName(_cur));
                                if (_wr <= 0) break; _co += _wr;
                                id _nx = [_cur respondsToSelector:_scHI] ? ((id(*)(id,SEL))objc_msgSend)(_cur, _scHI) : nil;
                                if (!_nx || _nx == _cur) break; _cur = _nx; _d++;
                            }
                            SEL _spHI = sel_registerName("prefersHomeIndicatorAutoHidden");
                            int _leaf = (_cur && [_cur respondsToSelector:_spHI]) ? ((BOOL(*)(id,SEL))objc_msgSend)(_cur, _spHI) : -1;
                            cbrEvent("PILL-PROBE chain=[%s] leaf=%s leafHidden=%d ovr=%d", _chain, _cur?object_getClassName(_cur):"nil", _leaf, gCBROrientOverride);
                        } @catch(...) {}
                    }
                }
                if (rvc && gCBROrientOverride > 0 && vio != gCBRLastVcIfo) {   // v3.44.0: ALL hosted windows, not just YTMainWindow
                    NSUInteger rSupp = ((NSUInteger(*)(id,SEL))objc_msgSend)(rvc, sel_registerName("supportedInterfaceOrientations"));
                    SEL _priv = sel_registerName("__supportedInterfaceOrientations");
                    NSUInteger rPriv = [rvc respondsToSelector:_priv] ? ((NSUInteger(*)(id,SEL))objc_msgSend)(rvc, _priv) : 0;
                    SEL _pref = sel_registerName("_preferredInterfaceOrientationForPresentation");
                    long rPref = [rvc respondsToSelector:_pref] ? ((long(*)(id,SEL))objc_msgSend)(rvc, _pref) : -1;
                    cbrEvent("HOSTWIN[%s] vcIfo %ld -> %ld | sceneIfo=%ld car=%d scene=%s | rvc=%s supp=0x%lx __supp=0x%lx pref=%ld | bounds=%.0fx%.0f sroCalls=%d lastAsk=%d",
                        object_getClassName(win), gCBRLastVcIfo, vio, io, isCar, object_getClassName(scene),
                        object_getClassName(rvc), (unsigned long)rSupp, (unsigned long)rPriv, rPref,
                        wb.size.width, wb.size.height, gCBRSroCalls, gCBRSroLastVal);
                    gCBRLastVcIfo = vio;
                }
                if (rvc && gCBROrientOverride > 0 && vio != 3) {
                    cbrSwizzleLandscape(object_getClass(rvc));
                    cbrSwizzleVCTree(rvc, 0);   // v3.44.0: whole tree, catches YT TV's child content VC
                    cbrForceLandscapeGeometry(win);
                    // v3.35.0: ACTIVELY drive rotation like carplay-cast (it CALLS this on the key
                    // window, force=1). CBR only HOOKED the selector - clamping IF the app called it.
                    // On a reused/inactive scene the app never calls it, so the hook had nothing to
                    // clamp (same failure as the setBounds: lock). Call it ourselves.
                    @try {
                        id keyWin = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
                        keyWin = keyWin ? ((id(*)(id,SEL))objc_msgSend)(keyWin, sel_registerName("keyWindow")) : nil;
                        if (!keyWin) keyWin = win;
                        SEL _sro = sel_registerName("_setRotatableViewOrientation:duration:force:");
                        if ([keyWin respondsToSelector:_sro]) {
                            static int _dr=0; if(_dr++ < 12) cbrEvent("ACTIVE-SRO _setRotatableViewOrientation:3 force:1 on %s", object_getClassName(keyWin));
                            ((void(*)(id,SEL,int,float,int))objc_msgSend)(keyWin, _sro, 3, 0.0f, 1);
                        }
                    } @catch(...) {}
                }
                // v3.35.1: ACTIVE-SRO, UNGATED. v3.35.0 nested the active _setRotatableViewOrientation
                // call inside "if (vio != 3)", but the probe reports vcIfo=3 on these boots so it never
                // ran (zero ACTIVE-SRO lines). carplay-cast calls it unconditionally at host time.
                if (cbrIsHostedLandscapeWindow(win)) {   // v3.48.0: all hosted apps, was YTMainWindow only
                    @try {
                        id _app = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("UIApplication"), sel_registerName("sharedApplication"));
                        id _kw = _app ? ((id(*)(id,SEL))objc_msgSend)(_app, sel_registerName("keyWindow")) : nil;
                        if (!_kw) _kw = win;
                        SEL _sro2 = sel_registerName("_setRotatableViewOrientation:duration:force:");
                        if ([_kw respondsToSelector:_sro2]) {
                            static int _as=0; if(_as++ < 12) cbrEvent("ACTIVE-SRO force:1 orient:3 on %s (vcIfo was %ld)", object_getClassName(_kw), vio);
                            ((void(*)(id,SEL,int,float,int))objc_msgSend)(_kw, _sro2, 3, 0.0f, 1);
                        }
                    } @catch(...) {}
                }
                // v3.33.0 DIRECT ASSERT: reactive setBounds: lock never fired on sideways boots
                // (reused/inactive scene never calls setBounds: with a portrait value). Assert the
                // landscape shape directly every tick - tap capture proved 932x430 = upright.
                if (cbrIsHostedLandscapeWindow(win)) {   // v3.48.0: all hosted apps, was YTMainWindow only
                    @try {
                        id _ws = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("windowScene"));
                        id _sc = _ws ? ((id(*)(id,SEL))objc_msgSend)(_ws, sel_registerName("screen")) : nil;
                        if (_sc) {
                            CGRect _sb = ((CGRect(*)(id,SEL))objc_msgSend)(_sc, sel_registerName("bounds"));
                            CGFloat _mx = _sb.size.width > _sb.size.height ? _sb.size.width : _sb.size.height;
                            CGFloat _mn = _sb.size.width > _sb.size.height ? _sb.size.height : _sb.size.width;
                            if (_mx > 0 && (wb.size.height > wb.size.width || fabs(wb.size.width - _mx) > 1.0)) {
                                static int _da=0; if(_da++ < 20) cbrEvent("DIRECT-ASSERT %s %.0fx%.0f -> %.0fx%.0f (screen %.0fx%.0f)", object_getClassName(win), wb.size.width, wb.size.height, _mx, _mn, _sb.size.width, _sb.size.height);
                                ((void(*)(id,SEL,CGRect))objc_msgSend)(win, sel_registerName("setBounds:"), CGRectMake(0,0,_mx,_mn));
                                ((void(*)(id,SEL,CGRect))objc_msgSend)(win, sel_registerName("setFrame:"),  CGRectMake(0,0,_mx,_mn));
                            }
                        }
                    } @catch(...) {}
                }
                // v3.24.0: PERSISTENT PORTRAIT RE-PIN. YouTube reverts the window bounds, so the
                // one-shot pin in cbrAppOrientCallback is not enough. Portrait (281x472) is the
                // shape that yields an upright dash; landscape (472x281) yields sideways.
                if (0 && strcmp(object_getClassName(win), "YTMainWindow") == 0 && gCBRCarW > 0) { }
                if (rvc) {
                    id v = ((id(*)(id,SEL))objc_msgSend)(rvc, sel_registerName("view"));
                    if (v) {
                        CGRect vb = ((CGRect(*)(id,SEL))objc_msgSend)(v, sel_registerName("bounds"));
                        id lyr = ((id(*)(id,SEL))objc_msgSend)(v, sel_registerName("layer"));
                        CGAffineTransform tf = ((CGAffineTransform(*)(id,SEL))objc_msgSend)(v, sel_registerName("transform"));
                        [out appendFormat:@"    view bounds=%.0fx%.0f tf=[%.2f %.2f %.2f %.2f]\n",
                            vb.size.width, vb.size.height, tf.a, tf.b, tf.c, tf.d];
                        (void)lyr;
                    }
                }
            }
        }

        // v3.47.0 TRUTH PUBLISH: hand SpringBoard the app's REAL layout state as notify state.
        // Encoded as ifo (1..4) + 10 when the main window is landscape-shaped, so SB can log
        // both facts from one value. Only the hash-gated hosted app ever has override>0 now
        // (v3.45.0), so no bystander can pollute this channel.
        if (gCBROrientOverride > 0 && _truthBest <= 0) {
            static int _ts = 0; if (_ts++ < 6) cbrEvent("TRUTH skipped: armed but no window found in connectedScenes");   // v3.49.0
        }
        if (gCBROrientOverride > 0 && _truthBest > 0) {
            @try {
                // v3.51.0: hundreds digit = rootVC content orientation. An upright landscape
                // boot (vio=3) and a sideways one (vio=1) BOTH published sceneIfo=3 + a
                // landscape-shaped window (enc=13) - identical truth, so the bounce read
                // "truly landscape" and never fired on the exact boots that needed it.
                uint64_t _enc = (uint64_t)_truthIfo + ((_truthW > _truthH) ? 10 : 0) + ((uint64_t)_truthVio * 100);
                static int _tt = 0; if (!_tt) notify_register_check("com.cbr.app.truth", &_tt);
                if (_tt) notify_set_state(_tt, _enc);
                static uint64_t _lastEnc = 999; static int _tlog = 0;
                if (_enc != _lastEnc || _tlog < 3) {
                    cbrEvent("TRUTH sceneIfo=%ld vio=%ld win=%.0fx%.0f enc=%llu (published)", _truthIfo, _truthVio, _truthW, _truthH, (unsigned long long)_enc);
                    _lastEnc = _enc; _tlog++;
                }
            } @catch(...) {}
        }
        // v3.22.2 FIX: YouTube is SANDBOXED and cannot write to /var/mobile -- that is why the
        // v3.22.1 probe produced no file. v78's own app-side probes use NSTemporaryDirectory();
        // do the same. Also try /var/mobile as a bonus (harmless if the sandbox denies it).
        NSString *tmp = [NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_probe.txt"];
        [out writeToFile:tmp atomically:YES encoding:NSUTF8StringEncoding error:nil];
        [out writeToFile:@"/var/mobile/CBR_probe.txt" atomically:YES encoding:NSUTF8StringEncoding error:nil];
    } @catch(...) {}
}
static void cbrProbeSchedule(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.0 * NSEC_PER_SEC)), dispatch_get_main_queue(), ^{
        cbrProbeTick();
        cbrProbeSchedule();
    });
}

// v3.24.3: GATE-FREE self-detecting lock. v3.24.2 never fired because gCBRCarW is 0 until the 1s
// probe tick and the vcIfo decision lands as early as 81ms. Detect the car scene from the window's
// OWN windowScene.screen (<=520pt) - no override / gCBRCarW dependency - so it fires the instant
// YTMainWindow is first sized. Phone-safe: on the phone YTMainWindow's screen is >520pt.
static inline int cbrCarSizeForWindow(id win, CGFloat *outMin, CGFloat *outMax) {
    id ws = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("windowScene"));
    id scr = ws ? ((id(*)(id,SEL))objc_msgSend)(ws, sel_registerName("screen")) : nil;
    if (!scr) return 0;
    CGRect sb = ((CGRect(*)(id,SEL))objc_msgSend)(scr, sel_registerName("bounds"));
    CGFloat mx = sb.size.width>sb.size.height?sb.size.width:sb.size.height;
    CGFloat mn = sb.size.width>sb.size.height?sb.size.height:sb.size.width;
    if (mx <= 0 || mx > 520) return 0;
    if (gCBRCarW <= 0) { gCBRCarW = mx; gCBRCarH = mn; }
    *outMin = mn; *outMax = mx; return 1;
}

%group APPS


%hook UIWindow
// v3.38.0 THE TIMING FIX. Deep scan proved NO rotation anywhere in the app view tree (non-identity
// transforms: 0 on a sideways boot) - nothing rotates the content, the SURFACE is created with the
// wrong SHAPE. Geom dump: YTMainWindow is 430x932 (PORTRAIT) at [orient]/launch and only flips to
// 932x430 at the LATER activation transition. The host latches the surface while the window is still
// portrait; that portrait surface is composited onto the landscape dash (rotated to fit) and the
// shape is fixed before the window flips. Every prior fix ran on a ~1/sec tick or reacted to
// setBounds: - all too late. makeKeyAndVisible is when the window first becomes visible and its
// surface is created; force landscape HERE, before the surface exists.
- (void)makeKeyAndVisible {
    // v3.40.0 CHICKEN-AND-EGG FIX. v3.38.0 required gCBROrientOverride > 0, but that is only set when
    // the HOST posts com.cbr.orient.landscape - which happens AFTER launch. makeKeyAndVisible fires
    // DURING launch, so the override was still -1 and the guard ALWAYS failed: PRE-SURFACE never
    // logged once, in any container. Detect hosting from the WINDOW instead: its scene screen is
    // landscape. Phone-safe: on the phone the window's screen is portrait, so we skip.
    @try {
        id ws = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("windowScene"));
        id sc = ws ? ((id(*)(id,SEL))objc_msgSend)(ws, sel_registerName("screen")) : nil;
        if (sc) {
            CGRect sb = ((CGRect(*)(id,SEL))objc_msgSend)(sc, sel_registerName("bounds"));
            CGRect b  = ((CGRect(*)(id,SEL))objc_msgSend)(self, sel_registerName("bounds"));
            BOOL screenLandscape = (sb.size.width > sb.size.height && sb.size.width > 0);
            BOOL winPortrait     = (b.size.height > b.size.width);
            static int _mk=0;
            if (_mk++ < 20) cbrEvent("MKV %s win=%.0fx%.0f screen=%.0fx%.0f override=%d",
                object_getClassName(self), b.size.width, b.size.height, sb.size.width, sb.size.height, gCBROrientOverride);
            if (screenLandscape && winPortrait) {
                CGFloat mx = sb.size.width, mn = sb.size.height;
                cbrEvent("PRE-SURFACE landscape at makeKeyAndVisible: %.0fx%.0f -> %.0fx%.0f on %s",
                         b.size.width, b.size.height, mx, mn, object_getClassName(self));
                ((void(*)(id,SEL,CGRect))objc_msgSend)(self, sel_registerName("setBounds:"), CGRectMake(0,0,mx,mn));
                ((void(*)(id,SEL,CGRect))objc_msgSend)(self, sel_registerName("setFrame:"),  CGRectMake(0,0,mx,mn));
            }
        }
    } @catch(...) {}
    %orig;
}
- (void)_setRotatableViewOrientation:(int)orientation duration:(float)duration force:(int)force {
    gCBRSroCalls++; gCBRSroLastVal = orientation;
    if (gCBROrientOverride > 0) {
        cbrEvent("_setRotatableViewOrientation asked=%d force=%d -> FORCED %d on %s", orientation, force, gCBROrientOverride, object_getClassName(self));
        orientation = gCBROrientOverride;
    }
    %orig;
}
// v3.48.0: is this the hosted app's window on a landscape (car) screen? The landscape lock
// used to key on the literal class "YTMainWindow", which ONLY matched plain YouTube - so
// Amazon / YouTube TV (Unplugged) / Reddit were never protected and broke on the AVPlayer
// fullscreen-exit portrait write. Gate on the hosting override (set ONLY for the hash-matched
// hosted app, v3.45.0) AND a landscape scene screen, so no genuine phone-portrait window is
// touched. This makes the lock app-agnostic without risking non-hosted apps.
static inline int cbrIsHostedLandscapeWindow(id win) {
    if (gCBROrientOverride <= 0 || !win) return 0;
    @try {
        id ws = ((id(*)(id,SEL))objc_msgSend)(win, sel_registerName("windowScene"));
        id sc = ws ? ((id(*)(id,SEL))objc_msgSend)(ws, sel_registerName("screen")) : nil;
        if (!sc) return 0;
        CGRect sb = ((CGRect(*)(id,SEL))objc_msgSend)(sc, sel_registerName("bounds"));
        return (sb.size.width > 0 && sb.size.height > 0) ? 1 : 0;   // v3.49.0: any live screen; override is the gate
    } @catch(...) { return 0; }
}
- (void)setBounds:(CGRect)bounds {
    // v3.32.0 THE ROTATION FIX (proven by the tap capture): the manual tap flips YTMainWindow from
    // 430x932 (portrait, sideways) to 932x430 (landscape, upright) on a 932x430 io=3 screen. The
    // lever is YTMainWindow's SHAPE. v3.28.0 removed the old PORTRAIT lock; we actually need a
    // LANDSCAPE lock - force YTMainWindow landscape when it tries to go portrait, like the tap does.
    // v3.32.1 GATE FIX: v3.32.0's lock used cbrCarSizeForWindow(), which bails unless the screen is
    // <=520pt - but the hosted app's screen is 932x430 (max 932), so the gate ALWAYS failed and the
    // lock never ran (same reason the old portrait lock never fired). Gate on gCBROrientOverride>0
    // (set only while hosted) and derive the landscape size from the window's own scene screen.
    // v3.48.0: app-agnostic (was gated to YTMainWindow, i.e. plain YouTube only). Fires the
    // landscape lock on ANY hosted app's window that tries to go portrait - which is exactly
    // what the AVPlayer fullscreen-exit does on Amazon / YouTube TV / Reddit.
    if (bounds.size.height > bounds.size.width && !cbrIsHostedLandscapeWindow(self)) {
        static int _lsk = 0; if (_lsk++ < 8) cbrEvent("LOCK-SKIP portrait setBounds %s %.0fx%.0f (override=%d)", object_getClassName(self), bounds.size.width, bounds.size.height, gCBROrientOverride);   // v3.49.0
    }
    if (bounds.size.height > bounds.size.width && cbrIsHostedLandscapeWindow(self)) {
        @try {
            id _ws = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("windowScene"));
            id _sc = _ws ? ((id(*)(id,SEL))objc_msgSend)(_ws, sel_registerName("screen")) : nil;
            if (_sc) {
                CGRect _sb = ((CGRect(*)(id,SEL))objc_msgSend)(_sc, sel_registerName("bounds"));
                CGFloat _mx = _sb.size.width > _sb.size.height ? _sb.size.width : _sb.size.height;
                CGFloat _mn = _sb.size.width > _sb.size.height ? _sb.size.height : _sb.size.width;
                if (_mx > 0) {
                    static int _ll=0; if(_ll++ < 24) cbrEvent("LANDSCAPE-LOCK setBounds: %s %.0fx%.0f -> %.0fx%.0f (screen %.0fx%.0f)", object_getClassName(self), bounds.size.width, bounds.size.height, _mx, _mn, _sb.size.width, _sb.size.height);
                    bounds.size.width = _mx; bounds.size.height = _mn;
                }
            }
        } @catch(...) {}
    }
    %orig(bounds);
}
- (void)setFrame:(CGRect)frame {
    // v3.32.0: landscape lock (see setBounds:).
    // v3.48.0: app-agnostic (see setBounds:).
    if (frame.size.height > frame.size.width && cbrIsHostedLandscapeWindow(self)) {
        @try {
            id _ws = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("windowScene"));
            id _sc = _ws ? ((id(*)(id,SEL))objc_msgSend)(_ws, sel_registerName("screen")) : nil;
            if (_sc) {
                CGRect _sb = ((CGRect(*)(id,SEL))objc_msgSend)(_sc, sel_registerName("bounds"));
                CGFloat _mx = _sb.size.width > _sb.size.height ? _sb.size.width : _sb.size.height;
                CGFloat _mn = _sb.size.width > _sb.size.height ? _sb.size.height : _sb.size.width;
                if (_mx > 0) {
                    static int _lf=0; if(_lf++ < 12) cbrEvent("LANDSCAPE-LOCK setFrame: %s %.0fx%.0f -> %.0fx%.0f", object_getClassName(self), frame.size.width, frame.size.height, _mx, _mn);
                    frame.size.width = _mx; frame.size.height = _mn;
                }
            }
        } @catch(...) {}
    }
    %orig(frame);
}
%end
%hook UIViewController
- (NSUInteger)supportedInterfaceOrientations {
    if (gCBROrientOverride > 0) {
        if (!gCBRVCFired) { gCBRVCFired = 1; CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.appside.vc-orient-fired"), NULL, NULL, YES); }
        return (NSUInteger)(1UL<<3);   // v3.43.0: LandscapeRight only
    }
    return %orig;
}
- (NSUInteger)__supportedInterfaceOrientations {
    if (gCBROrientOverride > 0) return (NSUInteger)(1UL<<3);   // v3.43.0: LandscapeRight only
    return %orig;
}
// v3.53.0: hide the iOS home-indicator pill on the hosted app (Colin: remove the home bar from
// the dash). Only while armed, so a genuine phone-foreground app is untouched.
- (BOOL)prefersHomeIndicatorAutoHidden {
    if (gCBROrientOverride > 0) return YES;
    return %orig;
}
// v3.56.0: also hook the PRIVATE resolved variant. Per the CarBridge RE doc, apps override the
// PUBLIC prefersHomeIndicatorAutoHidden (Amazon/Netflix/Reddit) so the base public hook loses, but
// they rarely override the private resolved getter - hooking it catches them (same reason CarBridge
// hooks __supportedInterfaceOrientations, not just the public method).
- (BOOL)_preferredHomeIndicatorAutoHidden {
    if (gCBROrientOverride > 0) return YES;
    return %orig;
}
%end
// v3.49.0 GEO-REWRITE (see patch header).
%hook UIWindowScene
- (void)requestGeometryUpdateWithPreferences:(id)prefs errorHandler:(id)handler {
    @try {
        if (gCBROrientOverride > 0 && prefs && [prefs respondsToSelector:sel_registerName("interfaceOrientations")]) {
            NSUInteger _m = ((NSUInteger(*)(id,SEL))objc_msgSend)(prefs, sel_registerName("interfaceOrientations"));
            @try { char _o3[64]; snprintf(_o3,sizeof(_o3),"GEO-req mask=0x%lx",(unsigned long)_m); cbrOrient3(_o3, 1); } @catch(...) {}   // v3.53.0: the fullscreen-exit re-break moment
            if (_m != 0 && (_m & (NSUInteger)(1UL<<3)) == 0) {
                static int _gr = 0; if (_gr++ < 12) cbrEvent("GEO-REWRITE app asked mask=0x%lx -> 0x8 LandscapeRight on %s", (unsigned long)_m, object_getClassName(self));
                if ([prefs respondsToSelector:sel_registerName("setInterfaceOrientations:")])
                    ((void(*)(id,SEL,NSUInteger))objc_msgSend)(prefs, sel_registerName("setInterfaceOrientations:"), (NSUInteger)(1UL<<3));
            }
        }
    } @catch(...) {}
    %orig(prefs, handler);
}
%end
%hook UIDevice
- (NSInteger)orientation {
    if (gCBROrientOverride > 0) return 3;
    return %orig;
}
%end
// v3.24.5: YouTube's ROOT vc overrides supportedInterfaceOrientations with 0x2 (portrait), which
// bypasses our base-UIViewController hook (that's the supp=0x2 in every log) and makes iOS veto the
// landscape geometry request (BSActionErrorDomain err 1). Hook the concrete class directly so it
// reports landscape while hosted: the decision reads landscape AND requestGeometryUpdate is accepted.
%hook YTAppViewControllerImpl
- (NSUInteger)supportedInterfaceOrientations {
    if (gCBROrientOverride > 0) return (NSUInteger)(1UL<<3);   // v3.43.0: LandscapeRight only
    return %orig;
}
- (NSUInteger)__supportedInterfaceOrientations {
    if (gCBROrientOverride > 0) return (NSUInteger)(1UL<<3);   // v3.43.0: LandscapeRight only
    return %orig;
}
%end
%end

%ctor {
    // PURE C — no ObjC whatsoever
    // v3.20.47: UNCONDITIONAL beacon - log the progname of EVERY process we inject into.
    // Definitively shows whether the dylib reaches YouTube + what its real progname is.
    // v3.20.47: reliable YouTube detection - check bundle id via the main bundle path, not progname.
    // If the executable path contains "youtube" (case-insensitive) we treat it as YouTube.
    int _isYT = 0;
    @try {
        char _xp[1024]; uint32_t _xs = sizeof(_xp);
        extern int _NSGetExecutablePath(char*, uint32_t*);
        if (_NSGetExecutablePath(_xp, &_xs) == 0) {
            for (char *_c = _xp; *_c; _c++) { if ((_c[0]=='y'||_c[0]=='Y') && (strncasecmp(_c,"youtube",7)==0)) { _isYT = 1; break; } }
            int _bf2 = open("/var/mobile/CBR_injected_procs.txt", O_WRONLY|O_CREAT|O_APPEND, 0666);
            if (_bf2 >= 0) { char _bb2[1200]; int _bn2 = snprintf(_bb2, sizeof(_bb2), "  execpath=[%s] isYT=%d\n", _xp, _isYT); write(_bf2, _bb2, _bn2); close(_bf2); }
        }
    } @catch(...) {}

    if (strcmp(__progname, "CarPlay") == 0) {
        unlink("/var/mobile/CBR_live.txt");
        gLogFD = open("/var/mobile/CBR_live.txt", O_WRONLY|O_CREAT|O_TRUNC, 0666);
        %init(CARPLAY);
        // v3.57.0 DISCONNECT PROBE: the screenshot phantom needs teardown on CarPlay disconnect, and
        // UIScreenDidDisconnect never fired in SpringBoard. Observe the likely signals in the CarPlay
        // process + log which fires on unplug (CBR_disconnect_probe.txt).
        @try {
            unlink("/var/mobile/CBR_disconnect_probe.txt");
            id _dc = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSNotificationCenter"), sel_registerName("defaultCenter"));
            NSArray *_dnames = @[@"UIScreenDidDisconnectNotification", @"UISceneDidDisconnectNotification", @"UISceneWillDeactivateNotification", @"UIApplicationDidEnterBackgroundNotification", @"UIApplicationWillResignActiveNotification"];
            for (NSString *_dn in _dnames) {
                NSString *_dncap = _dn;
                void (^_dblk)(id) = ^(id note){
                    @try { int _f=open("/var/mobile/CBR_disconnect_probe.txt",O_WRONLY|O_CREAT|O_APPEND,0644); if(_f>=0){ char _b[200]; int _n=snprintf(_b,sizeof(_b),"[DISCONNECT-PROBE] fired: %s\n", [_dncap UTF8String]); if(_n>0)write(_f,_b,(size_t)_n); close(_f);} } @catch(...) {}
                };
                ((id(*)(id,SEL,id,id,id,void(^)(id)))objc_msgSend)(_dc, sel_registerName("addObserverForName:object:queue:usingBlock:"), _dn, nil, nil, _dblk);
            }
        } @catch(...) {}
        // v3.29.0: start the CarPlay-side rotation probe (the one process never instrumented).
        unlink("/var/mobile/CBR_cp_rotation.txt");
        cbrCPRotationSchedule();
        { int hf = open("/var/mobile/CBR_cp_hooks.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);
          cbrLogHook(hf, "DashBoard", '+', "_newApplicationLibrary");
          cbrLogHook(hf, "DBEnvironmentConfiguration", '-', "policyForApplicationInfo:");
          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", '-', "effectivePolicyForAppDeclaration:");
          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", '-', "effectivePolicyForAppDeclaration:inVehicleWithCertificateSerial:");
          cbrLogHook(hf, "DBDashboardHomeViewController", '-', "_setupIconModel");
          cbrLogHook(hf, "DBApplicationLaunchInfo", '+', "launchInfoForApplication:withActivationSettings:");
          cbrLogHook(hf, "DBIconView", '-', "didMoveToWindow");
          if (hf >= 0) close(hf); }
        const char msg[] = "[CBR] v3.26.5 init - v77 baseline + PORTRAIT window pin (upright dash)";
        write(gLogFD, msg, sizeof(msg)-1);
        write(2, msg, sizeof(msg)-1);
    }
    // v3.39.0 THE ROOT CAUSE: the app-side branch was gated on _isYT (executable path contains
    // "youtube"), so %init(APPS) ran ONLY in YouTube. YouTube TV (executable is Unplugged, not
    // "youtube"), Reddit, Netflix, Amazon all got _isYT=0 and NEVER initialized ANY app-side hooks -
    // no probe, no orientation swizzle, no makeKeyAndVisible fix; gCBROrientOverride stayed -1. The
    // injected-process log proves it: only YouTube's container has any CBR app log. Every orientation
    // fix executed in exactly one app. Gate instead on "is a normal app" (not a known system process).
    // Safe for non-hosted apps: the override stays -1 until the host posts com.cbr.orient.landscape.
    else if (strcmp(__progname, "SpringBoard") != 0 && strcmp(__progname, "CarPlay") != 0
             && strcmp(__progname, "Spotlight") != 0 && strcmp(__progname, "Preferences") != 0
             && strncmp(__progname, "Widget", 6) != 0 && strncmp(__progname, "assistantd", 10) != 0
             && strncmp(__progname, "backboardd", 10) != 0 && strncmp(__progname, "iCleaner", 8) != 0) {
        %init(APPS);
        cbrProbeSchedule();
        { int _bf = open("/var/mobile/CBR_injected_procs.txt", O_WRONLY|O_CREAT|O_APPEND, 0666);
          if (_bf >= 0) { char _b[256]; int _n = snprintf(_b,sizeof(_b),"  APPS-INIT progname=[%s]\n", __progname); if(_n>0) write(_bf,_b,(size_t)_n); close(_bf); } }
        @try { NSString *ep=[NSTemporaryDirectory() stringByAppendingPathComponent:@"CBR_events.txt"]; [[NSFileManager defaultManager] removeItemAtPath:ep error:nil]; } @catch(...) {}
        // v3.20.78: GATED - stay -1 until hosted (keeps the phone keyboard fix).
        gCBROrientOverride = -1;
        // v3.42.0 SYNC GATE. The old flow - app posts 'loaded', SB replies with the landscape note,
        // override becomes 3 - is a round trip that RACES app launch: UIKit resolves the first
        // orientation (and the first surface commit) before the reply lands, override is still -1,
        // the swizzle returns the app's REAL portrait mask, and the surface is born portrait =
        // sideways. The manual tap always fixed it because by tap-time the override was long since 3
        // and the foreground transition re-ran orientation resolution against the landscape-only
        // mask. Read the host state SYNCHRONOUSLY here instead - no round trip, set before
        // UIApplicationMain, so the very FIRST resolution sees landscape-only.
        @try {
            // v3.45.0: own-bundle-id hash, so only the app actually hosted flips landscape.
            @try {
                id _mb = ((id(*)(Class,SEL))objc_msgSend)(objc_getClass("NSBundle"), sel_registerName("mainBundle"));
                id _bo = _mb ? ((id(*)(id,SEL))objc_msgSend)(_mb, sel_registerName("bundleIdentifier")) : nil;
                const char *_bc = _bo ? ((const char*(*)(id,SEL))objc_msgSend)(_bo, sel_registerName("UTF8String")) : NULL;
                gCBROwnBidHash = cbrBidHash(_bc);
                cbrEvent("SYNC-GATE ownBid=[%s]", _bc ? _bc : "(nil)");   // v3.52.0: log the string so a CP/app bid mismatch is visible
            } @catch(...) {}
            uint64_t _st = cbrReadHostState();
            if (_st != 0 && _st == gCBROwnBidHash) gCBROrientOverride = 3;
            cbrEvent("SYNC-GATE state=%llu ownHash=%llu override=%d", (unsigned long long)_st, (unsigned long long)gCBROwnBidHash, gCBROrientOverride);
            // v3.43.0: if we already read "hosting" synchronously, start the carplay-cast
            // keyWindow kick chain too (it self-guards on keyWindow existing yet).
            if (gCBROrientOverride == 3) cbrAppKickLandscape(0);
        } @catch(...) {}
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, cbrAppOrientCallback, CFSTR("com.cbr.orient.landscape"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, cbrAppOrientCallback, CFSTR("com.cbr.orient.unlock"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterPostNotification(CFNotificationCenterGetDarwinNotifyCenter(), CFSTR("com.cbr.appside.loaded"), NULL, NULL, YES);
    }
    else if (strcmp(__progname, "SpringBoard") == 0) {
        %init(SPRINGBOARD);
        cbrSBRegisterListener();
        // v3.42.0: clear stale host state after a respring (otherwise every app launched on the
        // phone would read state=3 and go landscape-only).
        @try {
            if (!gCBRHostStateToken) notify_register_check("com.cbr.orient.landscape", &gCBRHostStateToken);
            if (gCBRHostStateToken) notify_set_state(gCBRHostStateToken, 0);
        } @catch(...) {}
        unlink("/var/mobile/CBR_appside_sb.txt");
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, cbrSBAppsideCallback, CFSTR("com.cbr.appside.loaded"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        CFNotificationCenterAddObserver(CFNotificationCenterGetDarwinNotifyCenter(), NULL, cbrSBAppsideCallback, CFSTR("com.cbr.appside.vc-orient-fired"), NULL, CFNotificationSuspensionBehaviorDeliverImmediately);
        unlink("/var/mobile/CBR_keepalive.txt");
        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);
        if(_sf>=0){const char*m="[CBR-SB] v3.26.5 init - v77 baseline + PORTRAIT window pin (upright dash)";write(_sf,m,strlen(m));
            cbrLogHook(_sf, "FBScene", '-', "updateSettings:withTransitionContext:completion:");
            cbrLogHook(_sf, "FBSceneManager", '-', "createSceneWithDefinition:initialParameters:");
            cbrLogHook(_sf, "SBSuspendedUnderLockManager", '-', "_shouldBeBackgroundUnderLockForScene:withSettings:");
            close(_sf);}
    }
}

#pragma clang diagnostic pop
