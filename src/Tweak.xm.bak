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

// ─── Saved library — void* to avoid ANY ARC at store time ────────────────────
static void *gLibraryPtr = NULL;

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
    // Bridge an app onto the CarPlay dashboard iff its Settings toggle is ON.
    // The panel's PSSwitchCells persist to the com.carbridgereborn domain;
    // CFPreferencesCopyAppValue searches both host scopes so the read matches
    // however Settings wrote it. Default NO (user opts apps in via the panel).
    NSString *bid = [NSString stringWithUTF8String:bid_cstr];
    CFPropertyListRef v = CFPreferencesCopyAppValue((__bridge CFStringRef)bid,
                                                    CFSTR("com.carbridgereborn"));
    BOOL on = NO;
    if (v) {
        if (CFGetTypeID(v)==CFBooleanGetTypeID()) on = CFBooleanGetValue((CFBooleanRef)v);
        CFRelease(v);
    }
    return on;
}

// CarPlay app-policy "allowed" enum value. iOS typically uses 1 == allowed.
// Adjustable at runtime via prefs key "PolicyAllowValue" once we confirm from logs.
static long CBAllowedPolicyValue(void) {
    NSUserDefaults *defs = [[NSUserDefaults alloc] initWithSuiteName:@"com.carbridgereborn"];
    id v = [defs objectForKey:@"PolicyAllowValue"];
    return v ? [v longValue] : 1;
}

static void addCarplayDeclarations(id lib) {
    if (!lib) { CBLog("[CBR] addDeclarations: lib nil"); return; }

    Class declClass = objc_getClass("CRCarPlayAppDeclaration");
    if (!declClass) { CBLog("[CBR] CRCarPlayAppDeclaration not found"); return; }

    NSArray *apps = cb(lib, "allInstalledApplications");
    if (!apps) { CBLog("[CBR] allInstalledApplications nil"); return; }

    char msg[80];
    snprintf(msg, sizeof(msg), "[CBR] Library has %lu apps", (unsigned long)[apps count]);
    CBLog(msg);

    NSUInteger injected = 0;
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
            cb1b(decl, "setSupportsMaps:", YES);        // YES = 1
            cb1(decl, "setBundleIdentifier:", bidObj);
            id bundleURL = cb(appInfo, "bundleURL");
            if (bundleURL) cb1(decl, "setBundlePath:", bundleURL);

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


// ── Entitlement bypass: make non-CarPlay apps "allowed" on the dashboard ──────
// Normally CarPlay only shows apps with a CarPlay entitlement. The official
// CarBridge hooks this evaluator to force-allow bridged apps. We log every
// evaluation so we can confirm the iOS 17 enum values from a real device.
%hook CRCarPlayAppPolicyEvaluator

- (long)effectivePolicyForAppDeclaration:(id)declaration {
    long orig = %orig;
    @try {
        id bidObj = cb(declaration, "bundleIdentifier");
        if (bidObj) {
            const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                sel_registerName("UTF8String"));
            if (bid) {
                CBLogFmt("[CBR] policy(%s) orig=%ld", bid, orig);
                if (CBIsEnabled(bid)) {
                    long allow = CBAllowedPolicyValue();
                    CBLogFmt("[CBR]   -> forcing policy=%ld for %s", allow, bid);
                    return allow;
                }
            }
        }
    } @catch(...) {}
    return orig;
}

- (long)effectivePolicyForAppDeclaration:(id)declaration inVehicleWithCertificateSerial:(id)serial {
    long orig = %orig;
    @try {
        id bidObj = cb(declaration, "bundleIdentifier");
        if (bidObj) {
            const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
                sel_registerName("UTF8String"));
            if (bid && CBIsEnabled(bid)) {
                long allow = CBAllowedPolicyValue();
                CBLogFmt("[CBR] policy2(%s) orig=%ld -> %ld", bid, orig, allow);
                return allow;
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
    @try {
        // Check for our tag using C string comparison
        NSArray *tags = cb(appInfo, "tags");
        if (!tags) tags = getIvar(appInfo, "_tags");

        BOOL isOurs = NO;
        for (id tag in tags) {
            const char *t = ((const char*(*)(id,SEL))objc_msgSend)(tag,
                sel_registerName("UTF8String"));
            if (t && strcmp(t, "CarPlayEnable") == 0) { isOurs = YES; break; }
        }
        if (!isOurs) return %orig;

        id bidObj = cb(appInfo, "bundleIdentifier");
        if (!bidObj) return %orig;
        const char *bid = ((const char*(*)(id,SEL))objc_msgSend)(bidObj,
            sel_registerName("UTF8String"));
        CBLogFmt("[CBR] Tapped bridged app: %s", bid ?: "?");
        CBOpenApp(bid);
        return nil;
    } @catch(...) { return %orig; }
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
        const char msg[] = "[CBR] v3.6.1 init — NSUserDefaults prefs + Settings UI\n";
        write(gLogFD, msg, sizeof(msg)-1);
        write(2, msg, sizeof(msg)-1);
    }
}

#pragma clang diagnostic pop
