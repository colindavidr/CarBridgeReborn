/*
 * CarBridgeReborn — Settings controller (v3.11.8)
 *
 * v3.11.7 built 96 specifiers but the table rendered blank. Cause: when you
 * override -specifiers, PSListController's table data source reads the rows
 * from its internal _specifiers ivar — NOT from your return value. The stock
 * pattern (_specifiers = [self loadSpecifiers...]) assigns that ivar; ours
 * returned the array without setting it, and loadSpecifiersFromPlistName does
 * not populate the ivar on iOS 17, so the table saw 0 rows. Fix: write the
 * built specifiers into _specifiers via the runtime. Also logs PSListController's
 * ivar names once, so if the ivar isn't literally "_specifiers" we see the real
 * name and correct it.
 */
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <fcntl.h>
#import <unistd.h>
#import <string.h>

static void PLog(const char *m) {
    int fd = open("/var/mobile/CBR_prefs_live.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);
    if (fd >= 0) { write(fd, m, strlen(m)); write(fd, "\n", 1); close(fd); }
}

#define BUNDLE_PATH     @"/var/jb/Library/PreferenceBundles/CarBridgeRebornPrefs.bundle"
#define ROOT_PLIST_PATH @"/var/jb/Library/PreferenceBundles/CarBridgeRebornPrefs.bundle/Root.plist"
#define CBR_PSSwitchCell 6

@interface PSSpecifier : NSObject
+ (id)groupSpecifierWithName:(NSString *)name;
+ (id)preferenceSpecifierNamed:(NSString *)name target:(id)target set:(SEL)set get:(SEL)get detail:(Class)detail cell:(NSInteger)cell edit:(Class)edit;
- (void)setProperty:(id)value forKey:(NSString *)key;
- (id)propertyForKey:(NSString *)key;
@end

@interface PSListController : UIViewController
- (id)specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)plistName target:(id)target;
- (NSBundle *)bundle;
@end

// C helper (fallback) so nothing messages the forward-declared %subclass self
static NSMutableArray *cbrBuildManually(id target) {
    NSMutableArray *out = [NSMutableArray array];
    @try {
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:ROOT_PLIST_PATH];
        NSArray *items = plist[@"items"];
        for (NSDictionary *item in items) {
            NSString *cell = item[@"cell"];
            if ([cell isEqualToString:@"PSGroupCell"]) {
                PSSpecifier *g = [%c(PSSpecifier) groupSpecifierWithName:(item[@"label"] ?: @"")];
                if (item[@"footerText"]) [g setProperty:item[@"footerText"] forKey:@"footerText"];
                [out addObject:g];
            } else if ([cell isEqualToString:@"PSSwitchCell"]) {
                PSSpecifier *s = [%c(PSSpecifier) preferenceSpecifierNamed:(item[@"label"] ?: @"")
                                    target:target
                                       set:@selector(setPreferenceValue:specifier:)
                                       get:@selector(readPreferenceValue:)
                                    detail:nil cell:CBR_PSSwitchCell edit:nil];
                if (item[@"key"])      [s setProperty:item[@"key"]      forKey:@"key"];
                if (item[@"defaults"]) [s setProperty:item[@"defaults"] forKey:@"defaults"];
                if (item[@"default"])  [s setProperty:item[@"default"]  forKey:@"default"];
                [out addObject:s];
            }
        }
    } @catch (NSException *e) {
        PLog("[prefs] manual-build EXCEPTION:");
        PLog([[e description] UTF8String] ?: "(no description)");
    }
    return out;
}

%subclass CBRPrefsController : PSListController

- (id)navigationTitle { return @"CarBridge Reborn"; }

- (NSBundle *)bundle {
    NSBundle *b = [NSBundle bundleWithPath:BUNDLE_PATH];
    return b ?: %orig;
}

- (id)readPreferenceValue:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    NSString *domain = [specifier propertyForKey:@"defaults"] ?: @"com.carbridgereborn";
    if (!key) return @NO;
    CFPropertyListRef v = CFPreferencesCopyAppValue((__bridge CFStringRef)key,
                                                    (__bridge CFStringRef)domain);
    id val = v ? (__bridge_transfer id)v : nil;
    if (val == nil) {
        id def = [specifier propertyForKey:@"default"];
        return def ?: @NO;
    }
    return val;
}

- (void)setPreferenceValue:(id)value specifier:(PSSpecifier *)specifier {
    NSString *key = [specifier propertyForKey:@"key"];
    NSString *domain = [specifier propertyForKey:@"defaults"] ?: @"com.carbridgereborn";
    if (!key) return;
    CFPreferencesSetAppValue((__bridge CFStringRef)key,
                             (__bridge CFPropertyListRef)value,
                             (__bridge CFStringRef)domain);
    CFPreferencesAppSynchronize((__bridge CFStringRef)domain);
}

- (id)specifiers {
    PLog("[prefs] specifiers called (v3.11.8 ivar-cache)");
    Class pslc = %c(PSListController);

    static BOOL logged = NO;
    if (!logged) {
        logged = YES;
        unsigned int n = 0;
        Ivar *ivars = class_copyIvarList(pslc, &n);
        char hdr[80];
        snprintf(hdr, sizeof(hdr), "[prefs] PSListController ivars (%u):", n);
        PLog(hdr);
        for (unsigned int i = 0; i < n; i++) {
            const char *nm = ivar_getName(ivars[i]);
            if (nm) {
                char b[160];
                snprintf(b, sizeof(b), "[prefs]   %s", nm);
                PLog(b);
            }
        }
        if (ivars) free(ivars);
    }

    @try {
        NSArray *specs = [(PSListController *)self loadSpecifiersFromPlistName:@"Root" target:self];
        char buf[96];
        snprintf(buf, sizeof(buf), "[prefs] loaded -> %lu",
                 (unsigned long)(specs ? specs.count : 0));
        PLog(buf);

        if (!specs || specs.count == 0) {
            PLog("[prefs] loader gave 0 — building manually");
            specs = cbrBuildManually(self);
            snprintf(buf, sizeof(buf), "[prefs] manual -> %lu", (unsigned long)specs.count);
            PLog(buf);
        }

        // Populate the framework's _specifiers ivar so the table shows the rows.
        Ivar iv = class_getInstanceVariable(pslc, "_specifiers");
        if (iv && specs) {
            object_setIvar(self, iv, specs);
            objc_setAssociatedObject(self, "cbrSpecs", specs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            PLog("[prefs] _specifiers ivar set");
        } else {
            PLog("[prefs] _specifiers ivar NOT found — check ivar list above");
        }
        return specs;
    } @catch (NSException *e) {
        PLog("[prefs] EXCEPTION in specifiers:");
        PLog([[e description] UTF8String] ?: "(no description)");
        return @[];
    }
}

%end

%ctor {
    PLog("[prefs] ctor; registering CBRPrefsController");
    %init;
    PLog("[prefs] %init complete");
}
