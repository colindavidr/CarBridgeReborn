/*
 * CarBridgeReborn — Settings controller (v3.11.9)
 *
 * Panel renders (v3.11.8 set the _specifiers ivar). Polish:
 *  - Real display names via LSApplicationProxy (folder basename was showing
 *    "AlexaMobileiOS-prod" etc.); folder name stays as fallback.
 *  - App icons on the left via UIKit's private per-bundle-id icon API.
 * Header text is added to the plist by the generator (PSGroupCell label).
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
- (void)setName:(NSString *)name;
@end

@interface PSListController : UIViewController
- (id)specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)plistName target:(id)target;
- (NSBundle *)bundle;
@end

@interface LSApplicationProxy : NSObject
+ (instancetype)applicationProxyForIdentifier:(NSString *)identifier;
@property (nonatomic, readonly) NSString *localizedName;
@end

@interface UIImage (CBRPrivate)
+ (UIImage *)_applicationIconImageForBundleIdentifier:(NSString *)bid format:(int)fmt scale:(CGFloat)scale;
@end

static NSString *cbrDisplayName(NSString *bid) {
    @try {
        Class LSAP = %c(LSApplicationProxy);
        if (!LSAP) return nil;
        id proxy = [LSAP applicationProxyForIdentifier:bid];
        NSString *nm = [proxy localizedName];
        return (nm.length ? nm : nil);
    } @catch (NSException *e) { return nil; }
}

static UIImage *cbrIcon(NSString *bid) {
    @try {
        CGFloat scale = [UIScreen mainScreen].scale;
        if (scale < 1.0) scale = 2.0;
        return [%c(UIImage) _applicationIconImageForBundleIdentifier:bid format:2 scale:scale];
    } @catch (NSException *e) { return nil; }
}

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

static void cbrEnrich(NSArray *specs) {
    NSUInteger named = 0, iconed = 0;
    for (PSSpecifier *spec in specs) {
        NSString *bid = nil;
        @try { bid = [spec propertyForKey:@"key"]; } @catch (NSException *e) { bid = nil; }
        if (!bid.length) continue;
        NSString *nm = cbrDisplayName(bid);
        if (nm.length) {
            @try { [spec setName:nm]; } @catch (NSException *e) {}
            @try { [spec setProperty:nm forKey:@"label"]; } @catch (NSException *e) {}
            named++;
        }
        UIImage *ic = cbrIcon(bid);
        if (ic) {
            @try { [spec setProperty:ic forKey:@"iconImage"]; } @catch (NSException *e) {}
            iconed++;
        }
    }
    char b[96];
    snprintf(b, sizeof(b), "[prefs] enriched: %lu names, %lu icons",
             (unsigned long)named, (unsigned long)iconed);
    PLog(b);
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
    PLog("[prefs] specifiers called (v3.11.9 names+icons)");
    Class pslc = %c(PSListController);
    @try {
        NSArray *specs = [(PSListController *)self loadSpecifiersFromPlistName:@"Root" target:self];
        char buf[96];
        snprintf(buf, sizeof(buf), "[prefs] loaded -> %lu",
                 (unsigned long)(specs ? specs.count : 0));
        PLog(buf);

        if (!specs || specs.count == 0) {
            PLog("[prefs] loader gave 0 — building manually");
            specs = cbrBuildManually(self);
        }

        cbrEnrich(specs);

        Ivar iv = class_getInstanceVariable(pslc, "_specifiers");
        if (iv && specs) {
            object_setIvar(self, iv, specs);
            objc_setAssociatedObject(self, "cbrSpecs", specs, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
            PLog("[prefs] _specifiers ivar set");
        } else {
            PLog("[prefs] _specifiers ivar NOT found");
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
