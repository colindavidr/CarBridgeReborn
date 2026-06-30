/*
 * CarBridgeReborn — Settings controller (v3.11.6)
 *
 * Panel opens (ABI fixed) but lists 0 rows. Fixes:
 *  1. loadSpecifiersFromPlistName: finds Root.plist via [self bundle], which
 *     under a Logos %subclass doesn't resolve to our PreferenceBundle. Override
 *     -bundle to return our bundle explicitly.
 *  2. Manual fallback (ABI-safe now) builds specifiers directly from the plist
 *     at its absolute path, via a C helper to avoid %subclass self-typing.
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
@end

@interface PSListController : UIViewController
- (id)specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)plistName target:(id)target;
- (NSBundle *)bundle;
@end

// C helper so we don't message `self` (a forward-declared %subclass type)
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

- (id)specifiers {
    PLog("[prefs] specifiers called (v3.11.6 bundle-override)");
    @try {
        NSBundle *b = [(PSListController *)self bundle];
        char bb[320];
        snprintf(bb, sizeof(bb), "[prefs] [self bundle] -> %s",
                 b ? [[b bundlePath] UTF8String] : "(nil)");
        PLog(bb);

        NSArray *specs = [(PSListController *)self loadSpecifiersFromPlistName:@"Root" target:self];
        char buf[96];
        snprintf(buf, sizeof(buf), "[prefs] loadSpecifiersFromPlistName -> %lu",
                 (unsigned long)(specs ? specs.count : 0));
        PLog(buf);
        if (specs && specs.count > 0) return specs;

        PLog("[prefs] loader gave 0 — building manually");
        NSMutableArray *manual = cbrBuildManually(self);
        snprintf(buf, sizeof(buf), "[prefs] manual build -> %lu", (unsigned long)manual.count);
        PLog(buf);
        return manual;
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
