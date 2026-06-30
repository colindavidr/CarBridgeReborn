/*
 * CarBridgeReborn — Settings controller (v3.11.4)
 *
 * loadSpecifiersFromPlistName: relies on [self bundle], which resolves wrong
 * under a Logos %subclass and returned 0 specifiers. Fix: read Root.plist from
 * its absolute path and build specifiers with the PSSpecifier parser directly,
 * so bundle resolution is never involved.
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

#define ROOT_PLIST_PATH @"/var/jb/Library/PreferenceBundles/CarBridgeRebornPrefs.bundle/Root.plist"

@interface PSSpecifier : NSObject
+ (NSArray *)specifiersFromPlist:(NSDictionary *)plist
                          source:(id)source
        title:(NSString *)title
   defaultsKey:(NSString *)defaults
    notifyKey:(NSString *)notify
         isBaseSettings:(BOOL)base
   excludeFromSettingsLibrary:(BOOL)exclude
                          target:(id)target;
@end

@interface PSListController : UIViewController
- (id)specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)plistName target:(id)target;
@end

%subclass CBRPrefsController : PSListController

- (id)navigationTitle { return @"CarBridge Reborn"; }

- (id)specifiers {
    PLog("[prefs] specifiers called (v3.11.4 abs-path)");
    @try {
        NSDictionary *plist = [NSDictionary dictionaryWithContentsOfFile:ROOT_PLIST_PATH];
        if (!plist) { PLog("[prefs] Root.plist not found at abs path"); return @[]; }

        NSArray *specs = [%c(PSSpecifier) specifiersFromPlist:plist
                                                       source:self
                                                        title:@"CarBridge Reborn"
                                                   defaultsKey:@"com.carbridgereborn"
                                                    notifyKey:nil
                                               isBaseSettings:NO
                                   excludeFromSettingsLibrary:NO
                                                       target:self];
        char buf[80];
        snprintf(buf, sizeof(buf), "[prefs] built %lu specifiers from abs-path plist",
                 (unsigned long)(specs ? specs.count : 0));
        PLog(buf);

        // Fallback to the old path-resolution method if the parser returned nothing
        if (!specs || specs.count == 0) {
            PLog("[prefs] parser gave 0 — trying loadSpecifiersFromPlistName");
            specs = [(PSListController *)self loadSpecifiersFromPlistName:@"Root" target:self];
            snprintf(buf, sizeof(buf), "[prefs] fallback loaded %lu",
                     (unsigned long)(specs ? specs.count : 0));
            PLog(buf);
        }
        return specs ?: @[];
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
