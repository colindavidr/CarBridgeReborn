/*
 * CarBridgeReborn — Settings controller (v3.11.1)
 *
 * v3.11.0 loaded the panel but crashed on tap: our arm64e code called
 * +[PSSpecifier preferenceSpecifierNamed:...] and hit a PAC auth fault
 * (0xdac1...). This version stops constructing PSSpecifiers in our code and
 * instead asks Preferences to parse a Root.plist (generated on-device by the
 * postinst via uicache). Preferences builds the specifiers in its own code, so
 * the only call we make is the simple loadSpecifiersFromPlistName:.
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

@interface PSListController : UIViewController
- (id)specifiers;
- (NSArray *)loadSpecifiersFromPlistName:(NSString *)plistName target:(id)target;
@end

%subclass CBRPrefsController : PSListController

- (id)navigationTitle { return @"CarBridge Reborn"; }

- (id)specifiers {
    PLog("[prefs] specifiers called");
    @try {
        NSArray *specs = [(PSListController *)self loadSpecifiersFromPlistName:@"Root" target:self];
        char buf[64];
        snprintf(buf, sizeof(buf), "[prefs] loaded %lu specifiers from Root.plist",
                 (unsigned long)(specs ? specs.count : 0));
        PLog(buf);
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
