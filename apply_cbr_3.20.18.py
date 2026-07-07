#!/usr/bin/env python3
# v3.20.18 — port carplay-cast's keep-alive hooks so the hosted app's scene isn't
# suspended when it leaves the phone's foreground (fixes the brief-death). Adds a
# SpringBoard hook group (CBR had none), a keep-alive set, and removes the 30s auto-dismiss.
import sys
p="src/Tweak.xm"; s=open(p,encoding="utf-8").read()
if "gCBRKeepAlive" in s: sys.exit("ALREADY PATCHED")

def repl(old,new,label):
    global s
    if old not in s: sys.exit(f"FAIL anchor: {label}")
    s=s.replace(old,new,1)

# 1) keep-alive set global (after gCBRTxn)
repl('static id gCBRTxn = nil;         // v3.19.5: strong-hold txn for safe completion',
     'static id gCBRTxn = nil;         // v3.19.5: strong-hold txn for safe completion\n'
     'static NSMutableSet *gCBRKeepAlive = nil;  // v3.20.18: bundle IDs whose scenes must NOT be backgrounded while hosted on CarPlay',
     "keepalive global")

# 2) clear keep-alive in dismiss
repl('        gCBRRootWindow = nil; gCBRAppVC = nil; gCBRActiveTxns = nil;',
     '        gCBRRootWindow = nil; gCBRAppVC = nil; gCBRActiveTxns = nil;\n'
     '        @try { if (gCBRKeepAlive) [gCBRKeepAlive removeAllObjects]; } @catch(...) {}',
     "dismiss clear")

# 3) mark app keep-alive once we're committed to hosting (after application confirmed)
repl('        if (!application) { HH("no application -> abort\\n"); HH("==== END ====\\n"); if(fd>=0)close(fd); return; }',
     '        if (!application) { HH("no application -> abort\\n"); HH("==== END ====\\n"); if(fd>=0)close(fd); return; }\n'
     '        // v3.20.18: mark this app keep-alive so the FBScene/lock hooks refuse to\n'
     '        // background its scene while it is hosted on CarPlay (fixes the brief-death).\n'
     '        @try { if (!gCBRKeepAlive) gCBRKeepAlive = [[NSMutableSet alloc] init]; [gCBRKeepAlive addObject:bid]; HH("marked keep-alive\\n"); } @catch(...) {}',
     "mark keepalive")

# 4) remove the hardcoded 30s auto-dismiss (it killed the render at 30s)
repl('        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBHostDismiss(); });',
     '        // v3.20.18: removed the hardcoded 30s auto-dismiss - the keep-alive hooks hold\n'
     '        // the scene now, so let it render until CarPlay disconnects instead of timing out.\n'
     '        // dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(30*NSEC_PER_SEC)), dispatch_get_main_queue(), ^{ cbrSBHostDismiss(); });',
     "remove 30s dismiss")

# 5) add the SPRINGBOARD hook group before %ctor
group = r'''%group SPRINGBOARD
// v3.20.18: keep-alive hooks ported from carplay-cast (EthanArbuckle/carplay-cast).
// While an app is hosted on CarPlay, SpringBoard's normal lifecycle would suspend it the
// moment it is no longer the main-screen foreground app, killing the render. These hooks
// refuse to background any scene whose app is in gCBRKeepAlive.
%hook FBScene
- (void)updateSettings:(id)arg1 withTransitionContext:(id)arg2 completion:(void *)arg3 {
    @try {
        if (gCBRKeepAlive && [gCBRKeepAlive count]) {
            id client = ((id(*)(id,SEL))objc_msgSend)(self, sel_registerName("client"));
            if (client && [client respondsToSelector:sel_registerName("process")]) {
                id proc = ((id(*)(id,SEL))objc_msgSend)(client, sel_registerName("process"));
                id bid = proc ? ((id(*)(id,SEL))objc_msgSend)(proc, sel_registerName("bundleIdentifier")) : nil;
                if (bid && [gCBRKeepAlive containsObject:bid]) {
                    BOOL isFg = ((BOOL(*)(id,SEL))objc_msgSend)(arg1, sel_registerName("isForeground"));
                    if (!isFg) { return; }   // block the background transition -> keep it live on CarPlay
                }
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
            id client = ((id(*)(id,SEL))objc_msgSend)(arg2, sel_registerName("client"));
            id proc = client ? ((id(*)(id,SEL))objc_msgSend)(client, sel_registerName("process")) : nil;
            id bid = proc ? ((id(*)(id,SEL))objc_msgSend)(proc, sel_registerName("bundleIdentifier")) : nil;
            if (bid && [gCBRKeepAlive containsObject:bid]) shouldBackground = NO;
        }
    } @catch(...) {}
    return shouldBackground;
}
%end
%end  // group SPRINGBOARD

%ctor {
    // PURE C — no ObjC whatsoever'''
repl('%ctor {\n    // PURE C — no ObjC whatsoever', group, "SPRINGBOARD group")

# 6) %init(SPRINGBOARD) + a SB-side init log so we can confirm the hooks loaded
repl('    else if (strcmp(__progname, "SpringBoard") == 0) {\n        cbrSBRegisterListener();\n    }',
     '    else if (strcmp(__progname, "SpringBoard") == 0) {\n'
     '        %init(SPRINGBOARD);\n'
     '        cbrSBRegisterListener();\n'
     '        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);\n'
     '        if(_sf>=0){const char*m="[CBR-SB] v3.20.18 init - keep-alive hooks active\\n";write(_sf,m,strlen(m));close(_sf);}\n'
     '    }',
     "SPRINGBOARD init")

# 7) version string bump (str.replace - NOT re.sub)
repl('"[CBR] v3.20.17 init - grafting host only (PATH-A reverted, load runaway fix)\\n"',
     '"[CBR] v3.20.18 init - keep-alive hooks (FBScene+lock) prevent scene backgrounding\\n"',
     "version string")

open(p,"w",encoding="utf-8").write(s)
print("OK: v3.20.18 applied")
