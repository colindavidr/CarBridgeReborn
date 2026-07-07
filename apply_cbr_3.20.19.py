#!/usr/bin/env python3
# v3.20.19 — purely-additive diagnostic: at init, check every hooked class+selector
# against the live runtime and log whether it RESOLVED on this device. No behavior change.
import sys
p="src/Tweak.xm"; s=open(p,encoding="utf-8").read()
if "cbrLogHook" in s: sys.exit("ALREADY PATCHED")
def repl(old,new,label):
    global s
    if old not in s: sys.exit(f"FAIL anchor: {label}")
    s=s.replace(old,new,1)

# 1) resolution-logging helper, inserted right before %ctor
helper = (
'// v3.20.19: report whether each hooked class+selector actually resolves on THIS\n'
'// device (answers "are we blind-hooking on iOS 17?"). Pure C + runtime lookups.\n'
'static void cbrLogHook(int fd, const char *clsName, char kind, const char *selName) {\n'
'    Class c = objc_getClass(clsName);\n'
'    int hasCls = (c != NULL);\n'
'    int hasMethod = 0;\n'
'    if (c && selName && selName[0]) {\n'
'        SEL sel = sel_registerName(selName);\n'
'        Method m = (kind == \'+\') ? class_getClassMethod(c, sel) : class_getInstanceMethod(c, sel);\n'
'        hasMethod = (m != NULL);\n'
'    }\n'
'    int resolved = hasCls && hasMethod;\n'
'    char buf[360];\n'
'    int n = snprintf(buf, sizeof(buf), "[hook] %-30s %c%-50s class=%-3s method=%-3s => %s\\n",\n'
'                     clsName, kind, selName,\n'
'                     hasCls ? "YES" : "NO", hasMethod ? "YES" : "NO",\n'
'                     resolved ? "RESOLVED" : "** MISSING **");\n'
'    if (fd >= 0 && n > 0) write(fd, buf, (size_t)n);\n'
'}\n\n'
'%ctor {\n'
'    // PURE C — no ObjC whatsoever')
repl('%ctor {\n    // PURE C — no ObjC whatsoever', helper, "helper+ctor")

# 2) CARPLAY hook resolution log, after %init(CARPLAY)
repl('        %init(CARPLAY);\n',
'        %init(CARPLAY);\n'
'        { int hf = open("/var/mobile/CBR_cp_hooks.txt", O_WRONLY|O_CREAT|O_TRUNC, 0644);\n'
'          cbrLogHook(hf, "DashBoard", \'+\', "_newApplicationLibrary");\n'
'          cbrLogHook(hf, "DBEnvironmentConfiguration", \'-\', "policyForApplicationInfo:");\n'
'          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", \'-\', "effectivePolicyForAppDeclaration:");\n'
'          cbrLogHook(hf, "CRCarPlayAppPolicyEvaluator", \'-\', "effectivePolicyForAppDeclaration:inVehicleWithCertificateSerial:");\n'
'          cbrLogHook(hf, "DBDashboardHomeViewController", \'-\', "_setupIconModel");\n'
'          cbrLogHook(hf, "DBApplicationLaunchInfo", \'+\', "launchInfoForApplication:withActivationSettings:");\n'
'          cbrLogHook(hf, "DBIconView", \'-\', "didMoveToWindow");\n'
'          if (hf >= 0) close(hf); }\n',
"carplay hooklog")

# 3) SpringBoard hook resolution log (replace the init block)
repl('        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);\n'
     '        if(_sf>=0){const char*m="[CBR-SB] v3.20.18 init - keep-alive hooks active\\n";write(_sf,m,strlen(m));close(_sf);}',
     '        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);\n'
     '        if(_sf>=0){const char*m="[CBR-SB] v3.20.19 init - hook resolution check:\\n";write(_sf,m,strlen(m));\n'
     '            cbrLogHook(_sf, "FBScene", \'-\', "updateSettings:withTransitionContext:completion:");\n'
     '            cbrLogHook(_sf, "SBSuspendedUnderLockManager", \'-\', "_shouldBeBackgroundUnderLockForScene:withSettings:");\n'
     '            close(_sf);}',
     "springboard hooklog")

# 4) version string bump
repl('"[CBR] v3.20.18 init - keep-alive hooks (FBScene+lock) prevent scene backgrounding\\n"',
     '"[CBR] v3.20.19 init - keep-alive + hook-resolution logging\\n"',
     "version string")

open(p,"w",encoding="utf-8").write(s)
print("OK: v3.20.19 applied")
