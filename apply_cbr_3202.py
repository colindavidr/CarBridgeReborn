#!/usr/bin/env python3
# CarBridgeReborn v3.20.2 — declaration lifetime fix (stops the CarPlayApp crash-loop).
# Idempotent: safe to run once. Anchored to v3.20.1 source.
import sys, re

p = "src/Tweak.xm"
s = open(p, encoding="utf-8").read()

if "gCBRDeclarations" in s:
    sys.exit("ALREADY PATCHED (gCBRDeclarations present). `git checkout -- src/Tweak.xm` to redo.")

# --- Edit 1: strong-storage + assoc-key globals before addCarplayDeclarations ---
anchor1 = ('static void addCarplayDeclarations(id lib) {\n'
           '    if (!lib) { CBLog("[CBR] addDeclarations: lib nil"); return; }')
assert anchor1 in s, "FAIL: addCarplayDeclarations anchor not found"
globals_block = (
'// v3.20.2: STRONG-hold every declaration we synthesize for the entire\n'
'// CarPlayApp process lifetime. object_setIvar into _carPlayDeclaration does\n'
'// NOT reliably take ownership of this ivar, so under ARC our local decl was\n'
'// freed at loop-scope end and the ivar dangled; CarPlay\'s async analytics\n'
'// (_DBAnalyticsAppInfo initWithBundleIdentifier:appDeclaration:policyEvaluator:)\n'
'// then retained a dead pointer and crash-looped the process. Keeping our own\n'
'// strong reference makes the object immortal so every later read is valid.\n'
'static NSMutableArray *gCBRDeclarations = nil;\n'
'// Associated-object key: also pins each declaration to its appInfo\'s lifetime.\n'
'static const void *kCBRDeclKey = &kCBRDeclKey;\n\n')
s = s.replace(anchor1, globals_block + anchor1, 1)

# --- Edit 2: fully populate 21 ivars + retain, replacing the old 4-field builder ---
old_builder = (
'            id decl = [[declClass alloc] init];\n'
'            cb1b(decl, "setSupportsTemplates:", NO);   // NO = 0\n'
'            cb1b(decl, "setSupportsMaps:", NO);        // YES = 1\n'
'            cb1(decl, "setBundleIdentifier:", bidObj);\n'
'            id bundleURL = cb(appInfo, "bundleURL");\n'
'            id declPath = bundleURL ? cb(bundleURL, "path") : nil;\n'
'            if (declPath) cb1(decl, "setBundlePath:", declPath);\n'
'\n'
'            BOOL set = setIvar(appInfo, "_carPlayDeclaration", decl);\n'
'            if (!set) {\n'
'                SEL setter = sel_registerName("setCarPlayDeclaration:");\n'
'                if (setter && [appInfo respondsToSelector:setter])\n'
'                    ((void(*)(id,SEL,id))objc_msgSend)(appInfo, setter, decl);\n'
'            }')
assert old_builder in s, "FAIL: declaration-builder anchor not found (source not clean v3.20.1?)"
new_builder = (
'            id decl = [[declClass alloc] init];\n'
'            // v3.20.2: populate ALL 21 ivars so analytics can never dereference\n'
'            // an uninitialized field. cb1b/cb1 no-op safely if a setter is absent.\n'
'            // 17 BOOL support flags — all NO for a bridged (non-native) app:\n'
'            cb1b(decl, "setSystemApp:", NO);\n'
'            cb1b(decl, "setRequiresGeoSupport:", NO);\n'
'            cb1b(decl, "setLaunchUsingSiri:", NO);\n'
'            cb1b(decl, "setLaunchNotificationsUsingSiri:", NO);\n'
'            cb1b(decl, "setSupportsPlayableContent:", NO);\n'
'            cb1b(decl, "setSupportsMessaging:", NO);\n'
'            cb1b(decl, "setSupportsCalling:", NO);\n'
'            cb1b(decl, "setSupportsMaps:", NO);          // NO = normal icon path\n'
'            cb1b(decl, "setSupportsAudio:", NO);\n'
'            cb1b(decl, "setSupportsCommunication:", NO);\n'
'            cb1b(decl, "setSupportsTemplates:", NO);     // NO = not a template app\n'
'            cb1b(decl, "setSupportsCharging:", NO);\n'
'            cb1b(decl, "setSupportsParking:", NO);\n'
'            cb1b(decl, "setSupportsPublicSafety:", NO);\n'
'            cb1b(decl, "setSupportsQuickOrdering:", NO);\n'
'            cb1b(decl, "setSupportsFueling:", NO);\n'
'            cb1b(decl, "setSupportsDrivingTask:", NO);\n'
'            // 3 object fields — never leave nil for the analytics reader:\n'
'            cb1(decl, "setBundleIdentifier:", bidObj);\n'
'            id bundleURL = cb(appInfo, "bundleURL");\n'
'            id declPath = bundleURL ? cb(bundleURL, "path") : nil;\n'
'            cb1(decl, "setBundlePath:", declPath ?: @"");\n'
'            cb1(decl, "setAutoMakerProtocols:", [NSSet set]);  // was left nil before\n'
'\n'
'            // v3.20.2 CRITICAL: take ownership BEFORE the ivar store so the\n'
'            // object cannot be freed when this scope ends (the crash-loop fix).\n'
'            if (!gCBRDeclarations) gCBRDeclarations = [[NSMutableArray alloc] init];\n'
'            [gCBRDeclarations addObject:decl];\n'
'            objc_setAssociatedObject(appInfo, kCBRDeclKey, decl,\n'
'                                     OBJC_ASSOCIATION_RETAIN_NONATOMIC);\n'
'\n'
'            BOOL set = setIvar(appInfo, "_carPlayDeclaration", decl);\n'
'            if (!set) {\n'
'                SEL setter = sel_registerName("setCarPlayDeclaration:");\n'
'                if (setter && [appInfo respondsToSelector:setter])\n'
'                    ((void(*)(id,SEL,id))objc_msgSend)(appInfo, setter, decl);\n'
'            }')
s = s.replace(old_builder, new_builder, 1)

# --- version string bump ---
s = s.replace(
    '"[CBR] v3.20.1 init - ENABLE in-process car-scene window (CarPlayApp side)\\n"',
    '"[CBR] v3.20.2 init - declaration lifetime fix (retain + full-populate)\\n"', 1)

open(p, "w", encoding="utf-8").write(s)
print("OK: applied v3.20.2 declaration lifetime fix")
