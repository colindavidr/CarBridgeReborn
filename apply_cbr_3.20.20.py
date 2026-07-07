#!/usr/bin/env python3
# v3.20.20 — instrument the keep-alive hooks so we can SEE, at lock time, whether they
# fire, match the hosted app, what class the settings arg is (settings vs diff on iOS 17),
# and whether they block. Diagnostic; logs to /var/mobile/CBR_keepalive.txt.
import sys
p="src/Tweak.xm"; s=open(p,encoding="utf-8").read()
if "cbrKLLog" in s: sys.exit("ALREADY PATCHED")
def repl(old,new,label):
    global s
    if old not in s: sys.exit(f"FAIL anchor: {label}")
    s=s.replace(old,new,1)

# 1) append-only diagnostic logger, before the SPRINGBOARD group
repl('%group SPRINGBOARD\n// v3.20.18: keep-alive hooks ported from carplay-cast',
'// v3.20.20: append-only diagnostic log for the keep-alive hooks (what happens at lock).\n'
'static void cbrKLLog(const char *fmt, ...) {\n'
'    static int klfd = -1;\n'
'    if (klfd < 0) klfd = open("/var/mobile/CBR_keepalive.txt", O_WRONLY|O_CREAT|O_APPEND, 0644);\n'
'    if (klfd < 0) return;\n'
'    char buf[512];\n'
'    va_list ap; va_start(ap, fmt);\n'
'    int n = vsnprintf(buf, sizeof(buf), fmt, ap);\n'
'    va_end(ap);\n'
'    if (n > 0) write(klfd, buf, (size_t)n > sizeof(buf) ? sizeof(buf) : (size_t)n);\n'
'}\n\n'
'%group SPRINGBOARD\n// v3.20.18: keep-alive hooks ported from carplay-cast',
"KLLog helper")

# 2) instrument FBScene hook (log argClass/isFg/decision)
repl('                if (bid && [gCBRKeepAlive containsObject:bid]) {\n'
     '                    BOOL isFg = ((BOOL(*)(id,SEL))objc_msgSend)(arg1, sel_registerName("isForeground"));\n'
     '                    if (!isFg) { return; }   // block the background transition -> keep it live on CarPlay\n'
     '                }',
     '                if (bid && [gCBRKeepAlive containsObject:bid]) {\n'
     '                    BOOL respFg = [arg1 respondsToSelector:sel_registerName("isForeground")];\n'
     '                    BOOL isFg = respFg ? ((BOOL(*)(id,SEL))objc_msgSend)(arg1, sel_registerName("isForeground")) : YES;\n'
     '                    cbrKLLog("[fbscene] bid=%s argClass=%s respFg=%d isFg=%d => %s\\n",\n'
     '                             [bid UTF8String], object_getClassName(arg1), (int)respFg, (int)isFg, (respFg && !isFg) ? "BLOCK" : "pass");\n'
     '                    if (respFg && !isFg) { return; }   // block the background transition -> keep it live on CarPlay\n'
     '                }',
     "FBScene instrument")

# 3) instrument SBSuspendedUnderLockManager hook
repl('            if (bid && [gCBRKeepAlive containsObject:bid]) shouldBackground = NO;',
     '            if (bid && [gCBRKeepAlive containsObject:bid]) {\n'
     '                cbrKLLog("[lockmgr] bid=%s origShould=%d => forcing NO\\n", [bid UTF8String], shouldBackground);\n'
     '                shouldBackground = NO;\n'
     '            }',
     "lockmgr instrument")

# 4) fresh keepalive log each respring + version bump
repl('        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);',
     '        unlink("/var/mobile/CBR_keepalive.txt");\n'
     '        int _sf=open("/var/mobile/CBR_sb_init.txt",O_WRONLY|O_CREAT|O_TRUNC,0644);',
     "keepalive unlink")
repl('"[CBR] v3.20.19 init - keep-alive + hook-resolution logging\\n"',
     '"[CBR] v3.20.20 init - keep-alive hook instrumentation\\n"',
     "version string")

open(p,"w",encoding="utf-8").write(s)
print("OK: v3.20.20 applied")
