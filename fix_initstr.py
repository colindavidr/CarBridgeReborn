#!/usr/bin/env python3
# Repair the v3.20.11 init-string literal that got a raw newline injected into it.
# Uses str.replace (NO re.sub) so backslashes are never reinterpreted.
p = "src/Tweak.xm"
s = open(p, encoding="utf-8").read()

broken = 'const char msg[] = "[CBR] v3.20.11 init - grafting host only (PATH-A reverted, load runaway fix)\n";'
fixed  = 'const char msg[] = "[CBR] v3.20.11 init - grafting host only (PATH-A reverted, load runaway fix)\\n";'

if fixed in s:
    print("ALREADY FIXED")
elif broken in s:
    s = s.replace(broken, fixed, 1)
    open(p, "w", encoding="utf-8").write(s)
    print("FIXED init-string literal")
else:
    print("PATTERN NOT FOUND — paste lines 2415-2424 so we can see the exact text")
