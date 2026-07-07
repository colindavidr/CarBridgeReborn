#!/usr/bin/env python3
# v3.20.11 — back PATH-A + probes out of the tap hot path (kills the load-143 runaway),
# keep only the grafting host that actually rendered YouTube. Strictly subtractive.
import sys
p="src/Tweak.xm"; s=open(p,encoding="utf-8").read()
if "v3.20.11" in s: sys.exit("ALREADY PATCHED")

old=('    cbrSBProbeSceneHandle(bid);\n'
     '    id _cbrHandle = cbrSBCreateSceneHandle(bid);\n'
     '    cbrSBHostScene(bid, _cbrHandle);\n'
     '    cbrSBReassignToCarPlay(bid);\n'
     '    cbrSBProbeTransition(bid);\n'
     '    cbrSBProbeTxnCtx(bid);\n')
assert old in s, "FAIL: launch-callback anchor not found"
new=('    // v3.20.11: PATH-A + probes REMOVED from the hot path. cbrSBReassignToCarPlay\n'
     '    // poked the LIVE main-display scene\'s display config on every tap; the composite\n'
     '    // never moved, leaving the scene spinning the render server -> load avg 143 runaway.\n'
     '    // Keep ONLY the grafting host - this is what actually rendered scrollable YouTube.\n'
     '    // cbrSBProbeSceneHandle(bid);      // diagnostic only - off hot path\n'
     '    id _cbrHandle = cbrSBCreateSceneHandle(bid);\n'
     '    cbrSBHostScene(bid, _cbrHandle);\n'
     '    // cbrSBReassignToCarPlay(bid);     // PATH-A - caused the load runaway - REMOVED\n'
     '    // cbrSBProbeTransition(bid);       // diagnostic only - off hot path\n'
     '    // cbrSBProbeTxnCtx(bid);           // diagnostic only - off hot path\n')
s=s.replace(old,new,1)

# version string bump (whatever the current init line says -> 3.20.11)
import re
s=re.sub(r'"\[CBR\] v3\.20\.\d+ init[^"]*\\n"',
         '"[CBR] v3.20.11 init - grafting host only (PATH-A reverted, load runaway fix)\\n"', s, count=1)
open(p,"w",encoding="utf-8").write(s)
print("OK: v3.20.11 applied")
