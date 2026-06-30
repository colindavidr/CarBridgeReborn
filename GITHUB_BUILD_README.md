# Building CarBridgeReborn on GitHub Actions (correct arm64e)

Your local Linux toolchain produces broken arm64e (`capabilities 0x0`), which
crashes on iOS 17. macOS/Xcode produces correct arm64e (`0x80`). This repo's
workflow builds the `.deb` on a macOS runner for free.

## One-time setup
1. Create a new GitHub repo (private is fine), e.g. `CarBridgeReborn`.
2. From this project folder:
   ```
   git init
   git add -A
   git commit -m "CarBridgeReborn v3.11.3"
   git branch -M main
   git remote add origin git@github.com:<YOUR_USERNAME>/CarBridgeReborn.git
   git push -u origin main
   ```
   (or use an https remote + a personal access token)

## Each build
- Pushing to the repo (or clicking "Run workflow" under the Actions tab) builds it.
- Open the run -> Artifacts -> download `CarBridgeReborn-deb` -> unzip to get the `.deb`.
- The run logs print the arm64e `capabilities` — it should say `0x80`.

## Install the artifact on device
```
scp <the>.deb root@100.70.27.4:/var/mobile/
ssh root@100.70.27.4 "dpkg -i /var/mobile/*.deb && killall -9 Preferences 2>/dev/null"
```
Re-bootstrap via NathanLR, then open Settings -> CarBridge Reborn.
