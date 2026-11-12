#!/usr/bin/env bash
set -euo pipefail
MODE="${1:-run}"
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"
export CLANG_MODULE_CACHE_PATH="$ROOT_DIR/work/clang-cache"
export SWIFTPM_MODULECACHE_OVERRIDE="$ROOT_DIR/work/swift-module-cache"
APP_NAME="Cascade"
APP_BUNDLE="${CASCADE_BUNDLE_PATH:-$ROOT_DIR/outputs/Cascade.app}"
BUILD_DIR="$ROOT_DIR/work/swift-build"
if [[ "$MODE" != "--package" && "$MODE" != "package" ]]; then
  pkill -x "$APP_NAME" >/dev/null 2>&1 || true
fi
swift build --disable-sandbox --scratch-path "$BUILD_DIR"
BIN_DIR="$(swift build --disable-sandbox --scratch-path "$BUILD_DIR" --show-bin-path)"
mkdir -p "$APP_BUNDLE/Contents/MacOS" "$APP_BUNDLE/Contents/Resources"
cp "$BIN_DIR/Cascade" "$APP_BUNDLE/Contents/MacOS/Cascade.next"
mv "$APP_BUNDLE/Contents/MacOS/Cascade.next" "$APP_BUNDLE/Contents/MacOS/Cascade"
chmod 755 "$APP_BUNDLE/Contents/MacOS/Cascade"
# The app resolves its resource bundle in Contents/Resources before the SwiftPM fallback.
rm -rf "$APP_BUNDLE/Cascade_CascadeMac.bundle"
rm -rf "$APP_BUNDLE/Contents/Resources/Cascade_CascadeMac.bundle"
cp -R "$BIN_DIR/Cascade_CascadeMac.bundle" "$APP_BUNDLE/Contents/Resources/"
rm -rf "$APP_BUNDLE/Contents/Resources/Cascade_CascadeCore.bundle"
cp -R "$BIN_DIR/Cascade_CascadeCore.bundle" "$APP_BUNDLE/Contents/Resources/"
cp "$ROOT_DIR/design/Cascade.icns" "$APP_BUNDLE/Contents/Resources/Cascade.icns"
cat > "$APP_BUNDLE/Contents/Info.plist" <<'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleExecutable</key><string>Cascade</string>
<key>CFBundleIdentifier</key><string>ru.badpaand.Cascade</string>
<key>CFBundleName</key><string>Cascade</string>
<key>CFBundleDisplayName</key><string>Cascade</string>
<key>CFBundleShortVersionString</key><string>0.5.0</string>
<key>CFBundleVersion</key><string>6</string>
<key>CFBundleIconFile</key><string>Cascade</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>LSMinimumSystemVersion</key><string>14.0</string>
<key>NSPrincipalClass</key><string>NSApplication</string>
<key>NSHighResolutionCapable</key><true/>
<key>NSHumanReadableCopyright</key><string>BadPaand · 2026</string>
</dict></plist>
PLIST
/usr/bin/codesign --force --deep --sign - "$APP_BUNDLE"
case "$MODE" in
  --package|package)
    /usr/bin/ditto -c -k --sequesterRsrc --keepParent "$APP_BUNDLE" "$ROOT_DIR/outputs/Cascade-Mac.zip"
    ;;
  run) /usr/bin/open -n "$APP_BUNDLE" ;;
  --verify|verify)
    /usr/bin/open -n "$APP_BUNDLE"
    sleep 2
    pgrep -x Cascade >/dev/null
    ;;
  --debug|debug) /usr/bin/lldb -- "$APP_BUNDLE/Contents/MacOS/Cascade" ;;
  --logs|logs|--telemetry|telemetry)
    /usr/bin/open -n "$APP_BUNDLE"
    /usr/bin/log stream --info --style compact --predicate 'process == "Cascade"'
    ;;
  *) echo "Usage: $0 [run|--verify|--package|--debug|--logs]" >&2; exit 2 ;;
esac
