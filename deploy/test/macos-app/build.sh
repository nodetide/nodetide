#!/bin/sh
# Build "Nodetide Wallet.app" (Apple-silicon or Intel, whichever this Mac is) with PyInstaller.
#   ./build.sh            -> dist/Nodetide Wallet.app
# The app is only ad-hoc signed: Gatekeeper warns on another Mac (right-click > Open), and macOS may ask again for
# Keychain access after each rebuild because the code identity changes.
set -eu
cd "$(dirname "$0")"
ROOT=$(cd ../../.. && pwd)

[ -d .build-venv ] || python3 -m venv .build-venv
.build-venv/bin/pip install -q --upgrade pip
.build-venv/bin/pip install -q "$ROOT/python" keyring rumps pyinstaller

rm -rf build dist
.build-venv/bin/pyinstaller --noconfirm --windowed --name "Nodetide Wallet" \
    --osx-bundle-identifier eu.kuklin.nodetide-wallet \
    --paths ../wallet --hidden-import app \
    --collect-submodules keyring.backends --collect-submodules nodetide \
    launcher.py

APP="dist/Nodetide Wallet.app"
plutil -insert LSUIElement -bool true "$APP/Contents/Info.plist"   # menu-bar only, no Dock icon
codesign --force --deep --sign - "$APP"
echo "built: $PWD/$APP"
