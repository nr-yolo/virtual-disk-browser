#!/usr/bin/env bash
# Builds the Linux executable inside a Debian 11 (glibc 2.31) container so the
# result runs on Ubuntu 20.04+, Debian 11+, RHEL/Rocky 9+, Fedora, etc.
# Works from Linux, macOS or Windows (Git Bash) with Docker installed.
# Output: dist-linux/virtualdiskbrowser
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist-linux

MSYS_NO_PATHCONV=1 docker run --rm -v "$(pwd -W 2>/dev/null || pwd):/src:ro" -v "$(pwd -W 2>/dev/null || pwd)/dist-linux:/out" \
  python:3.12-bullseye bash -c '
    set -e
    cp -r /src /build && cd /build
    rm -rf build dist .venv-build
    pip install --quiet --root-user-action=ignore -r requirements.txt pyinstaller
    python -m PyInstaller --noconfirm --clean --onefile --name virtualdiskbrowser \
      --add-data "assets/icon.png:assets" main.py
    cp dist/virtualdiskbrowser /out/
    chmod 755 /out/virtualdiskbrowser
  '
echo "Built dist-linux/virtualdiskbrowser"
