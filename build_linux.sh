#!/usr/bin/env bash
# Builds dist/virtualdiskbrowser (GUI + CLI in one binary) on a Linux machine.
# Needs python3 with tkinter (Debian/Ubuntu: apt install python3-tk python3-venv)
# and a C compiler if pip has to build pytsk3 from source (apt install build-essential python3-dev).
#
# Build on the oldest distribution you want to support: the binary runs on
# distributions with the same or a newer glibc.  To build in Docker instead, use
# build_linux_docker.sh.
set -euo pipefail
cd "$(dirname "$0")"

python3 -m venv .venv-build
. .venv-build/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller

python -m PyInstaller --noconfirm --clean --onefile \
  --name virtualdiskbrowser --add-data "assets/icon.png:assets" main.py

echo
echo "Built dist/virtualdiskbrowser"
echo "  GUI: ./dist/virtualdiskbrowser [disk.vmdk]"
echo "  CLI: ./dist/virtualdiskbrowser info disk.vmdk"
