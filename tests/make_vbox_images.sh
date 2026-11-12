#!/bin/bash
# Builds VDI / VHD images (including differencing disks) with VirtualBox's own
# VBoxManage, starting from the raw Windows test disk made by make_test_images.sh.
# Runs on Windows (Git Bash) or Linux with VirtualBox installed.
#
# VBOX_USER_HOME points at a throw-away folder so the user's VirtualBox media
# registry is never touched.
set -euo pipefail
cd "$(dirname "$0")"
IMG=images
OUT=$IMG/vbox
RAW=$IMG/win_monolithicFlat/win-flat.vmdk
VB=${VBOXMANAGE:-VBoxManage}
if ! command -v "$VB" >/dev/null; then
  VB="/c/Program Files/Oracle/VirtualBox/VBoxManage.exe"
fi
export VBOX_USER_HOME
VBOX_USER_HOME="$(mktemp -d)"
abs() { (cd "$(dirname "$1")" && echo "$(pwd -W 2>/dev/null || pwd)/$(basename "$1")"); }
rm -rf "$OUT"
mkdir -p "$OUT/diff_vdi/Snapshots" "$OUT/diff_vhd"

"$VB" convertfromraw "$RAW" "$OUT/win_dynamic.vdi" --format VDI >/dev/null
"$VB" convertfromraw "$RAW" "$OUT/win_fixed.vdi" --format VDI --variant Fixed >/dev/null
"$VB" convertfromraw "$RAW" "$OUT/win_dynamic.vhd" --format VHD >/dev/null
"$VB" convertfromraw "$RAW" "$OUT/win_fixed.vhd" --format VHD --variant Fixed >/dev/null

# differencing disks: VirtualBox snapshot layout (base next to Snapshots/{uuid}.vdi)
diffdisk() {  # base child format reference-name
  local base=$1 child=$2 fmt=$3 ref=$4
  cp "$OUT/win_dynamic.${fmt,,}" "$base"
  "$VB" createmedium disk --filename "$(abs "$child")" --diffparent "$(abs "$base")" --format "$fmt" >/dev/null
  # writes a FAT file system through the child: partly-filled blocks that mix with the parent
  "$VB" mediumio --disk "$(abs "$child")" formatfat --quick >/dev/null
  "$VB" mediumio --disk "$(abs "$child")" cat --output "$(abs "$OUT")/ref.raw" >/dev/null
  sha256sum "$OUT/ref.raw" | cut -d' ' -f1 > "$OUT/$ref.sha256"
  rm -f "$OUT/ref.raw"
  "$VB" closemedium disk "$(abs "$child")" >/dev/null
  "$VB" closemedium disk "$(abs "$base")" >/dev/null
}
diffdisk "$OUT/diff_vdi/base.vdi" "$OUT/diff_vdi/Snapshots/child.vdi" VDI diff_vdi
diffdisk "$OUT/diff_vhd/base.vhd" "$OUT/diff_vhd/child.vhd" VHD diff_vhd

rm -rf "$VBOX_USER_HOME" 2>/dev/null || true  # VBoxSVC may still hold its log for a few seconds
ls -laR "$OUT"
echo DONE
