#!/bin/bash
# VHD / VHDX / VDI variants written by qemu-img, from images made by make_test_images.sh.
#   docker run --rm -v "$PWD/tests:/tests" debian:bookworm bash /tests/make_qemu_formats.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
if ! command -v qemu-img >/dev/null; then
  apt-get update -qq >/dev/null && apt-get install -y -qq qemu-utils >/dev/null
fi
IMG=/tests/images
OUT=$IMG/qemu_formats
WIN=$IMG/win_monolithicFlat/win-flat.vmdk
LIN=$IMG/lin_monolithicSparse/lin.vmdk
rm -rf "$OUT" && mkdir -p "$OUT" /work
cd "$OUT"

qemu-img convert -f raw -O vpc -o subformat=dynamic,force_size=on "$WIN" win_dynamic.vhd
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size=on "$WIN" win_fixed.vhd
# without force_size qemu rounds the size up to a CHS geometry, like Virtual PC did
qemu-img convert -f raw -O vpc -o subformat=dynamic "$WIN" win_chs.vhd
qemu-img convert -O raw win_chs.vhd /work/r.raw && sha256sum /work/r.raw | cut -d' ' -f1 > win_chs.sha256
qemu-img convert -f raw -O vhdx -o subformat=dynamic "$WIN" win_dynamic.vhdx
qemu-img convert -f raw -O vhdx -o subformat=fixed "$WIN" win_fixed.vhdx
qemu-img convert -f raw -O vhdx -o subformat=dynamic,block_size=1M "$WIN" win_1m.vhdx
qemu-img convert -O vhdx -o subformat=dynamic "$LIN" lin.vhdx
qemu-img convert -f raw -O vdi "$WIN" win_dynamic.vdi
qemu-img convert -f raw -O vdi -o static=on "$WIN" win_static.vdi
qemu-img convert -O vdi "$LIN" lin.vdi
rm -f /work/r.raw
chmod -R a+rw "$OUT"
ls -la "$OUT"
echo DONE
