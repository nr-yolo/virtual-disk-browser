#!/bin/bash
# Builds QCOW/QCOW2 variants from the images made by make_test_images.sh.
#   docker run --rm -v "$PWD/tests:/tests" debian:bookworm bash /tests/make_qcow_images.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8
if ! command -v qemu-img >/dev/null; then
  apt-get update -qq >/dev/null && apt-get install -y -qq qemu-utils >/dev/null
fi

IMG=/tests/images
OUT=$IMG/qcow
WIN=$IMG/win_monolithicFlat/win-flat.vmdk     # raw copy of the Windows test disk
LIN=$IMG/lin_monolithicSparse/lin.vmdk
rm -rf "$OUT" && mkdir -p "$OUT" /work
cd "$OUT"

ref() {  # image name -> name.sha256 of qemu's own raw rendering
  qemu-img convert -O raw "$1" /work/ref.raw
  sha256sum /work/ref.raw | cut -d' ' -f1 > "$2.sha256"
  rm -f /work/ref.raw
}

qemu-img convert -f raw -O qcow2 "$WIN" win.qcow2
qemu-img convert -f raw -O qcow2 -o compat=0.10 "$WIN" win_v2.qcow2
qemu-img convert -f raw -O qcow2 -c "$WIN" win_zlib.qcow2
qemu-img convert -f raw -O qcow2 -c -o compression_type=zstd "$WIN" win_zstd.qcow2
qemu-img convert -f raw -O qcow2 -o extended_l2=on,cluster_size=128k "$WIN" win_extl2.qcow2
qemu-img convert -f raw -O qcow2 -o cluster_size=4k "$WIN" win_4k.qcow2
qemu-img convert -f raw -O qcow "$WIN" win.qcow
qemu-img convert -O qcow2 -c -o compression_type=zstd "$LIN" lin_zstd.qcow2

# backing chain: qcow2 overlay on qcow2 base, with written and zeroed ranges
qemu-img create -q -f qcow2 -b win.qcow2 -F qcow2 overlay.qcow2
qemu-io -c "write -P 0x5a 1M 64k" -c "write -z 3M 1M" overlay.qcow2 >/dev/null
ref overlay.qcow2 overlay
# extended-L2 overlay: sub-cluster allocation and zero bits on top of a backing file
qemu-img create -q -f qcow2 -o extended_l2=on -b win.qcow2 -F qcow2 overlay_extl2.qcow2
qemu-io -c "write -P 0x33 1028k 4k" -c "write -z 2052k 8k" overlay_extl2.qcow2 >/dev/null
ref overlay_extl2.qcow2 overlay_extl2
# qcow2 overlay on a VMDK base
cp "$IMG/win_monolithicSparse/win.vmdk" base.vmdk
qemu-img create -q -f qcow2 -b base.vmdk -F vmdk overlay_on_vmdk.qcow2
qemu-io -c "write -P 0x5a 1M 64k" -c "write -z 3M 1M" overlay_on_vmdk.qcow2 >/dev/null
ref overlay_on_vmdk.qcow2 overlay

# internal snapshot, then new writes on top of it
cp win.qcow2 snapshot.qcow2
qemu-img snapshot -c before-update snapshot.qcow2
qemu-io -c "write -P 0x77 2M 64k" snapshot.qcow2 >/dev/null
ref snapshot.qcow2 snapshot

chmod -R a+rw "$OUT"
ls -la "$OUT"
echo DONE
