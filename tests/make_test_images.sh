#!/bin/bash
# Builds reference disk images with real Linux tools, then converts them to every
# VMDK flavour qemu-img can produce.  Run inside a privileged Debian container:
#   docker run --rm --privileged -v "$PWD/tests:/tests" debian:bookworm bash /tests/make_test_images.sh
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive LC_ALL=C.UTF-8 LANG=C.UTF-8
apt-get update -qq >/dev/null
apt-get install -y -qq qemu-utils e2fsprogs xfsprogs ntfs-3g dosfstools mtools lvm2 fdisk exfatprogs >/dev/null

OUT=/tests/images
WORK=/work
rm -rf "$OUT" && mkdir -p "$OUT" "$WORK"
cd "$WORK"

mkcontent() {  # dir tag linux?
  local d=$1
  mkdir -p "$d/Documents/Sub Folder" "$d/bin" "$d/empty_dir" "$d/many"
  echo "hello from $2" > "$d/readme.txt"
  seq -f 'line %g of the text file' 1 5000 > "$d/Documents/lines.txt"
  head -c 3000000 /dev/urandom > "$d/bin/random.bin"
  head -c 70000 /dev/urandom > "$d/Documents/Sub Folder/small.dat"
  echo "unicode name test" > "$d/Documents/naïve café ☕.txt"
  local n=${4:-300}
  for i in $(seq 1 "$n"); do echo "file number $i" > "$d/many/file_$i.txt"; done
  if [ "${3:-}" = linux ]; then ln -s ../readme.txt "$d/bin/link_to_readme"; fi
}

manifest() {  # srcdir name
  (cd "$1" && find . -type f -print0 | sort -z | xargs -0 sha256sum) > "$OUT/$2.manifest"
}

attach() {  # image offset_bytes size_bytes -> prints loop dev
  losetup -f --show --offset "$2" --sizelimit "$3" "$1"
}

# ---------------------------------------------------------------- Windows disk
truncate -s 512M win.raw
sfdisk -q win.raw <<EOF
label: dos
start=2048, size=524288, type=7
start=526336, size=262144, type=c
start=788480, type=5
start=790528, size=204800, type=6
EOF
# NTFS partition
mkcontent src_ntfs NTFS no 300
L=$(attach win.raw $((2048*512)) $((524288*512)))
mkfs.ntfs -Q -q -L WINDATA "$L"
mkdir -p /mnt/ntfs && ntfs-3g "$L" /mnt/ntfs
cp -a src_ntfs/. /mnt/ntfs/
mkdir -p /mnt/ntfs/deleted_test && echo "to be deleted" > /mnt/ntfs/deleted_test/gone.txt && sync && rm /mnt/ntfs/deleted_test/gone.txt
umount /mnt/ntfs && losetup -d "$L"
manifest src_ntfs ntfs
# FAT32 partition (populated with mtools, no mount needed)
mkcontent src_fat32 FAT32 no 300
L=$(attach win.raw $((526336*512)) $((262144*512)))
mkfs.vfat -F 32 -n FAT32VOL "$L" >/dev/null
losetup -d "$L"
export MTOOLS_SKIP_CHECK=1
mcopy -s -i "win.raw@@$((526336*512))" src_fat32/* ::/
manifest src_fat32 fat32
# FAT16 logical partition inside the extended partition
mkcontent src_fat16 FAT16 no 50
L=$(attach win.raw $((790528*512)) $((204800*512)))
mkfs.vfat -F 16 -n LOGICAL "$L" >/dev/null
losetup -d "$L"
mcopy -s -i "win.raw@@$((790528*512))" src_fat16/* ::/
manifest src_fat16 fat16
sha256sum win.raw | cut -d' ' -f1 > "$OUT/win.sha256"

# ---------------------------------------------------------------- Linux disk
truncate -s 2560M lin.raw
sfdisk -q lin.raw <<EOF
label: gpt
start=2048, size=524288, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="ext4part"
start=526336, size=1048576, type=0FC63DAF-8483-4772-8E79-3D69D8477DE4, name="xfspart"
start=1574912, type=E6D6D379-F507-44C2-A23C-238F2A3DF928, name="lvmpv"
EOF
mkcontent src_ext4 ext4 linux 300
L=$(attach lin.raw $((2048*512)) $((524288*512)))
mkfs.ext4 -q -L LINROOT -d src_ext4 "$L"
losetup -d "$L"
manifest src_ext4 ext4

mkcontent src_xfs XFS linux 3000
L=$(attach lin.raw $((526336*512)) $((1048576*512)))
mkfs.xfs -q -f -L XFSDATA "$L"
mkdir -p /mnt/xfs && mount "$L" /mnt/xfs
cp -a src_xfs/. /mnt/xfs/
# a heavily fragmented file to force a b-tree extent map
for i in $(seq 0 2 400); do dd if=/dev/urandom of=/mnt/xfs/fragmented.bin bs=4096 seek=$i count=1 conv=notrunc status=none; sync; done
cp /mnt/xfs/fragmented.bin src_xfs/fragmented.bin
umount /mnt/xfs && losetup -d "$L"
manifest src_xfs xfs

# LVM PV on partition 3 with two logical volumes
L=$(attach lin.raw $((1574912*512)) $(( (5242880-1574912-34)*512 )))
LVMCONF='activation { udev_sync = 0 udev_rules = 0 } devices { obtain_device_list_from_udev = 0 }'
pvcreate -q --config "$LVMCONF" "$L"
vgcreate -q --config "$LVMCONF" vgtest "$L"
lvcreate -q --config "$LVMCONF" -an -Zn -L 400M -n lvroot vgtest
lvcreate -q --config "$LVMCONF" -an -Zn -L 600M -n lvdata vgtest
vgchange -q --config "$LVMCONF" -ay vgtest
vgscan -q --mknodes --config "$LVMCONF" >/dev/null
mkcontent src_lvroot lvroot linux 100
mkfs.ext4 -q -L LVROOT -d src_lvroot /dev/vgtest/lvroot
manifest src_lvroot lvroot
mkcontent src_lvdata lvdata linux 100
mkfs.xfs -q -f /dev/vgtest/lvdata
mkdir -p /mnt/lvx && mount /dev/vgtest/lvdata /mnt/lvx && cp -a src_lvdata/. /mnt/lvx/ && umount /mnt/lvx
manifest src_lvdata lvdata
vgchange -q --config "$LVMCONF" -an vgtest
losetup -d "$L"
sha256sum lin.raw | cut -d' ' -f1 > "$OUT/lin.sha256"

# ---------------------------------------------------------------- VMDK variants
for fmt in monolithicSparse streamOptimized monolithicFlat twoGbMaxExtentSparse; do
  mkdir -p "$OUT/win_$fmt"
  qemu-img convert -O vmdk -o subformat=$fmt win.raw "$OUT/win_$fmt/win.vmdk"
done
for fmt in monolithicSparse streamOptimized twoGbMaxExtentSparse; do
  mkdir -p "$OUT/lin_$fmt"
  qemu-img convert -O vmdk -o subformat=$fmt lin.raw "$OUT/lin_$fmt/lin.vmdk"
done
# small flat split variant
mkdir -p "$OUT/win_twoGbMaxExtentFlat"
qemu-img convert -O vmdk -o subformat=twoGbMaxExtentFlat win.raw "$OUT/win_twoGbMaxExtentFlat/win.vmdk"

# snapshot: delta disk on top of a sparse base, with a write landing in the delta
mkdir -p "$OUT/snapshot"
cp "$OUT/win_monolithicSparse/win.vmdk" "$OUT/snapshot/base.vmdk"
cd "$OUT/snapshot"
qemu-img create -q -f vmdk -b base.vmdk -F vmdk delta.vmdk
qemu-io -c "write -P 0x5a 1M 64k" delta.vmdk >/dev/null
qemu-img convert -O raw delta.vmdk /work/delta.raw
sha256sum /work/delta.raw | cut -d' ' -f1 > "$OUT/delta.sha256"
cd "$WORK"
chmod -R a+rw "$OUT"
ls -laR "$OUT" | head -80
bash /tests/make_qcow_images.sh
bash /tests/make_qemu_formats.sh
echo DONE
