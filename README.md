# Virtual Disk Browser

Browse and copy files out of virtual machine disks without starting the VM, on
Windows and Linux. It reads VMware VMDK, VirtualBox VDI, Hyper-V VHD/VHDX and
QEMU QCOW2 disks. Damaged and incomplete disks are supported too.

![icon](assets/icon.png)

## What it opens

### VMware: VMDK

| Variant | Typical source |
|---|---|
| monolithicSparse (single growable file) | VMware Workstation/Player, VirtualBox, QEMU |
| twoGbMaxExtentSparse (`disk-s001.vmdk` ...) | VMware Workstation split disks |
| monolithicFlat / twoGbMaxExtentFlat (`-flat.vmdk`, `-f001.vmdk`) | preallocated disks, VirtualBox fixed |
| vmfs / ESXi (`disk.vmdk` + `disk-flat.vmdk`) | ESXi datastores |
| streamOptimized (compressed) | OVA / OVF exports, cloud images |
| vmfsSparse / COWD | ESX snapshots |
| snapshot chains (`disk-000001.vmdk`) | VMware snapshots |

### VirtualBox: VDI

| Variant | Typical source |
|---|---|
| dynamic and fixed `.vdi` | VirtualBox's default disk format |
| differencing (`Snapshots/{uuid}.vdi`) | VirtualBox snapshots |

A VDI snapshot doesn't record where its parent disk is, only the parent's
UUID. The parent is found by checking the `.vdi` files next to the snapshot
and in the folder above, which is the normal VirtualBox VM folder layout.

### Microsoft: VHD and VHDX

| Variant | Typical source |
|---|---|
| VHD fixed, dynamic, differencing | Virtual PC, Hyper-V (older), Azure, Disk2vhd, VirtualBox |
| VHDX fixed, dynamic, differencing (512 or 4096-byte sectors) | Hyper-V, Windows Backup, Windows "Create VHD" |

### QEMU / KVM: QCOW2

| Variant | Typical source |
|---|---|
| QCOW2 v2/v3 (`.qcow2`): zlib or zstd compression, zero clusters, extended L2, external data files | QEMU/KVM, Proxmox, libvirt/virt-manager, GNS3, OpenStack |
| QCOW2 backing chains (overlay → base, which can be QCOW2, VMDK or raw) | `qemu-img create -b`, libvirt external snapshots |
| QCOW2 internal snapshots (listed under **Info**) | `qemu-img snapshot`, `virsh snapshot-create` |
| legacy QCOW v1 (`.qcow`) | old QEMU |

### Other

Raw images (`.img`, `.raw`, `.dd`), from dd or qemu.

Encrypted QCOW images (AES or LUKS) are detected, but they can't be read.

Partition tables: MBR (including extended/logical partitions), GPT, and Linux
LVM2 (linear and striped logical volumes).

File systems:

* Windows: NTFS, FAT12/16/32, exFAT
* Linux: ext2/3/4, XFS (built-in reader), plus LVM
* Other: HFS+, APFS, UFS/FFS, ISO9660

Btrfs, ReFS, ZFS and encrypted volumes (BitLocker, LUKS) are detected and
labelled, but they can't be browsed. You can still export them as raw images
for other tools.

## Damaged disks

The browser never gives up on the first error. Unreadable data is replaced with
zeros and recorded in **Tools > Problems log**, so everything still intact can
be copied out. The disk image files are only ever opened read-only.

**VMDK**

* **Grain directory or table damaged:** falls back to the redundant copy that
  VMware keeps.
* **Truncated streamOptimized/OVA disk** (interrupted download or copy): the
  grain index is rebuilt by scanning the compressed grain markers.
* **Corrupt compressed grain:** whatever inflates is kept, and the rest is zeroed.
* **Descriptor `.vmdk` lost:** open `disk-s001.vmdk` and the split extents are
  reassembled automatically.
* **Paths in the descriptor point at another machine** (`/vmfs/volumes/...`,
  `C:\VMs\...`): the files are looked up next to the descriptor instead.

**VDI, VHD and VHDX**

* **VHD footer missing or damaged** (for example, a truncated copy): the copy
  of the footer at the start of dynamic disks is used.
* **VHDX header or region table damaged:** the second copy is used.
* **VHDX not closed cleanly** (host crash or power loss): pending metadata
  updates in its log are replayed in memory. The file itself isn't modified.
* **Fixed VDI with a damaged block map:** the disk is read with the linear
  layout that fixed disks always use.

**QCOW2**

* **L2 table pointer damaged:** the same table is looked up in the image's
  internal snapshots, so older data is returned instead of zeros.
* **Truncated, flagged dirty, or flagged corrupt by QEMU:** it is read anyway.
  Clusters past the end of the file and damaged compressed clusters are
  zero-filled.

**All formats**

* **Missing extent, parent or backing file:** only the areas the snapshot
  didn't change read as zeros. Data stored in the snapshot itself is still
  readable.
* **Damaged GPT:** the backup GPT at the end of the disk is used.
* **Wiped or destroyed partition table:** use **Deep scan** to find NTFS, FAT,
  exFAT, ext and XFS file systems by their signatures.
* **Damaged NTFS / FAT32 / exFAT boot sector:** the backup boot sector is used.
* **Damaged ext superblock:** a backup superblock is used.
* **Damaged LVM metadata:** older copies in the metadata ring buffer are tried.
* **Damaged directories or files:** partial listings are shown, and unreadable
  blocks are zero-filled.
* **Disk still unreadable:** **Tools > Export volume / disk as raw image**
  writes a plain `.img` for forensic tools.

Deleted files on NTFS, FAT and ext can be shown with the **Deleted** checkbox
and copied out (best effort).

## Using it

### GUI

Run `VirtualDiskBrowser.exe` (Windows) or `./virtualdiskbrowser` (Linux), then
**Open image** and pick the disk file. You can also drag a disk file onto the
program icon.

For snapshots, open the newest file in the chain: its parent or base disks are
found automatically.

* **Split or snapshot VMDKs:** pick the small descriptor `.vmdk`.
* **VirtualBox snapshots:** pick the `.vdi` in `Snapshots/`.
* **Differencing VHD/VHDX or QCOW2 overlays:** pick the child file.

In the main window:

* The left pane shows the disk, its partitions, LVM volumes and folders.
* Double-click a folder to open it, or a file to preview it (text, hex, PNG/GIF).
* Select files or folders, then **Copy to...** (or right-click). Ctrl+E also works.
* **Actions > Copy whole volume to...** extracts everything.
* **Open with default application** extracts the file to a temp folder and
  opens it.
* **Info** shows the format, block or grain size, parent chain, and partition
  and file system details.

### Command line

The Linux binary includes the CLI. On Windows, use `vdbrowser-cli.exe`.

```bash
vdbrowser-cli info disk.vhdx
```

```bash
vdbrowser-cli ls disk.vdi -p 1 /Users -r
```

```bash
vdbrowser-cli extract disk.vmdk -p 1 /Users/me/Documents -o ./recovered
```

```bash
vdbrowser-cli cat disk.qcow2 -p 2 /etc/fstab
```

```bash
vdbrowser-cli export disk.vhd -p 3 -o partition3.img
```

Options:

* `-p N`: volume number as listed by `info`.
* `--deep`: deep scan for lost partitions.
* `--rebuild-index`: rescan a streamOptimized VMDK instead of trusting its index.
* `-d`: include deleted entries.
* `-s`: include file-system metadata files (NTFS `$MFT` etc.) when extracting.
* `-v`: print the problems log.

## Running from source

```bash
pip install -r requirements.txt
```

```bash
python main.py
```

On Linux, tkinter has to be installed (`sudo apt install python3-tk`, or
`sudo dnf install python3-tkinter`).

## Building executables

The output is a single self-contained file. It doesn't need Python on the
target machine.

**Windows:** run `build_windows.bat`. It produces `dist\VirtualDiskBrowser.exe`
(GUI) and `dist\vdbrowser-cli.exe` (console).

**Linux, natively:** run `./build_linux.sh`. It produces
`dist/virtualdiskbrowser`. Build on the oldest distribution you need to
support, because the binary requires that glibc or newer.

**Linux, with Docker** (from any OS): run `./build_linux_docker.sh`. It builds
on Debian 11 (glibc 2.31) and produces `dist-linux/virtualdiskbrowser`, which
runs on Ubuntu 20.04+, Debian 11+, RHEL/Rocky/Alma 9+, Fedora and others.

PyInstaller can't cross-compile. Build the Windows exe on Windows and the Linux
binary on Linux or in Docker.

## Tests

The test images are built from real disks created with real tools:

* **`tests/make_test_images.sh`** (Docker): uses mkfs.ntfs, mkfs.vfat,
  mkfs.ext4, mkfs.xfs, LVM and qemu-img to build NTFS/FAT/ext4/XFS/LVM disks.
  It converts them into every VMDK sub-format, and then runs:
  * `make_qcow_images.sh` for the QCOW2 and QCOW variants;
  * `make_qemu_formats.sh` for the qemu-made VHD, VHDX and VDI variants.
* **`tests/make_vbox_images.sh`** (needs VirtualBox installed): builds VDI and
  VHD disks with `VBoxManage`, including differencing disks with data written
  through them. VirtualBox itself produces the reference output. It uses a
  throw-away `VBOX_USER_HOME`, so your VirtualBox registry isn't touched.

```bash
docker run --rm --privileged -v "$PWD/tests:/tests" debian:bookworm bash /tests/make_test_images.sh
```

```bash
bash tests/make_vbox_images.sh
```

```bash
python tests/test_images.py
```

The tests check:

* full-disk SHA-256 against the creating tool's own raw output (qemu-img or
  VirtualBox), for every format variant and snapshot chain
* file-by-file SHA-256 against manifests, for every file system
* recovery from truncated, corrupted and missing-file scenarios, including
  VHDX log replay

Differencing VHDX disks are implemented to the published specification but
aren't covered by the tests. No tool available here could create them: they
need Hyper-V.

## Layout

```
main.py                entry point (GUI, or CLI when a sub-command is given)
vdbrowser/disk.py      block-device primitives, zero-fill-on-error reads, problem log
vdbrowser/vmdk.py      VMDK descriptor/sparse/stream/COWD/flat readers, format detection
vdbrowser/vdi.py       VirtualBox VDI reader, snapshot parent lookup by UUID
vdbrowser/vhd.py       VHD and VHDX readers, VHDX log replay
vdbrowser/qcow.py      QCOW2 (v2/v3) and QCOW v1 reader, backing chains, snapshot fallback
vdbrowser/volumes.py   MBR/GPT/LVM2 parsing, file-system signatures, deep scan
vdbrowser/fs.py        Sleuth Kit (pytsk3) backend, boot-sector/superblock fallbacks
vdbrowser/xfs.py       read-only XFS driver
vdbrowser/core.py      session object, recursive extraction, raw export
vdbrowser/gui.py       tkinter interface
vdbrowser/cli.py       command line interface
```

## Licence notes

File system parsing for NTFS/FAT/ext/HFS uses The Sleuth Kit through `pytsk3`
(Apache 2.0 / IBM Public License / CPL). Keep those notices if you
redistribute the executables.
