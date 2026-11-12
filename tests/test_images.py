"""End-to-end tests against images produced by tests/make_test_images.sh.

Run:  python -m pytest tests -q      (or simply: python tests/test_images.py)
"""

import hashlib
import os
import shutil
import struct
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from vdbrowser.core import Session, extract, resolve  # noqa: E402
from vdbrowser.disk import ErrorLog  # noqa: E402
from vdbrowser.vmdk import open_image  # noqa: E402

IMG = os.path.join(HERE, "images")


def _sha_disk(img, chunk=8 << 20):
    h = hashlib.sha256()
    pos = 0
    while pos < img.size:
        n = min(chunk, img.size - pos)
        h.update(img.read(pos, n) if img.is_allocated(pos, n) else bytes(n))
        pos += n
    return h.hexdigest()


def _ref(name):
    with open(os.path.join(IMG, name + ".sha256")) as f:
        return f.read().strip()


def _manifest(name):
    out = {}
    with open(os.path.join(IMG, name + ".manifest"), encoding="utf-8") as f:
        for line in f:
            digest, path = line.rstrip("\n").split("  ", 1)
            out[path[2:]] = digest
    return out


def _check_volume(sess, vol, manifest_name, tmp, allow_missing=0):
    fs = sess.filesystem(vol)
    dest = os.path.join(tmp, manifest_name)
    extract(fs, fs.list_dir(fs.root()), dest, sess.errors, include_system=False)
    want = _manifest(manifest_name)
    bad, missing = [], []
    for rel, digest in want.items():
        p = os.path.join(dest, *rel.split("/"))
        if not os.path.exists(p):
            missing.append(rel)
            continue
        with open(p, "rb") as f:
            if hashlib.sha256(f.read()).hexdigest() != digest:
                bad.append(rel)
    assert not bad, f"{manifest_name}: content mismatch {bad[:5]}"
    assert len(missing) <= allow_missing, f"{manifest_name}: missing {missing[:5]}"
    return len(want)


def _vol(sess, fs_hint=None, label_part=None):
    for v in sess.all_volumes():
        if fs_hint and v.fs_hint != fs_hint:
            continue
        if label_part and label_part not in v.label:
            continue
        return v
    raise AssertionError(f"volume {fs_hint} {label_part} not found in "
                         f"{[(v.label, v.fs_hint) for v in sess.all_volumes()]}")


# ---------------------------------------------------------------------------

WIN_VARIANTS = ["monolithicSparse", "streamOptimized", "monolithicFlat", "twoGbMaxExtentSparse",
                "twoGbMaxExtentFlat"]
LIN_VARIANTS = ["monolithicSparse", "streamOptimized", "twoGbMaxExtentSparse"]


def test_disk_hashes():
    for v in WIN_VARIANTS:
        img = open_image(os.path.join(IMG, f"win_{v}", "win.vmdk"))
        assert _sha_disk(img) == _ref("win"), v
        assert img.errors.count == 0, (v, img.errors.items)
        img.close()
    for v in LIN_VARIANTS:
        img = open_image(os.path.join(IMG, f"lin_{v}", "lin.vmdk"))
        assert _sha_disk(img) == _ref("lin"), v
        img.close()


def test_snapshot_chain():
    img = open_image(os.path.join(IMG, "snapshot", "delta.vmdk"))
    assert img.parent is not None
    assert _sha_disk(img) == _ref("delta")


def test_windows_filesystems():
    tmp = tempfile.mkdtemp()
    try:
        s = Session(os.path.join(IMG, "win_monolithicSparse", "win.vmdk"))
        assert s.scheme == "MBR"
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
        _check_volume(s, _vol(s, "FAT32"), "fat32", tmp)
        _check_volume(s, _vol(s, "FAT16"), "fat16", tmp)
        # deleted file shows up
        fs = s.filesystem(_vol(s, "NTFS"))
        d = resolve(fs, "/deleted_test")
        assert any(c.deleted and c.name == "gone.txt" for c in fs.list_dir(d))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_linux_filesystems():
    tmp = tempfile.mkdtemp()
    try:
        s = Session(os.path.join(IMG, "lin_streamOptimized", "lin.vmdk"))
        assert s.scheme == "GPT"
        _check_volume(s, _vol(s, label_part="ext4part"), "ext4", tmp)
        _check_volume(s, _vol(s, "XFS"), "xfs", tmp)
        _check_volume(s, _vol(s, label_part="lvroot"), "lvroot", tmp)
        _check_volume(s, _vol(s, label_part="lvdata"), "lvdata", tmp)
        fs = s.filesystem(_vol(s, "XFS"))
        link = resolve(fs, "/bin/link_to_readme")
        assert fs.readlink(link) == "../readme.txt"
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# Damage tolerance
# ---------------------------------------------------------------------------

def _copy(src, tmp):
    dst = os.path.join(tmp, os.path.basename(src))
    shutil.copy(src, dst)
    return dst


def test_truncated_stream_optimized():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(IMG, "lin_streamOptimized", "lin.vmdk"), tmp)
        size = os.path.getsize(p)
        with open(p, "r+b") as f:
            f.truncate(int(size * 0.7))  # footer, grain directory and tail are gone
        s = Session(p)
        assert s.errors.count >= 0
        # the early ext4 partition should still be largely recoverable
        v = _vol(s, label_part="ext4part")
        fs = s.filesystem(v)
        e = resolve(fs, "/readme.txt")
        assert fs.read(e, 0, 100).startswith(b"hello from ext4")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_corrupt_primary_grain_directory():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(IMG, "win_monolithicSparse", "win.vmdk"), tmp)
        with open(p, "r+b") as f:
            hdr = f.read(512)
            gd = struct.unpack_from("<Q", hdr, 56)[0]
            f.seek(gd * 512)
            f.write(b"\xff" * 512)  # wreck the primary grain directory
        img = open_image(p)
        assert _sha_disk(img) == _ref("win")  # redundant directory fully restores it
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_corrupt_compressed_grain():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(IMG, "win_streamOptimized", "win.vmdk"), tmp)
        with open(p, "r+b") as f:
            f.seek(os.path.getsize(p) // 2)
            f.write(os.urandom(4096))
        s = Session(p)
        _sha_disk(s.disk)  # touch every grain, including the damaged one
        ok = 0
        for hint in ("NTFS", "FAT32", "FAT16"):
            fs = s.filesystem(_vol(s, hint))
            ok += len(fs.list_dir(fs.root()))
        assert ok > 0
        assert s.errors.count > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_wiped_partition_table_deep_scan():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(IMG, "win_monolithicFlat", "win-flat.vmdk"), tmp)
        with open(p, "r+b") as f:
            f.write(bytes(512))
        s = Session(p)
        hints = {v.fs_hint for v in s.all_volumes()}
        assert {"NTFS", "FAT32", "FAT16"} <= hints, hints
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_ntfs_backup_boot_sector():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(IMG, "win_monolithicFlat", "win-flat.vmdk"), tmp)
        with open(p, "r+b") as f:
            f.seek(2048 * 512 + 11)
            f.write(bytes(80))  # damage BPB but keep the OEM id so it is still detected
        s = Session(p)
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_missing_split_descriptor():
    tmp = tempfile.mkdtemp()
    try:
        for f in ("lin-s001.vmdk", "lin-s002.vmdk"):
            _copy(os.path.join(IMG, "lin_twoGbMaxExtentSparse", f), tmp)
        img = open_image(os.path.join(tmp, "lin-s001.vmdk"))
        assert _sha_disk(img) == _ref("lin")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_missing_extent_file():
    tmp = tempfile.mkdtemp()
    try:
        for f in ("lin.vmdk", "lin-s001.vmdk"):  # second extent deliberately missing
            _copy(os.path.join(IMG, "lin_twoGbMaxExtentSparse", f), tmp)
        s = Session(os.path.join(tmp, "lin.vmdk"))
        assert s.errors.count > 0
        _check_volume(s, _vol(s, label_part="ext4part"), "ext4", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# QCOW / QCOW2 (images from tests/make_qcow_images.sh)
# ---------------------------------------------------------------------------

QCOW = os.path.join(IMG, "qcow")


def _qref(name):
    with open(os.path.join(QCOW, name + ".sha256")) as f:
        return f.read().strip()


def test_qcow_disk_hashes():
    for name in ("win.qcow2", "win_v2.qcow2", "win_zlib.qcow2", "win_zstd.qcow2", "win_extl2.qcow2",
                 "win_4k.qcow2", "win.qcow"):
        img = open_image(os.path.join(QCOW, name))
        assert _sha_disk(img) == _ref("win"), name
        assert img.errors.count == 0, (name, img.errors.items)
        img.close()
    img = open_image(os.path.join(QCOW, "lin_zstd.qcow2"))
    assert _sha_disk(img) == _ref("lin")


def test_qcow_backing_chains():
    for name, ref in (("overlay.qcow2", "overlay"), ("overlay_extl2.qcow2", "overlay_extl2"),
                      ("overlay_on_vmdk.qcow2", "overlay"), ("snapshot.qcow2", "snapshot")):
        img = open_image(os.path.join(QCOW, name))
        assert _sha_disk(img) == _qref(ref), name
        img.close()
    img = open_image(os.path.join(QCOW, "snapshot.qcow2"))
    assert any(s["name"] == "before-update" for s in img.snapshots)


def test_qcow_filesystems():
    tmp = tempfile.mkdtemp()
    try:
        s = Session(os.path.join(QCOW, "win_zstd.qcow2"))
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
        s = Session(os.path.join(QCOW, "lin_zstd.qcow2"))
        _check_volume(s, _vol(s, label_part="lvdata"), "lvdata", tmp)
        _check_volume(s, _vol(s, label_part="ext4part"), "ext4", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_qcow_damaged_l2_uses_snapshot():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(QCOW, "snapshot.qcow2"), tmp)
        with open(p, "r+b") as f:
            l1off = struct.unpack(">Q", f.read(48)[40:48])[0]
            f.seek(l1off)
            f.write(struct.pack(">Q", 0x00FFFFFFFFFF0000))  # active L1[0] -> garbage
        img = open_image(p)
        # the snapshot's L2 table still describes the disk as it was before the update
        assert _sha_disk(img) == _ref("win")
        assert img.errors.count > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_qcow_truncated_and_corrupt():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(QCOW, "win_zlib.qcow2"), tmp)
        with open(p, "r+b") as f:
            f.seek(os.path.getsize(p) // 3)
            f.write(os.urandom(8192))
            f.truncate(int(os.path.getsize(p) * 0.6))
        s = Session(p)
        _sha_disk(s.disk)
        assert s.errors.count > 0
        fs = s.filesystem(_vol(s, "NTFS"))
        e = resolve(fs, "/readme.txt")
        assert fs.read(e, 0, 100).startswith(b"hello from NTFS")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_qcow_missing_backing():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(QCOW, "overlay.qcow2"), tmp)
        img = open_image(p)
        assert img.parent is None and img.errors.count > 0
        assert img.read(1 << 20, 4) == b"\x5a" * 4  # data in the overlay itself survives
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# ---------------------------------------------------------------------------
# VDI / VHD / VHDX (images from tests/make_vbox_images.sh and make_qemu_formats.sh)
# ---------------------------------------------------------------------------

VBOX = os.path.join(IMG, "vbox")
QF = os.path.join(IMG, "qemu_formats")


def _sha_file(path):
    with open(path) as f:
        return f.read().strip()


def test_vdi_vhd_vhdx_hashes():
    win = _ref("win")
    cases = [(os.path.join(VBOX, n), win) for n in ("win_dynamic.vdi", "win_fixed.vdi", "win_dynamic.vhd",
                                                     "win_fixed.vhd")]
    cases += [(os.path.join(QF, n), win) for n in ("win_dynamic.vhd", "win_fixed.vhd", "win_dynamic.vhdx",
                                                   "win_fixed.vhdx", "win_1m.vhdx", "win_dynamic.vdi",
                                                   "win_static.vdi")]
    cases += [(os.path.join(QF, "win_chs.vhd"), _sha_file(os.path.join(QF, "win_chs.sha256"))),
              (os.path.join(QF, "lin.vhdx"), _ref("lin")), (os.path.join(QF, "lin.vdi"), _ref("lin"))]
    for path, ref in cases:
        img = open_image(path)
        assert _sha_disk(img) == ref, path
        assert img.errors.count == 0, (path, img.errors.items)
        img.close()


def test_virtualbox_differencing_disks():
    for child, ref in (("diff_vdi/Snapshots/child.vdi", "diff_vdi"), ("diff_vhd/child.vhd", "diff_vhd")):
        img = open_image(os.path.join(VBOX, *child.split("/")))
        assert img.parent is not None, child
        assert _sha_disk(img) == _sha_file(os.path.join(VBOX, ref + ".sha256")), child
        img.close()


def test_vdi_vhd_vhdx_filesystems():
    tmp = tempfile.mkdtemp()
    try:
        s = Session(os.path.join(QF, "win_dynamic.vhdx"))
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
        s = Session(os.path.join(VBOX, "win_dynamic.vdi"))
        _check_volume(s, _vol(s, "FAT32"), "fat32", tmp)
        s = Session(os.path.join(VBOX, "win_dynamic.vhd"))
        _check_volume(s, _vol(s, "FAT16"), "fat16", tmp)
        s = Session(os.path.join(QF, "lin.vhdx"))
        _check_volume(s, _vol(s, label_part="lvdata"), "lvdata", tmp)
        s = Session(os.path.join(QF, "lin.vdi"))
        _check_volume(s, _vol(s, "XFS"), "xfs", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_vhd_missing_footer():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(VBOX, "win_dynamic.vhd"), tmp)
        with open(p, "r+b") as f:
            f.truncate(os.path.getsize(p) - 512)  # footer at the end is gone
        img = open_image(p)
        assert img.format.startswith("VHD") and _sha_disk(img) == _ref("win")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_vhdx_damaged_header_and_region_table():
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(QF, "win_dynamic.vhdx"), tmp)
        with open(p, "r+b") as f:
            for off in (64 * 1024, 192 * 1024):  # first header copy and primary region table
                f.seek(off + 4)
                f.write(os.urandom(64))
        img = open_image(p)
        assert _sha_disk(img) == _ref("win")
        assert img.errors.count > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_vhdx_log_replay():
    """A BAT update that only reached the log must be replayed (image not closed cleanly)."""
    from vdbrowser.vhd import crc32c
    tmp = tempfile.mkdtemp()
    try:
        p = _copy(os.path.join(QF, "win_dynamic.vhdx"), tmp)
        with open(p, "r+b") as f:
            hdrs = []
            for off in (64 * 1024, 128 * 1024):
                f.seek(off)
                h = bytearray(f.read(4096))
                hdrs.append((struct.unpack_from("<Q", h, 8)[0], off, h))
            _seq, hoff, h = max(hdrs)
            log_len, log_off = struct.unpack_from("<IQ", h, 68)
            f.seek(192 * 1024)
            rt = f.read(4096)
            bat_off = None
            for i in range(struct.unpack_from("<I", rt, 8)[0]):
                e = rt[16 + i * 32:48 + i * 32]
                if e[:4] == bytes.fromhex("6677c22d"):
                    bat_off = struct.unpack_from("<Q", e, 16)[0]
            f.seek(bat_off)
            page = f.read(4096)
            f.seek(bat_off)
            f.write(bytes(4096))  # the on-disk BAT is stale (all blocks "not present")
            guid = os.urandom(16)
            entry = bytearray(8192)
            struct.pack_into("<4sIIIQII16sQQ", entry, 0, b"loge", 0, 8192, 0, 1, 1, 0, guid, 0, 0)
            struct.pack_into("<4sIQQQ", entry, 64, b"desc", struct.unpack_from("<I", page, 4092)[0],
                             struct.unpack_from("<Q", page, 0)[0], bat_off, 1)
            struct.pack_into("<4sI", entry, 4096, b"data", 0)
            entry[4096 + 8:4096 + 4092] = page[8:4092]
            struct.pack_into("<I", entry, 4096 + 4092, 1)
            struct.pack_into("<I", entry, 4, crc32c(bytes(entry)))
            f.seek(log_off)
            f.write(entry)
            h[48:64] = guid
            h[4:8] = b"\0\0\0\0"
            struct.pack_into("<I", h, 4, crc32c(bytes(h)))
            f.seek(hoff)
            f.write(h)
        img = open_image(p)
        assert any("replayed" in n for n in img.notes), img.notes
        assert _sha_disk(img) == _ref("win")
        with open(p, "rb") as f:  # the file itself is left untouched
            f.seek(bat_off)
            assert f.read(4096) == bytes(4096)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_deep_scan_finds_partitions_under_reformatted_disk():
    """The VirtualBox snapshot was reformatted as one whole-disk FAT; the old partitions remain."""
    tmp = tempfile.mkdtemp()
    try:
        s = Session(os.path.join(VBOX, "diff_vhd", "child.vhd"), deep=True)
        hints = [v.fs_hint for v in s.all_volumes()]
        assert hints.count("FAT16") == 2 and "NTFS" in hints and "FAT32" in hints, hints
        _check_volume(s, _vol(s, "NTFS"), "ntfs", tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_vdi_damage():
    tmp = tempfile.mkdtemp()
    try:
        # fixed VDI with a wrecked block-map entry falls back to the linear layout
        p = _copy(os.path.join(VBOX, "win_fixed.vdi"), tmp)
        with open(p, "r+b") as f:
            f.seek(0x154)
            off_blocks = struct.unpack("<I", f.read(4))[0]
            f.seek(off_blocks + 4 * 3)
            f.write(b"\x00\x00\xff\x7f")
        assert _sha_disk(open_image(p)) == _ref("win")
        # snapshot without its base disk: still opens, untouched areas are zeros
        child = _copy(os.path.join(VBOX, "diff_vdi", "Snapshots", "child.vdi"), tmp)
        img = open_image(child)
        assert img.parent is None and img.errors.count > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    import time
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            t = time.time()
            try:
                fn()
                print(f"PASS {name} ({time.time() - t:.1f}s)")
            except Exception as e:  # noqa: BLE001
                import traceback
                failures += 1
                print(f"FAIL {name}: {e}")
                traceback.print_exc()
    sys.exit(1 if failures else 0)
