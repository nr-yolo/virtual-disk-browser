"""File-system access layer.

Uses The Sleuth Kit (pytsk3) for NTFS, FAT12/16/32, exFAT, ext2/3/4, HFS+,
APFS, UFS and ISO9660, plus the built-in XFS reader.  All reads are
damage tolerant: unreadable parts of a file are zero-filled and reported.
"""

import threading

from .disk import SECTOR

try:
    import pytsk3
except ImportError:  # pragma: no cover - reported in the UI
    pytsk3 = None

TSK_LOCK = threading.RLock()


class Entry:
    __slots__ = ("name", "addr", "kind", "size", "mtime", "atime", "ctime", "crtime",
                 "deleted", "system", "parent", "extra")

    def __init__(self, name, addr, kind, size=0, mtime=0, atime=0, ctime=0, crtime=0,
                 deleted=False, system=False, extra=None):
        self.name = name
        self.addr = addr
        self.kind = kind            # "dir", "file", "link", "other"
        self.size = size
        self.mtime = mtime
        self.atime = atime
        self.ctime = ctime
        self.crtime = crtime
        self.deleted = deleted
        self.system = system
        self.parent = None
        self.extra = extra

    @property
    def is_dir(self):
        return self.kind == "dir"

    def __repr__(self):
        return f"<Entry {self.name!r} {self.kind} {self.size}>"


class FileSystem:
    """Interface implemented by every file-system backend."""

    type_name = "?"
    label = ""

    def root(self):
        raise NotImplementedError

    def list_dir(self, entry):
        raise NotImplementedError

    def read(self, entry, offset, length):
        raise NotImplementedError

    def readlink(self, entry):
        return None

    def iter_content(self, entry, chunk=1 << 20, cancel=None):
        """Yield the file's bytes in chunks; damaged regions are zero-filled."""
        off = 0
        size = entry.size
        while off < size:
            if cancel is not None and cancel.is_set():
                return
            n = min(chunk, size - off)
            yield self.read(entry, off, n)
            off += n

    def info(self):
        return [("File system", self.type_name), ("Label", self.label or "-")]


# ---------------------------------------------------------------------------
# Sleuth Kit backend
# ---------------------------------------------------------------------------

if pytsk3 is not None:
    class _TskImg(pytsk3.Img_Info):
        def __init__(self, image):
            self._image = image
            super().__init__(url="", type=pytsk3.TSK_IMG_TYPE_EXTERNAL)

        def read(self, offset, size):
            data = self._image.read(offset, size)
            if len(data) < size:
                data += bytes(size - len(data))
            return data

        def get_size(self):
            return self._image.size

        def close(self):
            pass

    _TSK_NAMES = {}
    for _n in dir(pytsk3):
        if _n.startswith("TSK_FS_TYPE_") and not _n.endswith(("DETECT", "ENUM")):
            _TSK_NAMES[int(getattr(pytsk3, _n))] = _n[len("TSK_FS_TYPE_"):]


class TskFileSystem(FileSystem):
    def __init__(self, image, errors):
        if pytsk3 is None:
            raise RuntimeError("pytsk3 is not installed")
        self.image = image
        self.errors = errors
        with TSK_LOCK:
            self._img = _TskImg(image)
            self._fs = pytsk3.FS_Info(self._img, offset=0)
            ftype = int(self._fs.info.ftype)
        self.type_name = _TSK_NAMES.get(ftype, f"type {ftype}")
        self.is_ntfs = self.type_name == "NTFS"
        self.block_size = int(self._fs.info.block_size)
        self.label = ""
        self._open_cache = {}

    def root(self):
        e = Entry("", int(self._fs.info.root_inum), "dir")
        return e

    def _kind(self, f):
        name = f.info.name
        meta = f.info.meta
        t = None
        if meta is not None:
            t = meta.type
            if t == pytsk3.TSK_FS_META_TYPE_DIR:
                return "dir"
            if t == pytsk3.TSK_FS_META_TYPE_REG:
                return "file"
            if t == pytsk3.TSK_FS_META_TYPE_LNK:
                return "link"
        nt = name.type
        if nt == pytsk3.TSK_FS_NAME_TYPE_DIR:
            return "dir"
        if nt == pytsk3.TSK_FS_NAME_TYPE_REG:
            return "file"
        if nt == pytsk3.TSK_FS_NAME_TYPE_LNK:
            return "link"
        if t is None and nt in (pytsk3.TSK_FS_NAME_TYPE_UNDEF,):
            return "file"
        return "other"

    def list_dir(self, entry):
        out = []
        seen = set()
        with TSK_LOCK:
            try:
                d = self._fs.open_dir(inode=entry.addr)
            except (IOError, OSError) as e:
                self.errors.add(f"cannot open directory '{entry.name or '/'}': {e}")
                return out
            it = iter(d)
            while True:
                try:
                    f = next(it)
                except StopIteration:
                    break
                except (IOError, OSError) as e:
                    self.errors.add(f"directory '{entry.name or '/'}' is damaged - listing is incomplete ({e})")
                    break
                try:
                    raw = f.info.name.name
                    name = raw.decode("utf-8", "replace") if isinstance(raw, bytes) else str(raw)
                    if name in (".", ".."):
                        continue
                    meta = f.info.meta
                    deleted = bool(int(f.info.name.flags) & int(pytsk3.TSK_FS_NAME_FLAG_UNALLOC))
                    addr = int(meta.addr) if meta is not None else int(f.info.name.meta_addr)
                    kind = self._kind(f)
                    key = (name, addr, deleted)
                    if key in seen:
                        continue
                    seen.add(key)
                    e = Entry(name, addr, kind, deleted=deleted)
                    if meta is not None:
                        e.size = int(meta.size) if kind != "dir" else 0
                        e.mtime = int(meta.mtime or 0)
                        e.atime = int(meta.atime or 0)
                        e.ctime = int(meta.ctime or 0)
                        e.crtime = int(meta.crtime or 0)
                        if kind == "link":
                            try:
                                lk = meta.link
                                if lk:
                                    e.extra = lk.decode("utf-8", "replace") if isinstance(lk, bytes) else str(lk)
                            except Exception:  # noqa: BLE001
                                pass
                    virtual = f.info.name.type in (pytsk3.TSK_FS_NAME_TYPE_VIRT,
                                                   pytsk3.TSK_FS_NAME_TYPE_VIRT_DIR) or (
                        meta is not None and meta.type in (pytsk3.TSK_FS_META_TYPE_VIRT,
                                                           pytsk3.TSK_FS_META_TYPE_VIRT_DIR))
                    # TSK's virtual helpers ($MBR, $FAT1, $OrphanFiles ...) are metadata, not user files
                    e.system = virtual or (name.startswith("$") and self.is_ntfs) or name in (
                        "$OrphanFiles", "System Volume Information") or name.endswith("(Volume Label Entry)")
                    e.parent = entry
                    out.append(e)
                except Exception as ex:  # noqa: BLE001 - skip unreadable entries, keep the rest
                    self.errors.add(f"skipped damaged entry in '{entry.name or '/'}': {ex}")
        return out

    def _file(self, entry):
        f = self._open_cache.get(entry.addr)
        if f is None:
            f = self._fs.open_meta(inode=entry.addr)
            if len(self._open_cache) > 64:
                self._open_cache.clear()
            self._open_cache[entry.addr] = f
        return f

    def read(self, entry, offset, length):
        if offset >= entry.size:
            return b""
        length = min(length, entry.size - offset)
        with TSK_LOCK:
            try:
                f = self._file(entry)
            except (IOError, OSError) as e:
                self.errors.add(f"cannot open '{entry.name}': {e} - content replaced with zeros",
                                key=("open", entry.addr))
                return bytes(length)
            try:
                data = f.read_random(offset, length)
            except (IOError, OSError):
                data = self._salvage(f, entry, offset, length)
        if len(data) < length:
            self.errors.add(f"'{entry.name}': only {offset + len(data)} of {entry.size} bytes readable - "
                            "rest zero-filled", key=("short", entry.addr))
            data += bytes(length - len(data))
        return data

    def _salvage(self, f, entry, offset, length):
        step = max(self.block_size, 4096)
        out = bytearray()
        pos = offset
        end = offset + length
        bad = 0
        while pos < end:
            n = min(step, end - pos)
            try:
                piece = f.read_random(pos, n)
            except (IOError, OSError):
                piece = b""
            if len(piece) < n:
                bad += n - len(piece)
                piece += bytes(n - len(piece))
            out += piece
            pos += n
        if bad:
            self.errors.add(f"'{entry.name}': {bad} unreadable bytes near offset {offset} zero-filled",
                            key=("salvage", entry.addr, offset // (16 << 20)))
        return bytes(out)

    def readlink(self, entry):
        if entry.extra:
            return entry.extra
        if entry.kind == "link" and 0 < entry.size < 4096:
            return self.read(entry, 0, entry.size).decode("utf-8", "replace")
        return None

    def info(self):
        i = self._fs.info
        rows = [("File system", self.type_name), ("Block size", str(self.block_size)),
                ("Blocks", f"{int(i.block_count):,}"), ("Inodes", f"{int(i.inum_count):,}")]
        return rows


def open_filesystem(volume, errors):
    """Open the file system in ``volume``; returns FileSystem or raises."""
    hint = volume.fs_hint or ""
    if hint == "XFS":
        from .xfs import XfsFileSystem
        return XfsFileSystem(volume.image, errors)
    if hint in ("LVM2 PV", "Linux swap", "LUKS (encrypted)", "BitLocker (encrypted)"):
        raise RuntimeError(f"{hint} does not contain a browsable file system"
                           + (" - expand it to see its logical volumes" if hint == "LVM2 PV" else ""))
    try:
        return TskFileSystem(volume.image, errors)
    except Exception as e:  # noqa: BLE001
        first = e
    # TSK refused: try again from a backup boot sector / superblock where we can
    alt = _try_backup_boot(volume, errors)
    if alt is not None:
        return alt
    msg = str(first).strip().splitlines()[0] if str(first).strip() else type(first).__name__
    raise RuntimeError(f"Unable to open file system ({hint or 'unknown type'}): {msg}")


class _PatchedImage:
    """Overlay that substitutes the first sector(s) of an image (backup boot sector repair)."""

    def __init__(self, base, patch_off, patch):
        self.base = base
        self.size = base.size
        self.errors = base.errors
        self.patch_off = patch_off
        self.patch = patch

    def read(self, offset, length):
        data = bytearray(self.base.read(offset, length))
        a = max(offset, self.patch_off)
        b = min(offset + length, self.patch_off + len(self.patch))
        if a < b:
            data[a - offset:b - offset] = self.patch[a - self.patch_off:b - self.patch_off]
        return bytes(data)

    def is_allocated(self, offset, length):
        return self.base.is_allocated(offset, length)


def _try_backup_boot(volume, errors):
    img = volume.image
    candidates = []
    # NTFS keeps a copy of the boot sector in the last sector of the volume
    last = img.read(img.size - SECTOR, SECTOR)
    if last[3:11] == b"NTFS    ":
        candidates.append(("NTFS backup boot sector", 0, last))
    # FAT32 keeps a backup boot sector at sector 6
    s6 = img.read(6 * SECTOR, SECTOR)
    if s6[82:87] == b"FAT32" and s6[510:512] == b"\x55\xaa":
        candidates.append(("FAT32 backup boot sector", 0, s6))
    # exFAT: backup boot region starts at sector 12
    s12 = img.read(12 * SECTOR, SECTOR)
    if s12[3:11] == b"EXFAT   ":
        candidates.append(("exFAT backup boot sector", 0, s12))
    for what, off, patch in candidates:
        try:
            fs = TskFileSystem(_PatchedImage(img, off, patch), errors)
            errors.add(f"{volume.label}: primary boot sector damaged - opened using {what}")
            return fs
        except Exception:  # noqa: BLE001
            continue
    # ext*: try backup superblocks (block groups 1, 3, 5, 7, 9 for common sizes)
    for bs in (4096, 1024, 2048):
        for group in (1, 3, 5, 7, 9):
            per_group = bs * 8
            sb_off = group * per_group * bs + (1024 if bs == 1024 else 0)
            sb = img.read(sb_off, 1024)
            if sb[56:58] != b"\x53\xef":
                continue
            patch = bytearray(sb)
            # the backup's block_group_nr field must be zeroed to look primary
            patch[90:92] = b"\0\0"
            try:
                fs = TskFileSystem(_PatchedImage(img, 1024, bytes(patch)), errors)
                errors.add(f"{volume.label}: ext superblock damaged - opened using backup "
                           f"superblock from group {group}")
                return fs
            except Exception:  # noqa: BLE001
                continue
    return None
