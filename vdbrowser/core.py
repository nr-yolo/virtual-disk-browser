"""High level session object and file extraction used by both GUI and CLI."""

import os
import re
import sys
import time

from .disk import ErrorLog, fmt_size
from .vmdk import open_image
from .volumes import discover
from .fs import open_filesystem


class Session:
    """An opened disk image with its volumes and (lazily opened) file systems."""

    def __init__(self, path, deep=False, rebuild_stream_index=False, progress=None, cancel=None):
        self.path = path
        self.errors = ErrorLog()
        self.disk = open_image(path, self.errors, rebuild_stream_index=rebuild_stream_index)
        self.scheme, self.volumes = discover(self.disk, self.errors, deep=deep,
                                             progress=progress, cancel=cancel)
        self._fs = {}

    def all_volumes(self):
        out = []
        for v in self.volumes:
            out.append(v)
            out.extend(v.children)
        return out

    def filesystem(self, volume):
        key = id(volume)
        if key not in self._fs:
            try:
                self._fs[key] = open_filesystem(volume, self.errors)
            except Exception as e:  # noqa: BLE001
                self._fs[key] = e
        fs = self._fs[key]
        if isinstance(fs, Exception):
            raise fs
        return fs

    def rescan(self, deep=True, progress=None, cancel=None):
        self.scheme, self.volumes = discover(self.disk, self.errors, deep=deep,
                                             progress=progress, cancel=cancel)
        self._fs = {}

    def close(self):
        self.disk.close()


def resolve(fs, path):
    """Find an Entry by '/'-separated path (case-insensitive fallback)."""
    cur = fs.root()
    for part in [p for p in path.replace("\\", "/").split("/") if p]:
        children = fs.list_dir(cur)
        match = next((c for c in children if c.name == part and not c.deleted), None)
        if match is None:
            match = next((c for c in children if c.name.lower() == part.lower()), None)
        if match is None:
            raise FileNotFoundError(path)
        match.parent = cur
        cur = match
    return cur


def entry_path(entry):
    parts = []
    e = entry
    while e is not None and e.name:
        parts.append(e.name)
        e = e.parent
    return "/" + "/".join(reversed(parts))


# ---------------------------------------------------------------------------
# Extraction
# ---------------------------------------------------------------------------

_WIN_BAD = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
_WIN_RESERVED = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
                 *(f"LPT{i}" for i in range(1, 10))}


def safe_name(name):
    if not name or name in (".", ".."):
        name = "_"
    if sys.platform == "win32":
        name = _WIN_BAD.sub("_", name).rstrip(" .") or "_"
        if name.split(".")[0].upper() in _WIN_RESERVED:
            name = "_" + name
    else:
        name = name.replace("/", "_").replace("\0", "_")
    return name[:240]


class ExtractStats:
    def __init__(self):
        self.files = 0
        self.dirs = 0
        self.bytes = 0
        self.failed = 0
        self.skipped = 0
        self.current = ""

    def summary(self):
        s = f"{self.files} files, {self.dirs} folders, {fmt_size(self.bytes)}"
        if self.failed:
            s += f", {self.failed} failed"
        if self.skipped:
            s += f", {self.skipped} skipped"
        return s


def _unique(path, used):
    """Avoid collisions caused by case-insensitivity or name sanitising."""
    base, ext = os.path.splitext(path)
    cand = path
    n = 1
    while cand.lower() in used:
        cand = f"{base} ({n}){ext}"
        n += 1
    used.add(cand.lower())
    return cand


def extract(fs, entries, dest, errors, stats=None, progress=None, cancel=None,
            include_deleted=False, include_system=True):
    """Copy entries (files or directories, recursively) into folder ``dest``."""
    stats = stats or ExtractStats()
    os.makedirs(dest, exist_ok=True)
    used = set()
    visited = set()
    for e in entries:
        _extract_one(fs, e, dest, used, visited, errors, stats, progress, cancel,
                     include_deleted, include_system)
    return stats


def _extract_one(fs, e, dest_dir, used, visited, errors, stats, progress, cancel,
                 include_deleted, include_system):
    if cancel is not None and cancel.is_set():
        return
    target = _unique(os.path.join(dest_dir, safe_name(e.name)), used)
    stats.current = entry_path(e)
    if progress:
        progress(stats)
    try:
        if e.kind == "dir":
            key = (e.addr, e.deleted)
            if key in visited:
                errors.add(f"directory loop detected at {entry_path(e)} - skipped")
                return
            visited.add(key)
            os.makedirs(target, exist_ok=True)
            stats.dirs += 1
            child_used = set()
            for c in fs.list_dir(e):
                if c.deleted and not include_deleted:
                    continue
                if c.system and not include_system:
                    continue
                c.parent = e
                _extract_one(fs, c, target, child_used, visited, errors, stats, progress, cancel,
                             include_deleted, include_system)
        elif e.kind == "link":
            link = fs.readlink(e)
            done = False
            if link and sys.platform != "win32":
                try:
                    os.symlink(link, target)
                    done = True
                except OSError:
                    pass
            if not done:
                with open(target + ".symlink.txt", "w", encoding="utf-8") as f:
                    f.write(link or "")
            stats.files += 1
        elif e.kind == "file":
            with open(target, "wb") as f:
                for chunk in fs.iter_content(e, cancel=cancel):
                    f.write(chunk)
                    stats.bytes += len(chunk)
                    if progress:
                        progress(stats)
            stats.files += 1
        else:
            stats.skipped += 1
            return
        if e.mtime:
            try:
                os.utime(target, (e.atime or e.mtime, e.mtime), follow_symlinks=False)
            except (OSError, NotImplementedError, ValueError):
                pass
    except OSError as ex:
        stats.failed += 1
        errors.add(f"failed to extract {entry_path(e)}: {ex}")


def export_raw(image, dest_path, progress=None, cancel=None, chunk=4 << 20):
    """Write a (possibly damaged) volume or disk out as a plain raw image."""
    total = image.size
    done = 0
    with open(dest_path, "wb") as f:
        while done < total:
            if cancel is not None and cancel.is_set():
                break
            n = min(chunk, total - done)
            if image.is_allocated(done, n):
                data = image.read(done, n)
                if len(data) < n:
                    data += bytes(n - len(data))
                f.write(data)
            else:
                f.seek(n, 1)  # keep the output sparse where the source is empty
            done += n
            if progress:
                progress(done, total)
        f.truncate(done)
    return done


def fmt_time(ts):
    if not ts:
        return ""
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except (OverflowError, OSError, ValueError):
        return str(ts)
