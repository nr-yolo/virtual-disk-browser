"""Generic, corruption-tolerant block device abstractions.

Every image object exposes ``size`` and ``read(offset, length)``.  Reads never
raise for damaged or missing data: unreadable regions are returned as zeros and
recorded in a shared :class:`ErrorLog`, so higher layers (partition tables,
file systems) can keep going and salvage whatever is still intact.
"""

import os
import threading
from collections import OrderedDict

SECTOR = 512


class ErrorLog:
    """Collects (de-duplicated) problems found while reading an image."""

    def __init__(self, limit=2000):
        self.limit = limit
        self.items = []
        self.count = 0
        self._keys = set()
        self._lock = threading.Lock()

    def add(self, msg, key=None):
        with self._lock:
            if key is not None:
                if key in self._keys:
                    return
                self._keys.add(key)
            self.count += 1
            if len(self.items) < self.limit:
                self.items.append(msg)

    def __len__(self):
        return self.count


class LRUCache:
    def __init__(self, capacity):
        self.capacity = capacity
        self._d = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key):
        with self._lock:
            v = self._d.get(key)
            if v is not None:
                self._d.move_to_end(key)
            return v

    def put(self, key, value):
        with self._lock:
            self._d[key] = value
            self._d.move_to_end(key)
            while len(self._d) > self.capacity:
                self._d.popitem(last=False)


class SafeFile:
    """Thread-safe positional reads that zero-fill past EOF or on I/O errors."""

    def __init__(self, path, errors):
        self.path = path
        self.errors = errors
        self._f = open(path, "rb")
        self.size = os.fstat(self._f.fileno()).st_size
        self._lock = threading.Lock()

    def _raw(self, offset, length):
        with self._lock:
            self._f.seek(offset)
            return self._f.read(length)

    def pread(self, offset, length, what="data"):
        if length <= 0:
            return b""
        if offset >= self.size:
            self.errors.add(
                f"{os.path.basename(self.path)}: {what} at offset {offset} lies beyond end of file "
                f"({self.size} bytes) - file truncated? zeros substituted",
                key=(self.path, "eof", offset // (1 << 20)))
            return bytes(length)
        try:
            data = self._raw(offset, length)
        except OSError:
            data = self._salvage(offset, length)
        if len(data) < length:
            self.errors.add(
                f"{os.path.basename(self.path)}: short read of {what} at offset {offset} "
                f"(file truncated?) - zeros substituted",
                key=(self.path, "short", offset // (1 << 20)))
            data += bytes(length - len(data))
        return data

    def _salvage(self, offset, length, chunk=4096):
        """Read sector-sized pieces around a failing region of the host file."""
        out = bytearray()
        pos = offset
        end = offset + length
        while pos < end:
            n = min(chunk, end - pos)
            try:
                piece = self._raw(pos, n)
            except OSError as e:
                self.errors.add(f"{os.path.basename(self.path)}: I/O error at {pos}: {e}",
                                key=(self.path, "io", pos))
                piece = bytes(n)
            if not piece:
                break
            out += piece
            pos += len(piece)
        return bytes(out)

    def close(self):
        try:
            self._f.close()
        except OSError:
            pass


class DiskImage:
    """Base class: a readable virtual block device."""

    size = 0
    name = ""

    def __init__(self, errors=None):
        self.errors = errors if errors is not None else ErrorLog()

    def read(self, offset, length):
        if offset < 0:
            length += offset
            offset = 0
        if length <= 0 or offset >= self.size:
            return b""
        length = min(length, self.size - offset)
        return self._read(offset, length)

    def _read(self, offset, length):
        raise NotImplementedError

    def is_allocated(self, offset, length):
        """False only when the range is known to contain nothing but zeros."""
        return True

    def info(self):
        """List of (label, value) pairs describing the image."""
        return [("Size", fmt_size(self.size))]

    def close(self):
        pass


class ZeroImage(DiskImage):
    def __init__(self, size, errors=None, name="zero"):
        super().__init__(errors)
        self.size = size
        self.name = name

    def _read(self, offset, length):
        return bytes(length)

    def is_allocated(self, offset, length):
        return False


class RawImage(DiskImage):
    """A flat file (raw .img/.dd, -flat.vmdk, FLAT extents)."""

    def __init__(self, path, errors=None, file_offset=0, size=None):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.file = SafeFile(path, self.errors)
        self.file_offset = file_offset
        self.size = size if size is not None else max(0, self.file.size - file_offset)
        if file_offset + self.size > self.file.size:
            self.errors.add(f"{self.name}: file is {self.file.size} bytes but "
                            f"{file_offset + self.size} expected - missing tail is read as zeros")

    def _read(self, offset, length):
        return self.file.pread(self.file_offset + offset, length)

    def info(self):
        return [("Format", "Raw / flat"), ("File", self.path), ("Size", fmt_size(self.size))]

    def close(self):
        self.file.close()


class SliceImage(DiskImage):
    """A window into another image (a partition)."""

    def __init__(self, parent, offset, size, name=""):
        super().__init__(parent.errors)
        self.parent = parent
        self.offset = offset
        self.size = max(0, min(size, parent.size - offset))
        self.name = name

    def _read(self, offset, length):
        return self.parent.read(self.offset + offset, length)

    def is_allocated(self, offset, length):
        return self.parent.is_allocated(self.offset + offset, length)


class ConcatImage(DiskImage):
    """Concatenation of extents: list of (length, image) in order."""

    def __init__(self, parts, errors=None, name=""):
        super().__init__(errors)
        self.name = name
        self.parts = []  # (start, length, image)
        pos = 0
        for length, img in parts:
            self.parts.append((pos, length, img))
            pos += length
        self.size = pos

    def _iter(self, offset, length):
        end = offset + length
        for start, plen, img in self.parts:
            pend = start + plen
            if pend <= offset or start >= end:
                continue
            a = max(offset, start)
            b = min(end, pend)
            yield img, a - start, b - a

    def _read(self, offset, length):
        out = bytearray()
        for img, local, n in self._iter(offset, length):
            data = img.read(local, n)
            if len(data) < n:
                data += bytes(n - len(data))
            out += data
        return bytes(out)

    def is_allocated(self, offset, length):
        return any(img.is_allocated(local, n) for img, local, n in self._iter(offset, length))


class MappedImage(DiskImage):
    """Logical volume assembled from (logical_offset, length, image, image_offset) segments.

    Gaps between segments read as zeros."""

    def __init__(self, segments, size, errors=None, name=""):
        super().__init__(errors)
        self.segments = sorted(segments, key=lambda s: s[0])
        self.size = size
        self.name = name

    def _read(self, offset, length):
        out = bytearray(length)
        end = offset + length
        for lstart, slen, img, ioff in self.segments:
            send = lstart + slen
            if send <= offset or lstart >= end:
                continue
            a = max(offset, lstart)
            b = min(end, send)
            data = img.read(ioff + (a - lstart), b - a)
            out[a - offset:a - offset + len(data)] = data
        return bytes(out)

    def is_allocated(self, offset, length):
        end = offset + length
        for lstart, slen, img, ioff in self.segments:
            send = lstart + slen
            if send <= offset or lstart >= end:
                continue
            a = max(offset, lstart)
            b = min(end, send)
            if img.is_allocated(ioff + (a - lstart), b - a):
                return True
        return False


def fmt_size(n):
    if n is None:
        return "?"
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if n < 1024 or unit == "PB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024.0
