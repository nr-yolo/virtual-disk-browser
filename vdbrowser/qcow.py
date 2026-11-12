"""QCOW (v1) and QCOW2 (v2/v3) reader - QEMU/KVM, Proxmox, libvirt, GNS3 disks.

Supported
  * QCOW2 version 2 (compat=0.10) and version 3 (compat=1.1)
  * zlib and zstd compressed clusters
  * zero clusters, extended L2 entries (sub-clusters), external data files
  * backing-file chains (qcow2 / vmdk / raw backing images)
  * legacy QCOW version 1
  * internal snapshots are listed in the image information

Damage tolerance
  * L2 tables whose pointer is invalid are looked up in the internal snapshots'
    L1 tables instead (older data beats zeros), otherwise read as zeros
  * clusters beyond the end of a truncated file read as zeros
  * damaged compressed clusters are partially inflated, the rest zero-filled
  * a missing backing file only blanks the unallocated areas
"""

import os
import struct
import time
import zlib

from .disk import DiskImage, RawImage, SafeFile, ErrorLog, LRUCache, fmt_size

try:  # Python 3.14+
    from compression import zstd as _zstd_std
except ImportError:  # pragma: no cover
    _zstd_std = None
try:
    import zstandard as _zstd_pkg
except ImportError:  # pragma: no cover
    _zstd_pkg = None

QCOW_MAGIC = b"QFI\xfb"

L1_OFFSET_MASK = 0x00FFFFFFFFFFFE00
L2_OFFSET_MASK = 0x00FFFFFFFFFFFE00
QCOW_OFLAG_COPIED = 1 << 63
QCOW_OFLAG_COMPRESSED = 1 << 62
QCOW_OFLAG_ZERO = 1

INCOMPAT_DIRTY = 1 << 0
INCOMPAT_CORRUPT = 1 << 1
INCOMPAT_DATA_FILE = 1 << 2
INCOMPAT_COMPRESSION = 1 << 3
INCOMPAT_EXTL2 = 1 << 4

EXT_END = 0
EXT_BACKING_FORMAT = 0xE2792ACA
EXT_DATA_FILE = 0x44415441

# lookup results
UNALLOC, ZERO, DATA, COMP, BAD = range(5)


def is_qcow(head):
    return head[:4] == QCOW_MAGIC


class QcowImage(DiskImage):
    def __init__(self, path, errors=None, opener=None, depth=0):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.file = SafeFile(path, self.errors)
        self.data_file = self.file
        self.parent = None
        self.notes = []
        self.snapshots = []
        self.backing_name = None
        self.backing_format = None
        self.data_file_name = None
        self.compression = "zlib"
        self.extended_l2 = False
        self._l2_cache = LRUCache(4096)
        self._cluster_cache = LRUCache(64)
        self._snap_l1 = []
        self._open_backing = opener

        head = self.file.pread(0, 4096, "header")
        if not is_qcow(head):
            raise ValueError("not a QCOW image")
        self.version = struct.unpack_from(">I", head, 4)[0]
        if self.version == 1:
            self._init_v1(head)
        elif self.version in (2, 3):
            self._init_v2(head)
        else:
            raise ValueError(f"unsupported QCOW version {self.version}")
        self.format = "QCOW" if self.version == 1 else f"QCOW2 (v{self.version})"

        if self.crypt_method:
            raise ValueError("this QCOW image is encrypted (AES/LUKS) - encrypted images cannot be read "
                             "without the passphrase")

        if self.backing_name:
            self._attach_backing(depth)

    # -- headers -----------------------------------------------------------
    def _init_v1(self, h):
        (_m, _v, bfo, bfs, _mtime, size, cbits, l2bits, _pad, crypt, l1off) = \
            struct.unpack_from(">4sIQIIQBBHIQ", h)
        self.size = size
        self.cluster_bits = cbits
        self.cluster_size = 1 << cbits
        self.l2_entries = 1 << l2bits
        self.l2_bits = l2bits
        self.crypt_method = crypt
        span = self.cluster_size * self.l2_entries
        self.l1_size = (size + span - 1) // span
        self.l1_offset = l1off
        self.incompat = 0
        self.unit = self.cluster_size
        if bfo and bfs:
            self.backing_name = self.file.pread(bfo, bfs, "backing file name").decode("utf-8", "replace")
        self.l1 = self._read_l1(l1off, self.l1_size, "L1 table")

    def _init_v2(self, h):
        (bfo, bfs, cbits, size, crypt, l1_size, l1off, _rto, _rtc, nb_snap, snap_off) = \
            struct.unpack_from(">QIIQIIQQIIQ", h, 8)
        if not 9 <= cbits <= 21:
            raise ValueError(f"QCOW2 header is damaged (cluster_bits={cbits})")
        self.size = size
        self.cluster_bits = cbits
        self.cluster_size = 1 << cbits
        self.crypt_method = crypt
        self.l1_offset = l1off
        hdr_len = 72
        self.incompat = 0
        comp_type = 0
        if self.version >= 3:
            self.incompat, compat, autoclear, _rorder, hdr_len = struct.unpack_from(">QQQII", h, 72)
            if hdr_len > 104 and self.incompat & INCOMPAT_COMPRESSION:
                comp_type = h[104]
            if autoclear & 1:
                self.notes.append("bitmaps extension present")
            if compat & 1:
                self.notes.append("lazy refcounts enabled")
        self.compression = {0: "zlib", 1: "zstd"}.get(comp_type, f"type {comp_type}")
        self.extended_l2 = bool(self.incompat & INCOMPAT_EXTL2)
        entry_bytes = 16 if self.extended_l2 else 8
        self.l2_entries = self.cluster_size // entry_bytes
        self.l2_bits = self.l2_entries.bit_length() - 1
        self.unit = self.cluster_size // 32 if self.extended_l2 else self.cluster_size
        if self.incompat & INCOMPAT_DIRTY:
            self.notes.append("image is marked dirty (QEMU was not shut down cleanly) - "
                              "data is still readable")
        if self.incompat & INCOMPAT_CORRUPT:
            self.errors.add(f"{self.name}: QEMU flagged this image as CORRUPT - reading it anyway")
        unknown = self.incompat & ~0x1F
        if unknown:
            self.errors.add(f"{self.name}: unknown incompatible features 0x{unknown:x} - "
                            "data may be misread")

        self._read_extensions(h, hdr_len)
        if bfo and bfs:
            self.backing_name = self.file.pread(bfo, min(bfs, 1023), "backing file name") \
                .decode("utf-8", "replace")
        if self.incompat & INCOMPAT_DATA_FILE:
            self._attach_data_file()

        span = self.cluster_size * self.l2_entries
        needed = (size + span - 1) // span
        if l1_size < needed:
            self.errors.add(f"{self.name}: L1 table shorter than the disk ({l1_size} < {needed}) - "
                            "the end of the disk reads as zeros")
        self.l1_size = l1_size
        self.l1 = self._read_l1(l1off, min(l1_size, max(needed, 1) * 4), "L1 table")
        self._read_snapshots(nb_snap, snap_off)

    def _read_extensions(self, h, pos):
        while pos + 8 <= len(h):
            etype, elen = struct.unpack_from(">II", h, pos)
            if etype == EXT_END:
                break
            data = h[pos + 8:pos + 8 + elen]
            if etype == EXT_BACKING_FORMAT:
                self.backing_format = data.decode("ascii", "replace")
            elif etype == EXT_DATA_FILE:
                self.data_file_name = data.decode("utf-8", "replace")
            pos += 8 + ((elen + 7) & ~7)

    def _read_l1(self, off, count, what):
        if not off or count <= 0:
            return []
        if off >= self.file.size:
            self.errors.add(f"{self.name}: {what} lies beyond the end of the file (truncated?)")
            return []
        raw = self.file.pread(off, count * 8, what)
        return list(struct.unpack(f">{count}Q", raw))

    def _read_snapshots(self, count, off):
        if not count or not off or count > 65536:
            return
        pos = off
        for _ in range(count):
            hdr = self.file.pread(pos, 40, "snapshot table")
            (l1off, l1size, id_len, name_len, dsec, _dns, _vmclock, vmstate, extra) = \
                struct.unpack(">QIHHIIQII", hdr)
            disk_size = self.size
            if extra >= 16:  # extra data: vm_state_size_large, disk_size
                disk_size = struct.unpack(">Q", self.file.pread(pos + 48, 8, "snapshot"))[0]
            pos += 40 + extra
            ident = self.file.pread(pos, id_len, "snapshot").decode("utf-8", "replace")
            pos += id_len
            name = self.file.pread(pos, name_len, "snapshot").decode("utf-8", "replace")
            pos += name_len
            pos = (pos + 7) & ~7
            self.snapshots.append(dict(id=ident, name=name, date=dsec, l1_offset=l1off, l1_size=l1size,
                                       vm_state=vmstate, disk_size=disk_size))
            if pos > self.file.size:
                break
        # newest snapshot first: used as fallback when an active L2 pointer is damaged
        for s in sorted(self.snapshots, key=lambda s: s["date"], reverse=True):
            if 0 < s["l1_size"] <= len(self.l1) * 4 + 1024:
                self._snap_l1.append(self._read_l1(s["l1_offset"], s["l1_size"], "snapshot L1 table"))

    def _attach_data_file(self):
        base = os.path.dirname(os.path.abspath(self.path))
        from .vmdk import resolve_path
        p = resolve_path(base, self.data_file_name) if self.data_file_name else None
        if p is None:
            self.errors.add(f"{self.name}: external data file '{self.data_file_name}' not found - "
                            "allocated data reads as zeros")
            self.data_file = None
            return
        self.data_file = SafeFile(p, self.errors)
        self.notes.append(f"external data file: {p}")

    def _attach_backing(self, depth):
        from .vmdk import resolve_path
        base = os.path.dirname(os.path.abspath(self.path))
        p = resolve_path(base, self.backing_name)
        if p is None:
            self.errors.add(f"backing file '{self.backing_name}' not found - unallocated areas of "
                            f"{self.name} read as zeros")
            self.notes.append(f"missing backing file: {self.backing_name}")
            return
        if depth > 32:
            self.errors.add("backing chain too deep (loop?) - stopping")
            return
        if self.backing_format == "raw" or self._open_backing is None:
            self.parent = RawImage(p, self.errors)
        else:
            self.parent = self._open_backing(p, self.errors, _depth=depth + 1)

    # -- mapping -------------------------------------------------------------
    def _valid_table(self, off):
        return off and off % 512 == 0 and off + self.l2_entries * 8 <= self.file.size + self.cluster_size

    def _l2(self, l1, l1_idx, tag):
        if l1_idx >= len(l1):
            return None
        e = l1[l1_idx]
        off = (e & L1_OFFSET_MASK) if self.version >= 2 else e
        if off == 0:
            return ()
        if not self._valid_table(off):
            return None
        key = (tag, l1_idx)
        tbl = self._l2_cache.get(key)
        if tbl is None:
            n = self.l2_entries * (2 if self.extended_l2 else 1)
            tbl = struct.unpack(f">{n}Q", self.file.pread(off, n * 8, "L2 table"))
            self._l2_cache.put(key, tbl)
        return tbl

    def lookup(self, unit_idx):
        """Return (kind, host_offset, compressed_size) for one cluster / sub-cluster."""
        if self.extended_l2:
            cl, sc = divmod(unit_idx, 32)
        else:
            cl, sc = unit_idx, 0
        l1_idx, l2_idx = divmod(cl, self.l2_entries)
        tbl = self._l2(self.l1, l1_idx, "a")
        if tbl is None:
            for i, snap in enumerate(self._snap_l1):
                tbl = self._l2(snap, l1_idx, f"s{i}")
                if tbl is not None:
                    self.errors.add(f"{self.name}: L2 table {l1_idx} damaged - using data from an "
                                    "internal snapshot instead", key=(self.path, "l2snap", l1_idx))
                    break
        if tbl is None:
            self.errors.add(f"{self.name}: L2 table {l1_idx} is damaged - "
                            f"{fmt_size(self.cluster_size * self.l2_entries)} read as zeros",
                            key=(self.path, "l2", l1_idx))
            return BAD, 0, 0
        if not tbl:
            return UNALLOC, 0, 0
        if self.version == 1:
            return self._entry_v1(tbl[l2_idx])
        if self.extended_l2:
            return self._entry_ext(tbl[2 * l2_idx], tbl[2 * l2_idx + 1], sc)
        return self._entry_v2(tbl[l2_idx])

    def _entry_v1(self, e):
        if e == 0:
            return UNALLOC, 0, 0
        if e & (1 << 63):
            shift = 63 - self.cluster_bits
            csize = (e >> shift) & ((1 << self.cluster_bits) - 1)
            return COMP, e & ((1 << shift) - 1), csize
        return DATA, e, 0

    def _compressed(self, e):
        x = 62 - (self.cluster_bits - 8)
        off = e & ((1 << x) - 1)
        nsec = (e >> x) & ((1 << (self.cluster_bits - 8)) - 1)
        return COMP, off, (nsec + 1) * 512 - (off & 511)

    def _entry_v2(self, e):
        if e & QCOW_OFLAG_COMPRESSED:
            return self._compressed(e)
        if self.version >= 3 and e & QCOW_OFLAG_ZERO:
            return ZERO, 0, 0
        off = e & L2_OFFSET_MASK
        if off == 0:
            return UNALLOC, 0, 0
        return DATA, off, 0

    def _entry_ext(self, e, bitmap, sc):
        if e & QCOW_OFLAG_COMPRESSED:
            return self._compressed(e)
        off = e & L2_OFFSET_MASK
        if bitmap >> sc & 1:
            if off == 0:
                return BAD, 0, 0
            return DATA, off + sc * self.unit, 0
        if bitmap >> (32 + sc) & 1:
            return ZERO, 0, 0
        return UNALLOC, 0, 0

    # -- data ------------------------------------------------------------------
    def _decompress(self, data):
        n = self.cluster_size
        if self.compression == "zstd":
            return _unzstd(data, n)
        try:
            return zlib.decompressobj(-15).decompress(data, n)
        except zlib.error:
            d = zlib.decompressobj(-15)
            out = bytearray()
            try:
                for i in range(0, len(data), 256):
                    out += d.decompress(data[i:i + 256])
            except zlib.error:
                pass
            return bytes(out) or None

    def _cluster(self, cl, off, csize):
        cached = self._cluster_cache.get(cl)
        if cached is not None:
            return cached
        csize = max(0, min(csize, self.file.size - off, self.cluster_size * 2 + 512))
        raw = self.file.pread(off, csize, "compressed cluster") if csize else b""
        try:
            data = self._decompress(raw) if raw else None
        except Exception:  # noqa: BLE001 - zstd library errors vary
            data = None
        if not data:
            self.errors.add(f"{self.name}: compressed cluster {cl} is damaged - zeros substituted",
                            key=(self.path, "cc", cl))
            data = b""
        elif len(data) < self.cluster_size:
            self.errors.add(f"{self.name}: compressed cluster {cl} only partially recovered",
                            key=(self.path, "ccp", cl))
        data = data[:self.cluster_size].ljust(self.cluster_size, b"\0")
        self._cluster_cache.put(cl, data)
        return data

    def _from_parent(self, pos, n):
        if self.parent is not None:
            d = self.parent.read(pos, n)
            return d + bytes(n - len(d))
        return bytes(n)

    def _read(self, offset, length):
        out = bytearray()
        u = self.unit
        pos = offset
        end = offset + length
        while pos < end:
            ui, within = divmod(pos, u)
            n = min(u - within, end - pos)
            kind, host, csize = self.lookup(ui)
            if kind == UNALLOC:
                out += self._from_parent(pos, n)
            elif kind in (ZERO, BAD):
                out += bytes(n)
            elif kind == COMP:
                cl, cwithin = divmod(pos, self.cluster_size)
                out += self._cluster(cl, host, csize)[cwithin:cwithin + n]
            elif self.data_file is None:
                out += bytes(n)
            else:
                # coalesce physically contiguous clusters into one read
                expect = host + u
                nui = ui + 1
                while pos + n < end:
                    k2, h2, _c = self.lookup(nui)
                    if k2 != DATA or h2 != expect:
                        break
                    n += min(u, end - pos - n)
                    expect += u
                    nui += 1
                out += self.data_file.pread(host + within, n, "cluster")
            pos += n
        return bytes(out)

    def is_allocated(self, offset, length):
        u = self.unit
        for ui in range(offset // u, (offset + length - 1) // u + 1):
            kind = self.lookup(ui)[0]
            if kind in (DATA, COMP):
                return True
            if kind == UNALLOC and self.parent is not None and self.parent.is_allocated(ui * u, u):
                return True
        return False

    def info(self):
        rows = [("File", self.path), ("Format", self.format),
                ("Virtual size", f"{fmt_size(self.size)} ({self.size:,} bytes)"),
                ("Cluster size", fmt_size(self.cluster_size))]
        if self.version >= 2:
            rows.append(("Compression", self.compression))
        if self.extended_l2:
            rows.append(("Extended L2", f"yes ({fmt_size(self.unit)} sub-clusters)"))
        if self.backing_name:
            rows.append(("Backing file", self.backing_name
                         + (f" ({self.backing_format})" if self.backing_format else "")))
        if self.parent is not None:
            rows.append(("Backing opened", getattr(self.parent, "path", "?")))
        for s in self.snapshots:
            when = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(s["date"])) if s["date"] else "?"
            rows.append(("Snapshot", f"id {s['id']} '{s['name']}' taken {when}"
                                     + (f", VM state {fmt_size(s['vm_state'])}" if s["vm_state"] else "")))
        for n in self.notes:
            rows.append(("Note", n))
        rows.append(("Read problems", str(self.errors.count)))
        return rows

    def close(self):
        self.file.close()
        if self.data_file is not None and self.data_file is not self.file:
            self.data_file.close()
        if self.parent is not None:
            self.parent.close()


def _unzstd(data, n):
    if _zstd_std is not None:
        d = _zstd_std.ZstdDecompressor()
        try:
            return d.decompress(data, n)
        except _zstd_std.ZstdError:
            return _salvage_stream(_zstd_std.ZstdDecompressor, data, n, _zstd_std.ZstdError)
    if _zstd_pkg is not None:
        d = _zstd_pkg.ZstdDecompressor().decompressobj()
        try:
            return d.decompress(data)[:n]
        except _zstd_pkg.ZstdError:
            return None
    raise RuntimeError("zstd-compressed QCOW2 clusters need Python 3.14+ or 'pip install zstandard'")


def _salvage_stream(factory, data, n, err):
    d = factory()
    out = bytearray()
    try:
        for i in range(0, len(data), 256):
            out += d.decompress(data[i:i + 256])
            if len(out) >= n or d.eof:
                break
    except err:
        pass
    return bytes(out) or None


def open_qcow(path, errors=None, opener=None, depth=0):
    return QcowImage(path, errors if errors is not None else ErrorLog(), opener=opener, depth=depth)
