"""VMDK reader supporting the variants produced by VMware, VirtualBox and QEMU.

Supported layouts
  * monolithicSparse / twoGbMaxExtentSparse  (hosted sparse "KDMV" extents)
  * monolithicFlat / twoGbMaxExtentFlat / vmfs (ESXi "-flat.vmdk")
  * streamOptimized (compressed grains, OVA/OVF exports)
  * vmfsSparse / ESX 2.x "COWD" extents
  * snapshot / delta disks with parent chains (parentFileNameHint)
  * stand-alone descriptor files with any mix of the above extents

Damage tolerance
  * bad primary grain directory/table entries fall back to the redundant copy
  * streamOptimized files with a missing/corrupt footer (e.g. truncated
    downloads) are re-indexed by scanning the grain markers
  * corrupt compressed grains are partially inflated, the rest zero-filled
  * missing extent files and parents are replaced with zeros
  * an orphaned split extent (-s001.vmdk etc.) is reassembled with its siblings
"""

import os
import re
import struct
import zlib
import glob
import threading

from .disk import (SECTOR, DiskImage, RawImage, ZeroImage, ConcatImage, SliceImage, SafeFile,
                   ErrorLog, LRUCache, fmt_size)
from .qcow import QcowImage, is_qcow
from .vdi import VdiImage, is_vdi
from .vhd import VhdImage, VhdxImage, is_vhdx, vhd_footer_at_end

KDMV_MAGIC = 0x564D444B  # "KDMV"
COWD_MAGIC = 0x44574F43  # "COWD"
GD_AT_END = 0xFFFFFFFFFFFFFFFF

FLAG_REDUNDANT_GT = 1 << 1
FLAG_COMPRESSED = 1 << 16
FLAG_MARKERS = 1 << 17

MARKER_EOS, MARKER_GT, MARKER_GD, MARKER_FOOTER = 0, 1, 2, 3

_HDR = struct.Struct("<IIIQQQQIQQQB4sH")


def _parse_kdmv(buf):
    if len(buf) < _HDR.size:
        return None
    (magic, version, flags, capacity, grain, desc_off, desc_size, num_gtes, rgd, gd,
     overhead, unclean, _nl, compress) = _HDR.unpack_from(buf)
    if magic != KDMV_MAGIC:
        return None
    return dict(version=version, flags=flags, capacity=capacity, grain=grain,
                desc_off=desc_off, desc_size=desc_size, num_gtes=num_gtes, rgd=rgd, gd=gd,
                overhead=overhead, unclean=unclean, compress=compress)


def _sane_header(h, file_size):
    if not h:
        return False
    g = h["grain"]
    return (0 < g <= 1 << 16 and g & (g - 1) == 0 and 0 < h["num_gtes"] <= 1 << 16
            and 0 < h["capacity"] < (1 << 50))


class SparseExtent(DiskImage):
    """A hosted sparse (KDMV) or ESX COWD extent."""

    def __init__(self, path, errors=None, rebuild=False):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.file = SafeFile(path, self.errors)
        self.parent = None        # image providing data for unallocated grains
        self.parent_base = 0      # this extent's offset within the parent disk
        self.embedded_descriptor = None
        self.kind = "sparse"
        self._gt_cache = LRUCache(8192)
        self._grain_cache = LRUCache(64)
        self._scan_map = None
        self._scan_lock = threading.Lock()
        self.notes = []

        head = self.file.pread(0, SECTOR, "header")
        if struct.unpack_from("<I", head)[0] == COWD_MAGIC:
            self._init_cowd(head)
        else:
            self._init_kdmv(head)

        self.grain_bytes = self.grain * SECTOR
        self.size = self.capacity * SECTOR
        span = self.grain * self.num_gtes
        self.gd_entries = (self.capacity + span - 1) // span
        self.gd = self._load_gd(self.gd_off, "grain directory")
        self.rgd = self._load_gd(self.rgd_off, "redundant grain directory") if self.rgd_off else None
        if self.gd is None and self.rgd is not None:
            self.notes.append("primary grain directory unusable - using redundant copy")
            self.gd, self.rgd = self.rgd, None
        if self.compressed and (rebuild or self.gd is None):
            self._build_scan_map()
        elif self.gd is None:
            self.errors.add(f"{self.name}: no usable grain directory - extent reads as zeros")

    # -- header handling -------------------------------------------------
    def _init_cowd(self, head):
        (_m, version, flags, num_sectors, grain, gd_off, num_gde, _free) = struct.unpack_from("<8I", head)
        self.kind = "COWD (ESX vmfsSparse)"
        self.version = version
        self.capacity = num_sectors
        self.grain = grain or 1
        self.num_gtes = 4096
        self.gd_off = gd_off
        self.rgd_off = 0
        self.compressed = False
        self.flags = flags
        self.overhead = 0

    def _init_kdmv(self, head):
        h = _parse_kdmv(head)
        fsize = self.file.size
        footer = None
        if not _sane_header(h, fsize) or (h and h["gd"] == GD_AT_END):
            footer = self._find_footer()
        if h is None or not _sane_header(h, fsize):
            if footer:
                self.notes.append("primary header damaged - using footer copy")
                h = footer
            else:
                self.errors.add(f"{self.name}: sparse header is damaged - guessing VMware defaults "
                                "(64 KB grains)")
                h = dict(version=1, flags=FLAG_REDUNDANT_GT, grain=128, num_gtes=512,
                         capacity=fsize // SECTOR * 4, desc_off=0, desc_size=0, rgd=0,
                         gd=0, overhead=0, compress=0, unclean=0)
        self.header = h
        self.version = h["version"]
        self.flags = h["flags"]
        self.capacity = h["capacity"]
        self.grain = h["grain"]
        self.num_gtes = h["num_gtes"]
        self.overhead = h["overhead"]
        self.compressed = bool(h["flags"] & FLAG_COMPRESSED) or h["compress"] == 1
        gd = h["gd"]
        rgd = h["rgd"] if h["flags"] & FLAG_REDUNDANT_GT else 0
        if gd == GD_AT_END:
            if footer:
                gd = footer["gd"]
                rgd = footer["rgd"] if footer["flags"] & FLAG_REDUNDANT_GT else 0
            else:
                self.notes.append("stream footer missing (truncated file?) - rebuilding index by scanning")
                gd = 0
        self.gd_off = gd if gd != GD_AT_END else 0
        self.rgd_off = rgd if rgd != GD_AT_END else 0
        if self.compressed:
            self.kind = "streamOptimized (compressed)"
        if h["desc_off"] and h["desc_size"]:
            raw = self.file.pread(h["desc_off"] * SECTOR, min(h["desc_size"], 2048) * SECTOR,
                                  "descriptor")
            self.embedded_descriptor = raw.split(b"\0", 1)[0].decode("utf-8", "replace")
        if h.get("unclean"):
            self.notes.append("image was not shut down cleanly")

    def _find_footer(self):
        fsize = self.file.size
        start = max(0, fsize - 64 * 1024) // SECTOR * SECTOR
        tail = self.file.pread(start, fsize - start, "footer")
        pos = len(tail) - 1024
        while pos >= 0:
            h = _parse_kdmv(tail[pos:pos + SECTOR])
            if h and h["gd"] not in (0, GD_AT_END) and _sane_header(h, fsize):
                return h
            pos -= SECTOR
        return None

    # -- grain directory / tables -------------------------------------
    def _load_gd(self, sector, what):
        if not sector or sector == GD_AT_END:
            return None
        n = self.gd_entries
        if sector * SECTOR >= self.file.size:
            self.errors.add(f"{self.name}: {what} offset is beyond end of file")
            return None
        raw = self.file.pread(sector * SECTOR, n * 4, what)
        gd = list(struct.unpack(f"<{n}I", raw))
        limit = self.file.size // SECTOR
        bad = sum(1 for e in gd if e >= limit)
        if bad and bad == sum(1 for e in gd if e):
            self.errors.add(f"{self.name}: {what} is corrupt ({bad} invalid entries)")
            return None
        return gd

    def _gt_from(self, gd, idx, tag):
        if gd is None or idx >= len(gd):
            return None
        sec = gd[idx]
        if sec == 0:
            return ()
        key = (tag, idx)
        gt = self._gt_cache.get(key)
        if gt is not None:
            return gt
        if (sec + 1) * SECTOR > self.file.size:
            return None
        raw = self.file.pread(sec * SECTOR, self.num_gtes * 4, "grain table")
        gt = struct.unpack(f"<{self.num_gtes}I", raw)
        self._gt_cache.put(key, gt)
        return gt

    def _valid_grain_sector(self, sec):
        return sec <= 1 or sec * SECTOR < self.file.size

    def lookup(self, gi):
        """Grain index -> host sector (0 = unallocated, 1 = zero grain, -1 = damaged)."""
        if self._scan_map is not None:
            return self._scan_map.get(gi, 0)
        if self.gd is None and self.rgd is None:
            return -1
        gt_idx, gte = divmod(gi, self.num_gtes)
        for tag, gd in (("p", self.gd), ("r", self.rgd)):
            gt = self._gt_from(gd, gt_idx, tag)
            if gt is None:
                continue
            sec = gt[gte] if gt else 0
            if self._valid_grain_sector(sec):
                return sec
        if self.compressed:
            self._build_scan_map()
            return self._scan_map.get(gi, 0)
        self.errors.add(f"{self.name}: grain table entry for grain {gi} is damaged - "
                        "zeros substituted", key=(self.path, "gte", gi // 4096))
        return -1

    # -- streamOptimized index rebuild ------------------------------------
    def _build_scan_map(self):
        with self._scan_lock:
            if self._scan_map is not None:
                return
            m = {}
            fsize = self.file.size
            pos = max(self.overhead, 1) * SECTOR
            max_payload = self.grain_bytes + 4096
            resyncs = 0
            while pos + 12 <= fsize:
                hdr = self.file.pread(pos, 16, "marker")
                lba, size = struct.unpack_from("<QI", hdr)
                if size:
                    if (size <= max_payload and lba % self.grain == 0 and lba < self.capacity
                            and hdr[12] in (0x78, 0x58, 0x08, 0x38, 0x48, 0x68)):
                        m[lba // self.grain] = pos // SECTOR
                        pos += (12 + size + SECTOR - 1) // SECTOR * SECTOR
                        continue
                    resyncs += 1
                    pos += SECTOR
                    continue
                mtype = struct.unpack_from("<I", hdr, 12)[0]
                if mtype in (MARKER_GT, MARKER_GD, MARKER_FOOTER) and lba < (1 << 24):
                    pos += SECTOR + lba * SECTOR
                elif mtype == MARKER_EOS and lba == 0:
                    break
                else:
                    resyncs += 1
                    pos += SECTOR
            self._scan_map = m
            msg = f"stream index rebuilt by scanning: {len(m)} grains found"
            if resyncs:
                msg += f", skipped {resyncs} damaged sectors"
            self.notes.append(msg)

    # -- data access -------------------------------------------------------
    def _from_parent(self, offset, n):
        if self.parent is not None:
            data = self.parent.read(self.parent_base + offset, n)
            return data + bytes(n - len(data))
        return bytes(n)

    def _inflate(self, gi, sec):
        cached = self._grain_cache.get(gi)
        if cached is not None:
            return cached
        hdr = self.file.pread(sec * SECTOR, 12, "grain marker")
        lba, size = struct.unpack("<QI", hdr)
        if size == 0 or size > self.grain_bytes * 2 + 4096:
            self.errors.add(f"{self.name}: compressed grain {gi} has a bad marker", key=(self.path, "cg", gi))
            data = bytes(self.grain_bytes)
        else:
            payload = self.file.pread(sec * SECTOR + 12, size, "compressed grain")
            data = _inflate_tolerant(payload, self.grain_bytes)
            if data is None:
                self.errors.add(f"{self.name}: compressed grain {gi} is damaged - zeros substituted",
                                key=(self.path, "cg", gi))
                data = bytes(self.grain_bytes)
            elif len(data) < self.grain_bytes:
                if len(data) and lba == gi * self.grain:
                    self.errors.add(f"{self.name}: compressed grain {gi} only partially recovered",
                                    key=(self.path, "cgp", gi))
                data = data + bytes(self.grain_bytes - len(data))
        data = data[:self.grain_bytes]
        self._grain_cache.put(gi, data)
        return data

    def _read(self, offset, length):
        out = bytearray()
        gb = self.grain_bytes
        pos = offset
        end = offset + length
        while pos < end:
            gi, within = divmod(pos, gb)
            n = min(gb - within, end - pos)
            sec = self.lookup(gi)
            if sec == 0:
                out += self._from_parent(pos, n)
            elif sec in (1, -1):
                out += bytes(n)
            elif self.compressed:
                out += self._inflate(gi, sec)[within:within + n]
            else:
                # coalesce physically contiguous grains into one read
                expect = sec + self.grain
                ngi = gi + 1
                while pos + n < end and self.lookup(ngi) == expect:
                    n += min(gb, end - pos - n)
                    expect += self.grain
                    ngi += 1
                out += self.file.pread(sec * SECTOR + within, n, "grain")
            pos += n
        return bytes(out)

    def is_allocated(self, offset, length):
        gb = self.grain_bytes
        for gi in range(offset // gb, (offset + length - 1) // gb + 1):
            sec = self.lookup(gi)
            if sec > 1:
                return True
            if sec == 0 and self.parent is not None and \
                    self.parent.is_allocated(self.parent_base + gi * gb, gb):
                return True
        return False

    def allocated_grains(self):
        if self._scan_map is not None:
            return len(self._scan_map)
        count = 0
        for i in range(self.gd_entries):
            gt = self._gt_from(self.gd, i, "p")
            if gt:
                count += sum(1 for e in gt if e > 1)
        return count

    def close(self):
        self.file.close()


def _inflate_tolerant(payload, expected):
    for wbits in (15, -15, 31):
        try:
            return zlib.decompress(payload, wbits, expected)
        except zlib.error:
            pass
    # salvage what we can by feeding the stream in small pieces
    best = b""
    for wbits in (15, -15):
        d = zlib.decompressobj(wbits)
        out = bytearray()
        try:
            for i in range(0, len(payload), 256):
                out += d.decompress(payload[i:i + 256])
        except zlib.error:
            pass
        if len(out) > len(best):
            best = bytes(out)
    return best or None


# ---------------------------------------------------------------------------
# Descriptor handling
# ---------------------------------------------------------------------------

_EXTENT_RE = re.compile(
    r'^\s*(RW|RDONLY|NOACCESS)\s+(\d+)\s+([A-Za-z]+)(?:\s+"([^"]*)"(?:\s+(\d+))?)?', re.I)
_FIELD_RE = re.compile(r'^\s*([A-Za-z0-9_.]+)\s*=\s*"?([^"]*)"?\s*$')


class Descriptor:
    def __init__(self, text):
        self.text = text
        self.fields = {}
        self.extents = []  # dicts: access, sectors, type, file, offset
        for line in text.splitlines():
            m = _EXTENT_RE.match(line)
            if m:
                self.extents.append(dict(access=m.group(1).upper(), sectors=int(m.group(2)),
                                         type=m.group(3).upper(), file=m.group(4),
                                         offset=int(m.group(5) or 0)))
                continue
            if line.lstrip().startswith("#"):
                continue
            m = _FIELD_RE.match(line)
            if m:
                self.fields[m.group(1)] = m.group(2)

    @property
    def create_type(self):
        return self.fields.get("createType", "")

    @property
    def parent_hint(self):
        cid = self.fields.get("parentCID", "ffffffff").lower()
        hint = self.fields.get("parentFileNameHint")
        return hint if hint and cid != "ffffffff" else None


def _looks_like_descriptor(head, fsize):
    if fsize > 16 * 1024 * 1024:
        return False
    return (b"createType" in head or b"# Disk DescriptorFile" in head
            or bool(re.search(rb'(?m)^\s*(RW|RDONLY)\s+\d+\s+(SPARSE|FLAT|VMFS|ZERO)', head)))


def resolve_path(base_dir, name):
    """Locate a referenced file, tolerating absolute paths from other hosts and case changes."""
    if not name:
        return None
    candidates = []
    norm = name.replace("\\", "/")
    if os.path.isabs(name):
        candidates.append(name)
    candidates.append(os.path.join(base_dir, name))
    base = norm.rsplit("/", 1)[-1]
    candidates.append(os.path.join(base_dir, base))
    for c in candidates:
        if os.path.isfile(c):
            return c
    try:
        lower = base.lower()
        for entry in os.listdir(base_dir or "."):
            if entry.lower() == lower:
                return os.path.join(base_dir, entry)
    except OSError:
        pass
    return None


class VMDKImage(DiskImage):
    """Top-level opened disk: wraps an extent chain and records metadata."""

    def __init__(self, inner, path, fmt, errors, descriptor=None, extents=None, parent=None, notes=None):
        super().__init__(errors)
        self.inner = inner
        self.path = path
        self.name = os.path.basename(path)
        self.size = inner.size
        self.format = fmt
        self.descriptor = descriptor
        self.extents = extents or []
        self.parent = parent
        self.notes = notes or []

    def _read(self, offset, length):
        return self.inner.read(offset, length)

    def is_allocated(self, offset, length):
        return self.inner.is_allocated(offset, length)

    def info(self):
        rows = [("File", self.path), ("Format", self.format),
                ("Virtual size", f"{fmt_size(self.size)} ({self.size // SECTOR} sectors)")]
        if self.descriptor:
            for k in ("createType", "ddb.adapterType", "ddb.virtualHWVersion", "ddb.toolsVersion",
                      "CID", "parentCID", "ddb.uuid.image"):
                if k in self.descriptor.fields:
                    rows.append((k, self.descriptor.fields[k]))
        for e in self.extents:
            if isinstance(e, SparseExtent):
                rows.append(("Extent", f"{e.name}: {e.kind}, grain {e.grain_bytes // 1024} KB, "
                                       f"{fmt_size(e.size)}"))
                for n in e.notes:
                    rows.append(("  note", n))
            elif isinstance(e, RawImage):
                rows.append(("Extent", f"{e.name}: flat, {fmt_size(e.size)}"))
            else:
                rows.append(("Extent", f"{getattr(e, 'name', '?')}: {fmt_size(e.size)}"))
        if self.parent is not None:
            rows.append(("Parent", getattr(self.parent, "path", "?")))
        for n in self.notes:
            rows.append(("Note", n))
        rows.append(("Read problems", str(self.errors.count)))
        return rows

    def close(self):
        for e in self.extents:
            e.close()
        if self.parent is not None:
            self.parent.close()


def _open_parent(desc, base_dir, errors, depth, notes):
    hint = desc.parent_hint if desc else None
    if not hint:
        return None
    ppath = resolve_path(base_dir, hint)
    if ppath is None:
        errors.add(f"parent disk '{hint}' not found - unallocated areas of this snapshot read as zeros")
        notes.append(f"missing parent: {hint}")
        return None
    if depth > 32:
        errors.add("parent chain too deep (loop?) - stopping")
        return None
    return open_image(ppath, errors, _depth=depth + 1)


def _build_from_descriptor(desc, path, errors, depth):
    base_dir = os.path.dirname(os.path.abspath(path))
    notes = []
    parent = _open_parent(desc, base_dir, errors, depth, notes)
    parts = []
    opened = []
    disk_pos = 0
    for e in desc.extents:
        size = e["sectors"] * SECTOR
        etype = e["type"]
        img = None
        if etype == "ZERO":
            img = ZeroImage(size, errors)
        else:
            fpath = resolve_path(base_dir, e["file"])
            if fpath is None:
                errors.add(f"extent file '{e['file']}' is missing - {fmt_size(size)} read as zeros")
                notes.append(f"missing extent: {e['file']}")
                img = ZeroImage(size, errors, name=e["file"] or "missing")
            elif etype in ("SPARSE", "VMFSSPARSE"):
                try:
                    img = SparseExtent(fpath, errors)
                    img.parent = parent
                    img.parent_base = disk_pos
                except Exception as ex:  # noqa: BLE001 - keep going on damaged extents
                    errors.add(f"cannot open sparse extent {e['file']}: {ex}")
                    img = None
            elif etype in ("FLAT", "VMFS", "VMFSRAW", "VMFSRDM"):
                img = RawImage(fpath, errors, file_offset=e["offset"] * SECTOR, size=size)
            else:
                errors.add(f"extent type {etype} ({e['file']}) is not supported - "
                           "reading underlying parent data instead")
            if img is None:
                if parent is not None:
                    img = SliceImage(parent, disk_pos, size, name=e["file"] or "")
                else:
                    img = ZeroImage(size, errors)
        opened.append(img)
        parts.append((size, img))
        disk_pos += size
    inner = ConcatImage(parts, errors, name=os.path.basename(path))
    fmt = desc.create_type or "descriptor"
    return VMDKImage(inner, path, f"VMDK ({fmt})", errors, descriptor=desc, extents=opened,
                     parent=parent, notes=notes)


_SPLIT_RE = re.compile(r"^(.*)-([sf])(\d{3})\.vmdk$", re.I)


def _orphan_split(path, errors):
    """Reassemble -s001/-f001 style split extents when the descriptor is gone."""
    m = _SPLIT_RE.match(os.path.basename(path))
    if not m:
        return None
    base_dir = os.path.dirname(os.path.abspath(path))
    desc_path = os.path.join(base_dir, m.group(1) + ".vmdk")
    if os.path.isfile(desc_path):
        try:
            with open(desc_path, "rb") as f:
                head = f.read(65536)
            if _looks_like_descriptor(head, os.path.getsize(desc_path)):
                return open_image(desc_path, errors)
        except OSError:
            pass
    pattern = os.path.join(glob.escape(base_dir), glob.escape(m.group(1)) + f"-{m.group(2)}[0-9][0-9][0-9].vmdk")
    files = sorted(glob.glob(pattern))
    if len(files) <= 1:
        return None
    exts = []
    for f in files:
        if m.group(2).lower() == "s":
            exts.append(SparseExtent(f, errors))
        else:
            exts.append(RawImage(f, errors))
    inner = ConcatImage([(e.size, e) for e in exts], errors)
    note = f"descriptor missing - reassembled {len(files)} split extents"
    errors.add(note)
    return VMDKImage(inner, path, "VMDK (split extents, no descriptor)", errors, extents=exts, notes=[note])


def open_image(path, errors=None, _depth=0, rebuild_stream_index=False):
    """Open any supported disk image and return a DiskImage."""
    errors = errors if errors is not None else ErrorLog()
    fsize = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(65536)
    magic = struct.unpack_from("<I", head)[0] if len(head) >= 4 else 0

    if is_qcow(head):
        return QcowImage(path, errors, opener=open_image, depth=_depth)
    if is_vhdx(head):
        return VhdxImage(path, errors, opener=open_image, depth=_depth)
    if is_vdi(head):
        return VdiImage(path, errors, opener=open_image, depth=_depth)
    if head[:8] == b"conectix":
        return VhdImage(path, errors, opener=open_image, depth=_depth)

    if magic in (KDMV_MAGIC, COWD_MAGIC):
        ext = SparseExtent(path, errors, rebuild=rebuild_stream_index)
        desc = Descriptor(ext.embedded_descriptor) if ext.embedded_descriptor else None
        if desc and len(desc.extents) > 1:
            ext.close()
            return _build_from_descriptor(desc, path, errors, _depth)
        if _depth == 0 and _SPLIT_RE.match(os.path.basename(path)):
            whole = _orphan_split(path, errors)
            if whole is not None:
                ext.close()
                return whole
        notes = []
        parent = _open_parent(desc, os.path.dirname(os.path.abspath(path)), errors, _depth, notes)
        ext.parent = parent
        if desc and desc.extents and len(desc.extents) == 1:
            want = desc.extents[0]["sectors"] * SECTOR
            if want and want != ext.size:
                notes.append(f"descriptor size {want} differs from header capacity {ext.size}")
        fmt = desc.create_type if desc and desc.create_type else ext.kind
        return VMDKImage(ext, path, f"VMDK ({fmt})", errors, descriptor=desc, extents=[ext],
                         parent=parent, notes=notes)

    if _looks_like_descriptor(head, fsize):
        with open(path, "rb") as f:
            text = f.read().split(b"\0", 1)[0].decode("utf-8", "replace")
        desc = Descriptor(text)
        if desc.extents:
            return _build_from_descriptor(desc, path, errors, _depth)
        errors.add("descriptor contains no extent lines")

    if vhd_footer_at_end(path) is not None:  # fixed VHD: plain data followed by a footer
        return VhdImage(path, errors, opener=open_image, depth=_depth)
    if _depth == 0:
        whole = _orphan_split(path, errors)
        if whole is not None:
            return whole
    raw = RawImage(path, errors)
    fmt = "VMDK flat extent (raw)" if path.lower().endswith(".vmdk") else "Raw disk image"
    return VMDKImage(raw, path, fmt, errors, extents=[raw])
