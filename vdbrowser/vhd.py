"""Microsoft VHD and VHDX readers (Hyper-V, Azure, Virtual PC, Windows Backup, Disk2vhd).

VHD:  fixed, dynamic and differencing disks.
VHDX: fixed, dynamic and differencing disks, 512 and 4096-byte logical sectors.

Damage tolerance
  * VHD: a damaged or missing footer (e.g. truncated file) is replaced by the
    copy at the start of dynamic disks; a fixed VHD without footer reads as raw
  * VHDX: the newer valid header of the two copies is chosen, the backup region
    table is used when the primary is damaged, and a pending metadata log
    (image not closed cleanly) is replayed in memory - the file is never written
  * BAT entries pointing outside the file read as zeros
  * missing parent disks only blank the areas the child did not change
"""

import os
import struct
import uuid

from .disk import DiskImage, SafeFile, ErrorLog, fmt_size

SECTOR = 512
MB = 1 << 20


def _guid(b):
    return str(uuid.UUID(bytes_le=bytes(b)))


def _find_file(base_dir, candidates):
    from .vmdk import resolve_path
    for c in candidates:
        if not c:
            continue
        p = resolve_path(base_dir, c)
        if p:
            return p
    return None


# ---------------------------------------------------------------------------
# VHD
# ---------------------------------------------------------------------------

VHD_FIXED, VHD_DYNAMIC, VHD_DIFF = 2, 3, 4
VHD_TYPES = {VHD_FIXED: "fixed", VHD_DYNAMIC: "dynamic", VHD_DIFF: "differencing"}


def _parse_footer(b):
    if len(b) < 85 or b[:8] != b"conectix":
        return None
    (features, version, data_off, ts) = struct.unpack_from(">IIQI", b, 8)
    orig, cur, geom, dtype, checksum = struct.unpack_from(">QQIII", b, 40)
    calc = (~sum(b[:64] + b"\0\0\0\0" + b[68:512]) & 0xFFFFFFFF) if len(b) >= 512 else None
    return dict(data_off=data_off, size=cur, orig=orig, type=dtype, uid=b[68:84],
                creator=b[28:32].decode("latin-1", "replace").strip(),
                checksum_ok=calc == checksum, geom=geom, ts=ts)


def vhd_footer_at_end(path):
    """Return the footer dict when ``path`` ends in a VHD footer."""
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            f.seek(max(0, size - 512))
            tail = f.read(512)
    except OSError:
        return None
    for off in (0, 1):  # very old images have a 511-byte footer
        ft = _parse_footer(tail[off:] + b"\0" * off)
        if ft:
            return ft
    return None


def is_vhd(head, path):
    return head[:8] == b"conectix" or vhd_footer_at_end(path) is not None


class VhdImage(DiskImage):
    def __init__(self, path, errors=None, opener=None, depth=0):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.file = SafeFile(path, self.errors)
        self.parent = None
        self.parent_name = None
        self.notes = []
        tail = vhd_footer_at_end(path)
        head = _parse_footer(self.file.pread(0, 512, "footer copy"))
        ft = tail
        if tail is None or (not tail["checksum_ok"] and head and head["checksum_ok"]):
            if head:
                ft = head
                self.errors.add(f"{self.name}: footer at end of file is missing or damaged "
                                "(truncated?) - using the copy at the start")
        if ft is None:
            raise ValueError("no VHD footer found")
        self.footer = ft
        self.type = ft["type"]
        self.size = ft["size"]
        self.format = f"VHD ({VHD_TYPES.get(self.type, f'type {self.type}')})"
        if self.type == VHD_FIXED:
            self._data_end = self.file.size - 512 if tail else self.file.size
            if self.size > self._data_end:
                self.errors.add(f"{self.name}: file shorter than the disk - missing tail reads as zeros")
            return
        if self.type not in (VHD_DYNAMIC, VHD_DIFF):
            raise ValueError(f"unsupported VHD disk type {self.type}")
        dh = self.file.pread(ft["data_off"], 1024, "dynamic header")
        if dh[:8] != b"cxsparse":
            raise ValueError("VHD dynamic header is damaged")
        bat_off, = struct.unpack_from(">Q", dh, 16)
        self.max_entries, self.block_size = struct.unpack_from(">II", dh, 28)
        if not self.block_size or self.block_size % SECTOR:
            raise ValueError(f"VHD dynamic header is damaged (block size {self.block_size})")
        self.parent_uid = dh[40:56]
        self.parent_name = dh[64:576].decode("utf-16-be", "replace").split("\0", 1)[0]
        bitmap_bytes = self.block_size // SECTOR // 8
        self.bitmap_size = (bitmap_bytes + SECTOR - 1) // SECTOR * SECTOR
        n = self.max_entries
        self.bat = list(struct.unpack(f">{n}I", self.file.pread(bat_off, n * 4, "BAT")))
        self._bitmaps = {}
        if self.type == VHD_DIFF:
            self._open_parent(dh, opener, depth)

    def _open_parent(self, dh, opener, depth):
        names = []
        for i in range(8):
            code, _space, length, _r, off = struct.unpack_from(">4sIIIQ", dh, 576 + i * 24)
            if not length:
                continue
            raw = self.file.pread(off, min(length, 4096), "parent locator")
            if code in (b"W2ru", b"W2ku"):
                names.append(raw.decode("utf-16-le", "replace").split("\0", 1)[0])
            elif code in (b"Wi2r", b"Wi2k"):
                names.append(raw.decode("latin-1").split("\0", 1)[0])
            elif code == b"MacX":
                names.append(raw.decode("utf-8", "replace").replace("file://", "").split("\0", 1)[0])
        names.append(self.parent_name)
        base = os.path.dirname(os.path.abspath(self.path))
        p = _find_file(base, names)
        if p is None:
            self.errors.add(f"{self.name}: parent disk '{self.parent_name}' not found - unchanged areas "
                            "read as zeros")
            self.notes.append(f"missing parent: {self.parent_name}")
            return
        if depth > 64:
            self.errors.add("VHD parent chain too deep (loop?) - stopping")
            return
        self.parent = opener(p, self.errors, _depth=depth + 1) if opener else VhdImage(p, self.errors)
        pft = getattr(self.parent, "footer", None)
        if pft and pft["uid"] != self.parent_uid:
            self.notes.append("parent's unique ID does not match - it may have been modified since the "
                              "snapshot was taken")

    def _bitmap(self, blk, sec):
        bm = self._bitmaps.get(blk)
        if bm is None:
            bm = self.file.pread(sec * SECTOR, self.bitmap_size, "sector bitmap")
            if len(self._bitmaps) > 256:
                self._bitmaps.clear()
            self._bitmaps[blk] = bm
        return bm

    def _parent(self, pos, n):
        if self.parent is None:
            return bytes(n)
        d = self.parent.read(pos, n)
        return d + bytes(n - len(d))

    def _read(self, offset, length):
        if self.type == VHD_FIXED:
            n = max(0, min(length, self._data_end - offset))
            data = self.file.pread(offset, n, "data") if n else b""
            return data + bytes(length - len(data))
        out = bytearray()
        bs = self.block_size
        pos = offset
        end = offset + length
        while pos < end:
            blk, within = divmod(pos, bs)
            n = min(bs - within, end - pos)
            sec = self.bat[blk] if blk < len(self.bat) else 0xFFFFFFFF
            if sec == 0xFFFFFFFF:
                out += self._parent(pos, n) if self.type == VHD_DIFF else bytes(n)
            elif sec * SECTOR >= self.file.size:
                self.errors.add(f"{self.name}: block {blk} points outside the file - zeros substituted",
                                key=(self.path, "blk", blk // 256))
                out += bytes(n)
            else:
                data_off = sec * SECTOR + self.bitmap_size
                if self.type == VHD_DIFF:
                    out += self._diff_block(blk, sec, data_off, pos, within, n)
                else:
                    out += self.file.pread(data_off + within, n, "block")
            pos += n
        return bytes(out)

    def _diff_block(self, blk, sec, data_off, pos, within, n):
        """Merge child sectors (bitmap bit set) with parent sectors."""
        bm = self._bitmap(blk, sec)
        own = self.file.pread(data_off + within, n, "block")
        out = bytearray(n)
        i = 0
        while i < n:
            s = (within + i) // SECTOR
            run_end = min(n, (s + 1) * SECTOR - within)
            mine = bm[s >> 3] >> (7 - (s & 7)) & 1
            # extend the run while the bitmap value stays the same
            while run_end < n:
                s2 = (within + run_end) // SECTOR
                if (bm[s2 >> 3] >> (7 - (s2 & 7)) & 1) != mine:
                    break
                run_end = min(n, (s2 + 1) * SECTOR - within)
            out[i:run_end] = own[i:run_end] if mine else self._parent(pos + i, run_end - i)
            i = run_end
        return bytes(out)

    def is_allocated(self, offset, length):
        if self.type == VHD_FIXED:
            return True
        bs = self.block_size
        for blk in range(offset // bs, (offset + length - 1) // bs + 1):
            sec = self.bat[blk] if blk < len(self.bat) else 0xFFFFFFFF
            if sec != 0xFFFFFFFF:
                return True
            if self.parent is not None and self.parent.is_allocated(blk * bs, bs):
                return True
        return False

    def info(self):
        ft = self.footer
        rows = [("File", self.path), ("Format", self.format),
                ("Virtual size", f"{fmt_size(self.size)} ({self.size:,} bytes)"),
                ("Creator", ft["creator"] or "?"), ("Disk ID", _guid(ft["uid"]))]
        if self.type != VHD_FIXED:
            used = sum(1 for e in self.bat if e != 0xFFFFFFFF)
            rows += [("Block size", fmt_size(self.block_size)),
                     ("Allocated blocks", f"{used:,} of {len(self.bat):,}")]
        if self.type == VHD_DIFF:
            rows.append(("Parent", self.parent_name or "?"))
            if self.parent is not None:
                rows.append(("Parent opened", getattr(self.parent, "path", "?")))
        if not ft["checksum_ok"]:
            rows.append(("Note", "footer checksum mismatch"))
        for n in self.notes:
            rows.append(("Note", n))
        rows.append(("Read problems", str(self.errors.count)))
        return rows

    def close(self):
        self.file.close()
        if self.parent is not None:
            self.parent.close()


# ---------------------------------------------------------------------------
# VHDX
# ---------------------------------------------------------------------------

def is_vhdx(head):
    return head[:8] == b"vhdxfile"


_CRC32C_TABLE = []
for _i in range(256):
    _c = _i
    for _ in range(8):
        _c = (_c >> 1) ^ 0x82F63B78 if _c & 1 else _c >> 1
    _CRC32C_TABLE.append(_c)


def crc32c(data):
    crc = 0xFFFFFFFF
    t = _CRC32C_TABLE
    for b in data:
        crc = t[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc ^ 0xFFFFFFFF


def _crc_ok(buf, at=4):
    stored = struct.unpack_from("<I", buf, at)[0]
    b = bytearray(buf)
    b[at:at + 4] = b"\0\0\0\0"
    return crc32c(bytes(b)) == stored


GUID_BAT = "2dc27766-f623-4200-9d64-115e9bfd4a08"
GUID_METADATA = "8b7ca206-4790-4b9a-b8fe-575f050f886e"
META_FILE_PARAMS = "caa16737-fa36-4d43-b3b6-33f0aa44e76b"
META_DISK_SIZE = "2fa54224-cd1b-4876-b211-5dbed83bf4b8"
META_LOGICAL_SECTOR = "8141bf1d-a96f-4709-ba47-f233a8faab5f"
META_PHYSICAL_SECTOR = "cda348c7-445d-4471-9cc9-e9885251c556"
META_PARENT_LOCATOR = "a8d35f2d-b30b-454d-abf7-d3d84834ab0c"

PAYLOAD_NOT_PRESENT, PAYLOAD_UNDEFINED, PAYLOAD_ZERO, PAYLOAD_UNMAPPED = 0, 1, 2, 3
PAYLOAD_FULLY_PRESENT, PAYLOAD_PARTIALLY_PRESENT = 6, 7
SB_PRESENT = 6


class _LogOverlay:
    """File view with replayed VHDX log entries applied on top (4 KB granularity)."""

    def __init__(self, base):
        self.base = base
        self.size = base.size
        self.pages = {}

    def pread(self, offset, length, what="data"):
        data = bytearray(self.base.pread(offset, length, what))
        if self.pages:
            first = offset // 4096
            last = (offset + length - 1) // 4096
            for p in range(first, last + 1):
                page = self.pages.get(p)
                if page is None:
                    continue
                a = max(offset, p * 4096)
                b = min(offset + length, p * 4096 + 4096)
                data[a - offset:b - offset] = page[a - p * 4096:b - p * 4096]
        return bytes(data)

    def close(self):
        self.base.close()


class VhdxImage(DiskImage):
    def __init__(self, path, errors=None, opener=None, depth=0):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.raw = SafeFile(path, self.errors)
        self.file = self.raw
        self.parent = None
        self.notes = []
        self.parent_locator = {}
        if not is_vhdx(self.raw.pread(0, 8, "signature")):
            raise ValueError("not a VHDX image")
        self.creator = self.raw.pread(8, 512, "creator").decode("utf-16-le", "replace").split("\0", 1)[0]
        hdr = self._pick_header()
        self._replay_log(hdr)
        regions = self._regions()
        if GUID_BAT not in regions or GUID_METADATA not in regions:
            raise ValueError("VHDX region table has no BAT/metadata entry")
        self._read_metadata(*regions[GUID_METADATA])
        bat_off, bat_len = regions[GUID_BAT]
        self.chunk_ratio = ((1 << 23) * self.logical_sector) // self.block_size
        n_blocks = (self.size + self.block_size - 1) // self.block_size
        if self.has_parent:
            n_entries = ((n_blocks + self.chunk_ratio - 1) // self.chunk_ratio) * (self.chunk_ratio + 1)
        else:
            n_entries = n_blocks + (n_blocks - 1) // self.chunk_ratio
        n_entries = min(n_entries, bat_len // 8)
        self.bat = struct.unpack(f"<{n_entries}Q", self.file.pread(bat_off, n_entries * 8, "BAT"))
        self._bitmaps = {}
        kind = "differencing" if self.has_parent else ("fixed" if self.leave_allocated else "dynamic")
        self.format = f"VHDX ({kind})"
        if self.has_parent:
            self._open_parent(opener, depth)

    # -- headers & regions -------------------------------------------------
    def _pick_header(self):
        best = None
        for off in (64 * 1024, 128 * 1024):
            h = self.raw.pread(off, 4096, "header")
            if h[:4] != b"head":
                continue
            ok = _crc_ok(h)
            seq = struct.unpack_from("<Q", h, 8)[0]
            cand = dict(ok=ok, seq=seq, log_guid=h[48:64], log_len=struct.unpack_from("<I", h, 68)[0],
                        log_off=struct.unpack_from("<Q", h, 72)[0], version=struct.unpack_from("<H", h, 66)[0])
            if best is None or (ok, seq) > (best["ok"], best["seq"]):
                best = cand
        if best is None:
            raise ValueError("both VHDX headers are damaged")
        if not best["ok"]:
            self.errors.add(f"{self.name}: VHDX header checksum mismatch - using it anyway")
        return best

    def _regions(self):
        for which, off in (("primary", 192 * 1024), ("backup", 256 * 1024)):
            rt = self.file.pread(off, 64 * 1024, "region table")
            if rt[:4] != b"regi":
                continue
            ok = _crc_ok(rt)
            count = struct.unpack_from("<I", rt, 8)[0]
            if count > 2047:
                continue
            regions = {}
            for i in range(count):
                e = rt[16 + i * 32:48 + i * 32]
                foff, length = struct.unpack_from("<QI", e, 16)
                regions[_guid(e[:16])] = (foff, length)
            if GUID_BAT in regions and GUID_METADATA in regions:
                if which == "backup" or not ok:
                    self.errors.add(f"{self.name}: primary region table damaged - using {which} copy")
                return regions
        raise ValueError("VHDX region tables are damaged")

    def _read_metadata(self, off, length):
        mt = self.file.pread(off, min(length, 64 * 1024), "metadata")
        if mt[:8] != b"metadata":
            raise ValueError("VHDX metadata region is damaged")
        count = struct.unpack_from("<H", mt, 10)[0]
        items = {}
        for i in range(min(count, 2047)):
            e = mt[32 + i * 32:64 + i * 32]
            ioff, ilen = struct.unpack_from("<II", e, 16)
            items[_guid(e[:16])] = self.file.pread(off + ioff, ilen, "metadata item")
        fp = items.get(META_FILE_PARAMS)
        if not fp or META_DISK_SIZE not in items:
            raise ValueError("VHDX metadata is missing required items")
        self.block_size, flags = struct.unpack_from("<II", fp)
        self.leave_allocated = bool(flags & 1)
        self.has_parent = bool(flags & 2)
        self.size = struct.unpack_from("<Q", items[META_DISK_SIZE])[0]
        self.logical_sector = struct.unpack_from("<I", items.get(META_LOGICAL_SECTOR, b"\0\2\0\0"))[0] or 512
        self.physical_sector = struct.unpack_from("<I", items.get(META_PHYSICAL_SECTOR, b"\0\2\0\0"))[0]
        if not self.block_size or self.block_size & (self.block_size - 1):
            raise ValueError(f"VHDX metadata is damaged (block size {self.block_size})")
        pl = items.get(META_PARENT_LOCATOR)
        if pl and len(pl) >= 20:
            n = struct.unpack_from("<H", pl, 18)[0]
            for i in range(n):
                koff, voff, klen, vlen = struct.unpack_from("<IIHH", pl, 20 + i * 12)
                k = pl[koff:koff + klen].decode("utf-16-le", "replace")
                v = pl[voff:voff + vlen].decode("utf-16-le", "replace")
                self.parent_locator[k] = v

    # -- log replay ------------------------------------------------------------
    def _replay_log(self, hdr):
        if hdr["log_guid"] == bytes(16) or not hdr["log_len"]:
            return
        log = self.raw.pread(hdr["log_off"], hdr["log_len"], "log")
        entries = []
        for pos in range(0, len(log) - 4096 + 1, 4096):
            if log[pos:pos + 4] != b"loge":
                continue
            elen, _tail, seq, ndesc = struct.unpack_from("<IIQI", log, pos + 8)
            if elen % 4096 or not 0 < elen <= len(log) or log[pos + 32:pos + 48] != hdr["log_guid"]:
                continue
            entry = log[pos:pos + elen] if pos + elen <= len(log) else log[pos:] + log[:pos + elen - len(log)]
            if not _crc_ok(entry):
                continue
            entries.append((seq, entry, ndesc))
        if not entries:
            return
        overlay = _LogOverlay(self.raw)
        applied = 0
        for seq, entry, ndesc in sorted(entries, key=lambda e: e[0]):
            desc_sectors = (64 + 32 * ndesc + 4095) // 4096
            data_pos = desc_sectors * 4096
            for d in range(ndesc):
                dp = 64 + d * 32
                sig = entry[dp:dp + 4]
                if sig == b"zero":
                    zlen, foff = struct.unpack_from("<QQ", entry, dp + 8)
                    for p in range(foff // 4096, (foff + zlen) // 4096):
                        overlay.pages[p] = bytes(4096)
                elif sig == b"desc":
                    trailing, leading, foff = struct.unpack_from("<IQQ", entry, dp + 4)
                    sec = entry[data_pos:data_pos + 4096]
                    data_pos += 4096
                    if sec[:4] != b"data":
                        continue
                    page = struct.pack("<Q", leading) + sec[8:4092] + struct.pack("<I", trailing)
                    overlay.pages[foff // 4096] = page
            applied += 1
        self.file = overlay
        self.notes.append(f"image was not closed cleanly - replayed {applied} log entries in memory "
                          "(the file itself was not modified)")

    # -- parent ------------------------------------------------------------------
    def _open_parent(self, opener, depth):
        loc = self.parent_locator
        base = os.path.dirname(os.path.abspath(self.path))
        p = _find_file(base, [loc.get("relative_path"), loc.get("absolute_win32_path"),
                              loc.get("volume_path")])
        if p is None:
            name = loc.get("relative_path") or loc.get("absolute_win32_path") or "?"
            self.errors.add(f"{self.name}: parent disk '{name}' not found - unchanged areas read as zeros")
            self.notes.append(f"missing parent: {name}")
            return
        if depth > 64:
            self.errors.add("VHDX parent chain too deep (loop?) - stopping")
            return
        self.parent = opener(p, self.errors, _depth=depth + 1) if opener else VhdxImage(p, self.errors)

    # -- data ------------------------------------------------------------------
    def _entry(self, idx):
        if idx >= len(self.bat):
            return PAYLOAD_NOT_PRESENT, 0
        e = self.bat[idx]
        return e & 7, (e >> 20) * MB

    def _bitmap(self, chunk):
        bm = self._bitmaps.get(chunk)
        if bm is None:
            state, off = self._entry(chunk * (self.chunk_ratio + 1) + self.chunk_ratio)
            bm = self.file.pread(off, MB, "sector bitmap") if state == SB_PRESENT and off else bytes(MB)
            if len(self._bitmaps) > 16:
                self._bitmaps.clear()
            self._bitmaps[chunk] = bm
        return bm

    def _parent(self, pos, n):
        if self.parent is None:
            return bytes(n)
        d = self.parent.read(pos, n)
        return d + bytes(n - len(d))

    def _read(self, offset, length):
        out = bytearray()
        bs = self.block_size
        pos = offset
        end = offset + length
        while pos < end:
            blk, within = divmod(pos, bs)
            n = min(bs - within, end - pos)
            state, off = self._entry(blk + blk // self.chunk_ratio)
            if state == PAYLOAD_FULLY_PRESENT:
                if off == 0 or off >= self.file.size:
                    self.errors.add(f"{self.name}: block {blk} points outside the file - zeros substituted",
                                    key=(self.path, "blk", blk // 256))
                    out += bytes(n)
                else:
                    out += self.file.pread(off + within, n, "block")
            elif state == PAYLOAD_PARTIALLY_PRESENT and self.has_parent:
                out += self._partial(blk, off, pos, within, n)
            elif state in (PAYLOAD_NOT_PRESENT, PAYLOAD_UNDEFINED) and self.has_parent:
                out += self._parent(pos, n)
            else:  # zero / unmapped / not present without parent
                out += bytes(n)
            pos += n
        return bytes(out)

    def _partial(self, blk, off, pos, within, n):
        ls = self.logical_sector
        chunk = blk // self.chunk_ratio
        bm = self._bitmap(chunk)
        first_sector = (blk % self.chunk_ratio) * (self.block_size // ls)
        own = self.file.pread(off + within, n, "block")
        out = bytearray(n)
        i = 0
        while i < n:
            s = first_sector + (within + i) // ls
            run_end = min(n, ((within + i) // ls + 1) * ls - within)
            bit = bm[s >> 3] >> (s & 7) & 1  # VHDX bitmaps are LSB-first
            out[i:run_end] = own[i:run_end] if bit else self._parent(pos + i, run_end - i)
            i = run_end
        return bytes(out)

    def is_allocated(self, offset, length):
        bs = self.block_size
        for blk in range(offset // bs, (offset + length - 1) // bs + 1):
            state, _ = self._entry(blk + blk // self.chunk_ratio)
            if state in (PAYLOAD_FULLY_PRESENT, PAYLOAD_PARTIALLY_PRESENT):
                return True
            if self.has_parent and state in (PAYLOAD_NOT_PRESENT, PAYLOAD_UNDEFINED) and \
                    self.parent is not None and self.parent.is_allocated(blk * bs, bs):
                return True
        return False

    def info(self):
        rows = [("File", self.path), ("Format", self.format),
                ("Virtual size", f"{fmt_size(self.size)} ({self.size:,} bytes)"),
                ("Block size", fmt_size(self.block_size)),
                ("Sector size", f"{self.logical_sector} logical / {self.physical_sector} physical"),
                ("Creator", self.creator or "?")]
        n_blocks = (self.size + self.block_size - 1) // self.block_size
        present = sum(1 for b in range(n_blocks)
                      if self._entry(b + b // self.chunk_ratio)[0] in (PAYLOAD_FULLY_PRESENT,
                                                                        PAYLOAD_PARTIALLY_PRESENT))
        rows.append(("Allocated blocks", f"{present:,} of {n_blocks:,}"))
        for k in ("relative_path", "absolute_win32_path"):
            if k in self.parent_locator:
                rows.append((f"Parent ({k})", self.parent_locator[k]))
        if self.parent is not None:
            rows.append(("Parent opened", getattr(self.parent, "path", "?")))
        for n in self.notes:
            rows.append(("Note", n))
        rows.append(("Read problems", str(self.errors.count)))
        return rows

    def close(self):
        self.file.close()
        if self.parent is not None:
            self.parent.close()
