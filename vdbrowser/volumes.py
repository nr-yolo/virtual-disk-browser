"""Partition table, LVM and file-system signature detection.

Handles MBR (with extended/logical partitions), GPT (falling back to the backup
header when the primary is damaged), Linux LVM2 logical volumes, and a
signature-based "deep scan" that finds file systems even when the partition
table itself is destroyed.
"""

import re
import struct
import uuid
import zlib

from .disk import SECTOR, SliceImage, MappedImage, fmt_size


class Volume:
    """A candidate file-system container (partition, LV, or whole disk)."""

    def __init__(self, image, label, kind, start=0, note=""):
        self.image = image          # DiskImage (slice / mapped / whole disk)
        self.label = label          # human readable name
        self.kind = kind            # partition type description
        self.start = start          # byte offset on the physical disk (informational)
        self.note = note
        self.fs_hint = detect_fs(image)
        self.children = []          # e.g. LVM logical volumes inside a PV

    @property
    def size(self):
        return self.image.size

    def title(self):
        parts = [self.label]
        if self.fs_hint:
            parts.append(self.fs_hint)
        elif self.kind:
            parts.append(self.kind)
        parts.append(fmt_size(self.size))
        return " - ".join(parts)


# ---------------------------------------------------------------------------
# File-system signatures
# ---------------------------------------------------------------------------

def detect_fs(img, offset=0):
    """Return a short name of the file system at ``offset`` or None."""
    b = img.read(offset, 4096)
    if len(b) < 1536:
        return None
    if b[3:11] == b"NTFS    ":
        return "NTFS"
    if b[3:11] == b"EXFAT   ":
        return "exFAT"
    if b[510:512] == b"\x55\xaa":
        if b[82:87] == b"FAT32":
            return "FAT32"
        if b[54:59] in (b"FAT12", b"FAT16", b"FAT  "):
            return b[54:59].decode().strip() or "FAT"
    if b[1080:1082] == b"\x53\xef":
        compat, incompat = struct.unpack_from("<II", b, 1024 + 92)
        if incompat & 0x2C0:  # extents | 64bit | flex_bg
            return "ext4"
        return "ext3" if compat & 0x4 else "ext2"
    if b[0:4] == b"XFSB":
        return "XFS"
    if b[512:520] == b"LABELONE" or b[0:8] == b"LABELONE":
        return "LVM2 PV"
    if b[1024:1026] in (b"H+", b"HX"):
        return "HFS+"
    if b[0:4] == b"NXSB" or b[32:36] == b"NXSB":
        return "APFS"
    if b[0:8] == b"\xeb\x3c\x90mkdos" or b[3:8] == b"mkfs.":
        return "FAT"
    more = img.read(offset + 0x10000, 0x100)
    if more[0x40:0x48] == b"_BHRfS_M":
        return "Btrfs"
    if img.read(offset + 0x8000, 6)[1:6] == b"CD001":
        return "ISO9660"
    if b[0:4] == b"\x00\x00\x00\x00" and img.read(offset + 0xFF6, 10) == b"SWAPSPACE2":
        return "Linux swap"
    if img.read(offset + 0xFF6, 10) == b"SWAPSPACE2":
        return "Linux swap"
    if b[0:8] == b"-FVE-FS-" or b[3:11] == b"-FVE-FS-":
        return "BitLocker (encrypted)"
    if b[0:6] == b"LUKS\xba\xbe":
        return "LUKS (encrypted)"
    if b[0:4] == b"ReFS" or b[3:7] == b"ReFS":
        return "ReFS"
    return None


def fs_extent(img, offset, fs):
    """Approximate byte size of a file system from its boot sector (for deep scan)."""
    b = img.read(offset, 4096)
    try:
        if fs == "NTFS":
            bps = struct.unpack_from("<H", b, 11)[0]
            return struct.unpack_from("<Q", b, 40)[0] * bps + bps
        if fs.startswith("FAT"):
            bps = struct.unpack_from("<H", b, 11)[0]
            total = struct.unpack_from("<H", b, 19)[0] or struct.unpack_from("<I", b, 32)[0]
            return total * bps
        if fs == "exFAT":
            return struct.unpack_from("<Q", b, 72)[0] << b[108]
        if fs.startswith("ext"):
            blocks = struct.unpack_from("<I", b, 1024 + 4)[0]
            hi = struct.unpack_from("<I", b, 1024 + 0x150)[0] if struct.unpack_from("<I", b, 1024 + 96)[0] & 0x80 else 0
            bs = 1024 << struct.unpack_from("<I", b, 1024 + 24)[0]
            return ((hi << 32) | blocks) * bs
        if fs == "XFS":
            bs = struct.unpack_from(">I", b, 4)[0]
            return struct.unpack_from(">Q", b, 8)[0] * bs
    except (struct.error, IndexError):
        pass
    return 0


# ---------------------------------------------------------------------------
# Partition tables
# ---------------------------------------------------------------------------

MBR_TYPES = {
    0x01: "FAT12", 0x04: "FAT16", 0x05: "Extended", 0x06: "FAT16", 0x07: "NTFS/exFAT",
    0x0B: "FAT32", 0x0C: "FAT32 (LBA)", 0x0E: "FAT16 (LBA)", 0x0F: "Extended (LBA)",
    0x11: "Hidden FAT12", 0x12: "Recovery", 0x14: "Hidden FAT16", 0x16: "Hidden FAT16",
    0x17: "Hidden NTFS", 0x1B: "Hidden FAT32", 0x1C: "Hidden FAT32", 0x27: "Windows RE",
    0x42: "Windows dynamic", 0x82: "Linux swap", 0x83: "Linux", 0x85: "Linux extended",
    0x8E: "Linux LVM", 0xA5: "FreeBSD", 0xA6: "OpenBSD", 0xA8: "macOS", 0xAF: "HFS+",
    0xEE: "GPT protective", 0xEF: "EFI System", 0xFD: "Linux RAID",
}
EXTENDED = (0x05, 0x0F, 0x85)

GPT_TYPES = {
    "c12a7328-f81f-11d2-ba4b-00a0c93ec93b": "EFI System",
    "e3c9e316-0b5c-4db8-817d-f92df00215ae": "Microsoft reserved",
    "ebd0a0a2-b9e5-4433-87c0-68b6b72699c7": "Basic data (Windows)",
    "de94bba4-06d1-4d40-a16a-bfd50179d6ac": "Windows recovery",
    "5808c8aa-7e8f-42e0-85d2-e1e90434cfb3": "LDM metadata",
    "af9b60a0-1431-4f62-bc68-3311714a69ad": "LDM data",
    "0fc63daf-8483-4772-8e79-3d69d8477de4": "Linux filesystem",
    "e6d6d379-f507-44c2-a23c-238f2a3df928": "Linux LVM",
    "0657fd6d-a4ab-43c4-84e5-0933c84b4f4f": "Linux swap",
    "a19d880f-05fc-4d3b-a006-743f0f84911e": "Linux RAID",
    "4f68bce3-e8cd-4db1-96e7-fbcaf984b709": "Linux root (x86-64)",
    "44479540-f297-41b2-9af7-d131d5f0458a": "Linux root (x86)",
    "933ac7e1-2eb4-4f13-b844-0e14e2aef915": "Linux /home",
    "bc13c2ff-59e6-4262-a352-b275fd6f7172": "Linux /boot (XBOOTLDR)",
    "21686148-6449-6e6f-744e-656564454649": "BIOS boot",
    "48465300-0000-11aa-aa11-00306543ecac": "Apple HFS+",
    "7c3457ef-0000-11aa-aa11-00306543ecac": "Apple APFS",
    "516e7cb4-6ecf-11d6-8ff8-00022d09712b": "FreeBSD",
    "6a898cc3-1dd2-11b2-99a6-080020736631": "ZFS",
}


def _mbr_entries(sector):
    out = []
    for i in range(4):
        e = sector[446 + i * 16: 462 + i * 16]
        ptype = e[4]
        lba, count = struct.unpack_from("<II", e, 8)
        if ptype and count:
            out.append((i, ptype, lba, count, e[0] == 0x80))
    return out


def parse_mbr(img, errors):
    s0 = img.read(0, SECTOR)
    if len(s0) < SECTOR or s0[510:512] != b"\x55\xaa":
        return None
    # A boot sector of a partitionless file system also ends in 55AA.
    if detect_fs(img) in ("NTFS", "exFAT", "FAT12", "FAT16", "FAT32", "FAT"):
        return None
    entries = _mbr_entries(s0)
    if any(p[1] == 0xEE for p in entries):
        return "gpt"
    disk_sectors = img.size // SECTOR
    parts = []
    for idx, ptype, lba, count, boot in entries:
        if lba >= disk_sectors:
            errors.add(f"MBR entry {idx + 1} starts beyond end of disk - ignored")
            continue
        if ptype in EXTENDED:
            parts.extend(_parse_ebr_chain(img, lba, errors, disk_sectors))
            continue
        parts.append(dict(num=idx + 1, start=lba * SECTOR, size=min(count, disk_sectors - lba) * SECTOR,
                          type=MBR_TYPES.get(ptype, f"type 0x{ptype:02X}"), code=ptype, name=""))
    return parts


def _parse_ebr_chain(img, ext_lba, errors, disk_sectors):
    parts = []
    seen = set()
    cur = ext_lba
    num = 5
    while cur and cur not in seen and len(parts) < 128:
        seen.add(cur)
        ebr = img.read(cur * SECTOR, SECTOR)
        if ebr[510:512] != b"\x55\xaa":
            errors.add(f"extended partition chain broken at sector {cur}")
            break
        entries = _mbr_entries(ebr)
        nxt = 0
        for _i, ptype, lba, count, _b in entries[:2]:
            if ptype in EXTENDED:
                nxt = ext_lba + lba
            else:
                start = cur + lba
                if start < disk_sectors:
                    parts.append(dict(num=num, start=start * SECTOR,
                                      size=min(count, disk_sectors - start) * SECTOR,
                                      type=MBR_TYPES.get(ptype, f"type 0x{ptype:02X}"), code=ptype,
                                      name="logical"))
                    num += 1
        cur = nxt
    return parts


def _gpt_header(img, lba):
    h = img.read(lba * SECTOR, SECTOR)
    if h[:8] != b"EFI PART":
        return None
    hsize = struct.unpack_from("<I", h, 12)[0]
    crc_ok = False
    if 92 <= hsize <= SECTOR:
        hb = bytearray(h[:hsize])
        crc = struct.unpack_from("<I", hb, 16)[0]
        hb[16:20] = b"\0\0\0\0"
        crc_ok = (zlib.crc32(bytes(hb)) & 0xFFFFFFFF) == crc
    (my_lba, alt_lba, first, last) = struct.unpack_from("<QQQQ", h, 24)
    entries_lba, n, esize, ecrc = struct.unpack_from("<QIII", h, 72)
    return dict(crc_ok=crc_ok, alt=alt_lba, entries_lba=entries_lba, n=n, esize=esize,
                ecrc=ecrc, first=first, last=last)


def parse_gpt(img, errors):
    disk_sectors = img.size // SECTOR
    candidates = []
    primary = _gpt_header(img, 1)
    if primary:
        candidates.append(("primary", primary))
    backup_lba = primary["alt"] if primary and 0 < primary["alt"] < disk_sectors else disk_sectors - 1
    backup = _gpt_header(img, backup_lba)
    if backup is None and backup_lba != disk_sectors - 1:
        backup = _gpt_header(img, disk_sectors - 1)
    if backup:
        candidates.append(("backup", backup))
    # prefer headers whose CRCs check out
    candidates.sort(key=lambda c: not c[1]["crc_ok"])
    for which, h in candidates:
        if not (0 < h["n"] <= 1024 and 128 <= h["esize"] <= 4096):
            continue
        raw = img.read(h["entries_lba"] * SECTOR, h["n"] * h["esize"])
        entries_ok = (zlib.crc32(raw) & 0xFFFFFFFF) == h["ecrc"]
        parts = []
        for i in range(h["n"]):
            e = raw[i * h["esize"]:(i + 1) * h["esize"]]
            if len(e) < 128 or e[:16] == bytes(16):
                continue
            tguid = str(uuid.UUID(bytes_le=bytes(e[:16])))
            first, last = struct.unpack_from("<QQ", e, 32)
            if first >= disk_sectors or last < first:
                errors.add(f"GPT entry {i + 1} has invalid bounds - ignored")
                continue
            last = min(last, disk_sectors - 1)
            name = e[56:128].decode("utf-16-le", "replace").split("\0", 1)[0]
            parts.append(dict(num=i + 1, start=first * SECTOR, size=(last - first + 1) * SECTOR,
                              type=GPT_TYPES.get(tguid, tguid), code=tguid, name=name))
        if parts or entries_ok:
            if which == "backup":
                errors.add("primary GPT is damaged - using backup GPT at end of disk")
            elif not h["crc_ok"] or not entries_ok:
                errors.add("GPT checksum mismatch - table used anyway")
            return parts
    errors.add("GPT protective MBR found but no usable GPT header - try Deep Scan")
    return []


# ---------------------------------------------------------------------------
# LVM2
# ---------------------------------------------------------------------------

_LVM_TOKEN = re.compile(r'\s*(?:(#[^\n]*)|("(?:[^"\\]|\\.)*")|([\[\]{}=,])|([^\s\[\]{}=,"#]+))')


def parse_lvm_config(text):
    """Parse LVM's text metadata format into nested dicts/lists."""
    tokens = []
    pos = 0
    while pos < len(text):
        m = _LVM_TOKEN.match(text, pos)
        if not m or m.end() == pos:
            break
        pos = m.end()
        if m.group(1):
            continue
        if m.group(2) is not None:
            tokens.append(("s", m.group(2)[1:-1].replace('\\"', '"')))
        elif m.group(3):
            tokens.append(("p", m.group(3)))
        elif m.group(4):
            v = m.group(4)
            tokens.append(("v", int(v) if re.fullmatch(r"-?\d+", v) else v))
    idx = 0

    def value():
        nonlocal idx
        kind, v = tokens[idx]
        if kind == "p" and v == "[":
            idx += 1
            arr = []
            while idx < len(tokens) and tokens[idx] != ("p", "]"):
                if tokens[idx] == ("p", ","):
                    idx += 1
                    continue
                arr.append(tokens[idx][1])
                idx += 1
            idx += 1
            return arr
        idx += 1
        return v

    def block():
        nonlocal idx
        d = {}
        while idx < len(tokens):
            kind, v = tokens[idx]
            if kind == "p" and v == "}":
                idx += 1
                return d
            if idx + 1 >= len(tokens):
                idx += 1
                break
            nk, nv = tokens[idx + 1]
            if nk == "p" and nv == "{":
                idx += 2
                d[str(v)] = block()
            elif nk == "p" and nv == "=":
                idx += 2
                if idx < len(tokens):
                    d[str(v)] = value()
            else:
                idx += 1
        return d

    return block()


class LvmPV:
    def __init__(self, image, label_sector, pv_uuid, data_areas, meta_areas):
        self.image = image
        self.label_sector = label_sector
        self.uuid = pv_uuid
        self.data_areas = data_areas
        self.meta_areas = meta_areas


def read_lvm_pv(img):
    for sec in range(4):
        lbl = img.read(sec * SECTOR, SECTOR)
        if lbl[:8] == b"LABELONE" and lbl[24:32] == b"LVM2 001":
            off = struct.unpack_from("<I", lbl, 20)[0]
            p = lbl[off:]
            pv_uuid = p[:32].decode("ascii", "replace")
            pos = 40
            data, meta = [], []
            for target in (data, meta):
                while pos + 16 <= len(p):
                    o, s = struct.unpack_from("<QQ", p, pos)
                    pos += 16
                    if o == 0:
                        break
                    target.append((o, s))
            return LvmPV(img, sec, pv_uuid, data, meta)
    return None


def _lvm_metadata_texts(pv):
    """Yield candidate VG metadata texts, current copy first then older ones in the ring."""
    for moff, msize in pv.meta_areas:
        hdr = pv.image.read(moff, SECTOR)
        if hdr[4:20] != b" LVM2 x[5A%r0N*>":
            continue
        start, size = struct.unpack_from("<QQ", hdr, 24)
        o, s = struct.unpack_from("<QQ", hdr, 40)
        if s and o:
            if o + s <= size:
                text = pv.image.read(moff + o, s)
            else:  # wraps around the circular buffer
                first = size - o
                text = pv.image.read(moff + o, first) + pv.image.read(moff + 512, s - first)
            yield text.split(b"\0", 1)[0]
        # older copies remain in the ring buffer - useful when the current one is damaged
        ring = pv.image.read(moff + 512, min(msize, 8 << 20) - 512)
        for chunk in ring.split(b"\0"):
            if b"seqno" in chunk and b"physical_volumes" in chunk:
                i = chunk.find(b"{")
                j = chunk.rfind(b"\n", 0, i)
                yield chunk[j + 1:] if j >= 0 else chunk


def _parse_vg(pv, errors):
    best = None
    for text in _lvm_metadata_texts(pv):
        try:
            cfg = parse_lvm_config(text.decode("utf-8", "replace"))
        except (IndexError, ValueError):
            continue
        for name, vg in cfg.items():
            if isinstance(vg, dict) and "physical_volumes" in vg and "extent_size" in vg:
                seq = vg.get("seqno", 0) if isinstance(vg.get("seqno"), int) else 0
                if best is None:
                    best = (name, vg)
                elif seq > best[1].get("seqno", 0):
                    best = (name, vg)
        if best is not None:
            break
    if best is None:
        errors.add("LVM physical volume found but its metadata could not be parsed")
    return best


def lvm_volumes(pvs, errors):
    """Assemble logical volumes from a list of LvmPV objects (same or different VGs)."""
    out = []
    by_uuid = {pv.uuid.replace("-", ""): pv for pv in pvs}
    done_vgs = set()
    for pv in pvs:
        vgi = _parse_vg(pv, errors)
        if not vgi:
            continue
        vg_name, vg = vgi
        vg_id = vg.get("id", vg_name)
        if vg_id in done_vgs:
            continue
        done_vgs.add(vg_id)
        ext_bytes = int(vg["extent_size"]) * SECTOR
        pv_map = {}
        for key, pvd in vg.get("physical_volumes", {}).items():
            if not isinstance(pvd, dict):
                continue
            real = by_uuid.get(str(pvd.get("id", "")).replace("-", ""))
            if real is None:
                errors.add(f"LVM: physical volume {key} of VG '{vg_name}' is not on this disk - "
                           "its parts read as zeros")
                continue
            pv_map[key] = (real, int(pvd.get("pe_start", 2048)) * SECTOR)
        for lv_name, lv in vg.get("logical_volumes", {}).items():
            if not isinstance(lv, dict):
                continue
            segs = []
            total = 0
            unsupported = set()
            for skey, seg in lv.items():
                if not (skey.startswith("segment") and isinstance(seg, dict)):
                    continue
                start = int(seg.get("start_extent", 0)) * ext_bytes
                count = int(seg.get("extent_count", 0)) * ext_bytes
                total = max(total, start + count)
                stype = seg.get("type", "striped")
                stripes = seg.get("stripes", [])
                if stype == "striped" and int(seg.get("stripe_count", 1)) == 1 and len(stripes) >= 2:
                    target = pv_map.get(stripes[0])
                    if target:
                        pv_obj, pe_start = target
                        segs.append((start, count, pv_obj.image, pe_start + int(stripes[1]) * ext_bytes))
                elif stype == "striped" and int(seg.get("stripe_count", 1)) > 1:
                    segs.extend(_striped_segments(seg, start, count, ext_bytes, pv_map))
                else:
                    unsupported.add(stype)
            if not segs:
                if unsupported:
                    errors.add(f"LVM volume {vg_name}/{lv_name}: segment type(s) "
                               f"{', '.join(sorted(unsupported))} not supported")
                continue
            note = f"unsupported segment types: {', '.join(sorted(unsupported))}" if unsupported else ""
            img = MappedImage(segs, total, pvs[0].image.errors, name=f"{vg_name}/{lv_name}")
            out.append(Volume(img, f"LVM {vg_name}/{lv_name}", "LVM logical volume", note=note))
    return out


def _striped_segments(seg, start, count, ext_bytes, pv_map):
    """Expand a multi-stripe segment into many small linear pieces."""
    n = int(seg.get("stripe_count", 1))
    ssize = int(seg.get("stripe_size", 128)) * SECTOR
    stripes = seg.get("stripes", [])
    targets = []
    for i in range(n):
        t = pv_map.get(stripes[2 * i]) if 2 * i + 1 < len(stripes) else None
        targets.append((t, int(stripes[2 * i + 1]) * ext_bytes if t else 0))
    out = []
    pos = 0
    chunk = 0
    if count // ssize > 2_000_000:  # avoid absurd segment lists
        return out
    while pos < count:
        idx = chunk % n
        row = chunk // n
        t, base = targets[idx]
        if t:
            pv_obj, pe_start = t
            out.append((start + pos, min(ssize, count - pos), pv_obj.image, pe_start + base + row * ssize))
        pos += ssize
        chunk += 1
    return out


# ---------------------------------------------------------------------------
# Top-level discovery
# ---------------------------------------------------------------------------

def discover(disk, errors, deep=False, progress=None, cancel=None):
    """Return a list of Volume objects found on ``disk``."""
    vols = []
    table = parse_mbr(disk, errors)
    scheme = "none"
    parts = []
    if table == "gpt":
        scheme = "GPT"
        parts = parse_gpt(disk, errors)
    elif table:
        scheme = "MBR"
        parts = table
    elif disk.read(SECTOR, 8) == b"EFI PART":
        scheme = "GPT"
        parts = parse_gpt(disk, errors)

    for p in parts:
        img = SliceImage(disk, p["start"], p["size"], name=f"partition {p['num']}")
        label = f"Partition {p['num']}" + (f" ({p['name']})" if p["name"] and p["name"] != "logical" else "")
        vols.append(Volume(img, label, p["type"], start=p["start"]))

    if not parts:
        fs = detect_fs(disk)
        if fs:
            vols.append(Volume(disk, "Whole disk", "unpartitioned", start=0))

    if deep or not vols:
        found = deep_scan(disk, errors, existing=vols, progress=progress, cancel=cancel)
        vols.extend(found)

    # LVM: collect PVs from all volumes and expose their logical volumes
    pvs = []
    for v in vols:
        if v.fs_hint == "LVM2 PV":
            pv = read_lvm_pv(v.image)
            if pv:
                pvs.append((v, pv))
    if pvs:
        lvs = lvm_volumes([pv for _, pv in pvs], errors)
        pvs[0][0].children.extend(lvs)
    return scheme, vols


def deep_scan(disk, errors, existing=(), progress=None, cancel=None):
    """Look for file-system boot sectors at common alignments when tables are damaged."""
    covered = [(v.start, v.start + v.size) for v in existing if v.image is not disk]
    # a whole-disk file system must not hide older partitions beneath it, but it must not be found twice
    known_starts = {v.start for v in existing}
    candidates = set()
    total = disk.size // SECTOR
    for step, base in ((2048, 0), (16065, 0), (16065, 63), (63, 0)):
        limit = total if step != 63 else min(total, 2 * 1024 * 1024 * 2)  # 63-step only first 2 GB
        candidates.update(range(base, limit, step))
    candidates.update((0, 63, 128, 256, 2048, 4096))
    cands = sorted(c for c in candidates if c < total)
    found = []
    n = len(cands)
    for i, sec in enumerate(cands):
        if cancel is not None and cancel.is_set():
            break
        if progress and i % 2000 == 0:
            progress(i, n, f"Deep scan: sector {sec:,} of {total:,}")
        off = sec * SECTOR
        if off in known_starts or any(a <= off < b for a, b in covered):
            continue
        if not disk.is_allocated(off, 4096):
            continue
        fs = detect_fs(disk, off)
        if not fs or fs in ("ISO9660",):
            continue
        size = fs_extent(disk, off, fs) or (disk.size - off)
        size = min(size, disk.size - off)
        if size < 64 * 1024:
            continue
        img = SliceImage(disk, off, size, name=f"found@{sec}")
        found.append(Volume(img, f"Recovered volume @ sector {sec}", "found by deep scan", start=off))
        covered.append((off, off + size))
    if found:
        errors.add(f"deep scan found {len(found)} file system(s) outside the partition table")
    if progress:
        progress(n, n, "Deep scan complete")
    return found
