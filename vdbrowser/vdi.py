"""VirtualBox VDI reader (fixed, dynamic and differencing images).

Differencing images (VirtualBox snapshots, usually ``Snapshots/{uuid}.vdi``)
do not store their parent's path - only its UUID - so the parent is found by
scanning nearby .vdi/.vmdk/.vhd files for a matching UUID.

Damage tolerance
  * block-map entries pointing outside the file read as zeros (fixed images
    fall back to the linear layout they always use)
  * a truncated file only blanks the missing blocks
  * a missing parent only blanks the blocks the snapshot did not change
"""

import glob
import os
import struct
import uuid

from .disk import DiskImage, SafeFile, ErrorLog, fmt_size

VDI_SIGNATURE = 0xBEDA107F
TYPE_NAMES = {1: "dynamic", 2: "fixed", 3: "undo", 4: "differencing"}
BLOCK_FREE = 0xFFFFFFFF
BLOCK_ZERO = 0xFFFFFFFE


def is_vdi(head):
    return len(head) >= 0x48 and struct.unpack_from("<I", head, 0x40)[0] == VDI_SIGNATURE


def read_vdi_uuid(path):
    """Return the creation UUID of a VDI file (or None)."""
    try:
        with open(path, "rb") as f:
            h = f.read(0x200)
        if is_vdi(h):
            return h[0x188:0x198]
    except OSError:
        pass
    return None


class VdiImage(DiskImage):
    def __init__(self, path, errors=None, opener=None, depth=0):
        super().__init__(errors)
        self.path = path
        self.name = os.path.basename(path)
        self.file = SafeFile(path, self.errors)
        self.parent = None
        self.notes = []
        h = self.file.pread(0, 0x200, "header")
        if not is_vdi(h):
            raise ValueError("not a VDI image")
        version = struct.unpack_from("<I", h, 0x44)[0]
        if version >> 16 != 1:
            raise ValueError(f"unsupported VDI version {version >> 16}.{version & 0xFFFF}")
        (self.type, self.flags) = struct.unpack_from("<II", h, 0x4C)
        self.comment = h[0x54:0x154].split(b"\0", 1)[0].decode("utf-8", "replace")
        self.off_blocks, self.off_data = struct.unpack_from("<II", h, 0x154)
        self.sector_size = struct.unpack_from("<I", h, 0x168)[0] or 512
        self.size = struct.unpack_from("<Q", h, 0x170)[0]
        self.block_size, self.block_extra, self.n_blocks, self.n_alloc = struct.unpack_from("<IIII", h, 0x178)
        self.uuid_create = h[0x188:0x198]
        self.uuid_modify = h[0x198:0x1A8]
        self.uuid_parent = h[0x1A8:0x1B8]
        if not (self.block_size and self.block_size & (self.block_size - 1) == 0):
            raise ValueError(f"VDI header is damaged (block size {self.block_size})")
        need = (self.size + self.block_size - 1) // self.block_size
        if self.n_blocks < need:
            self.errors.add(f"{self.name}: block map shorter than the disk - the end reads as zeros")
        n = min(self.n_blocks, max(need, 1) * 2)
        raw = self.file.pread(self.off_blocks, n * 4, "block map")
        self.blocks = list(struct.unpack(f"<{n}I", raw))
        self.format = f"VDI ({TYPE_NAMES.get(self.type, f'type {self.type}')})"
        self._stride = self.block_size + self.block_extra
        if self.type == 4:
            self._find_parent(opener, depth)

    # -- parent lookup -------------------------------------------------------
    def _candidates(self):
        here = os.path.dirname(os.path.abspath(self.path))
        dirs = [here, os.path.dirname(here), os.path.join(os.path.dirname(here), "Snapshots"),
                os.path.join(here, "Snapshots")]
        seen = set()
        for d in dirs:
            for pattern in ("*.vdi", "*.VDI", "*.vmdk", "*.vhd", "*.vhdx"):
                for p in glob.glob(os.path.join(glob.escape(d), pattern)):
                    rp = os.path.normcase(os.path.abspath(p))
                    if rp not in seen and rp != os.path.normcase(os.path.abspath(self.path)):
                        seen.add(rp)
                        yield p

    def _find_parent(self, opener, depth):
        want = self.uuid_parent
        want_str = {str(uuid.UUID(bytes_le=want)), str(uuid.UUID(bytes=want))}
        found = None
        for p in self._candidates():
            if p.lower().endswith(".vdi"):
                if read_vdi_uuid(p) == want:
                    found = p
                    break
            elif p.lower().endswith(".vmdk"):
                try:
                    with open(p, "rb") as f:
                        text = f.read(65536).decode("latin-1")
                    if any(s in text.lower() for s in want_str):
                        found = p
                        break
                except OSError:
                    pass
        if found is None:
            self.errors.add(f"{self.name}: parent disk {uuid.UUID(bytes_le=want)} not found next to the "
                            "snapshot - unchanged areas read as zeros. Put the base .vdi in the same "
                            "or the parent folder.")
            self.notes.append(f"missing parent {uuid.UUID(bytes_le=want)}")
            return
        if depth > 64:
            self.errors.add("VDI snapshot chain too deep (loop?) - stopping")
            return
        self.parent = opener(found, self.errors, _depth=depth + 1) if opener else VdiImage(found, self.errors)

    # -- data ---------------------------------------------------------------
    def _block_offset(self, idx):
        """Host offset of a block, or None (unallocated) / 0 (zero) / -1 (damaged)."""
        if idx >= len(self.blocks):
            return -1
        e = self.blocks[idx]
        if e == BLOCK_FREE:
            return None
        if e == BLOCK_ZERO:
            return 0
        off = self.off_data + e * self._stride + self.block_extra
        if off >= self.file.size:
            if self.type == 2:  # fixed images are always laid out linearly
                lin = self.off_data + idx * self._stride + self.block_extra
                if lin < self.file.size:
                    return lin
            self.errors.add(f"{self.name}: block {idx} points outside the file - zeros substituted",
                            key=(self.path, "blk", idx // 256))
            return -1
        return off

    def _read(self, offset, length):
        out = bytearray()
        bs = self.block_size
        pos = offset
        end = offset + length
        while pos < end:
            idx, within = divmod(pos, bs)
            n = min(bs - within, end - pos)
            host = self._block_offset(idx)
            if host is None:
                if self.parent is not None:
                    d = self.parent.read(pos, n)
                    out += d + bytes(n - len(d))
                else:
                    out += bytes(n)
            elif host <= 0:
                out += bytes(n)
            else:
                out += self.file.pread(host + within, n, "block")
            pos += n
        return bytes(out)

    def is_allocated(self, offset, length):
        bs = self.block_size
        for idx in range(offset // bs, (offset + length - 1) // bs + 1):
            host = self._block_offset(idx)
            if host and host > 0:
                return True
            if host is None and self.parent is not None and self.parent.is_allocated(idx * bs, bs):
                return True
        return False

    def info(self):
        allocated = sum(1 for b in self.blocks if b not in (BLOCK_FREE, BLOCK_ZERO))
        rows = [("File", self.path), ("Format", self.format),
                ("Virtual size", f"{fmt_size(self.size)} ({self.size:,} bytes)"),
                ("Block size", fmt_size(self.block_size)),
                ("Allocated blocks", f"{allocated:,} of {len(self.blocks):,}"),
                ("UUID", str(uuid.UUID(bytes_le=self.uuid_create)))]
        if self.comment:
            rows.append(("Comment", self.comment))
        if self.type == 4:
            rows.append(("Parent UUID", str(uuid.UUID(bytes_le=self.uuid_parent))))
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


def open_vdi(path, errors=None, opener=None, depth=0):
    return VdiImage(path, errors if errors is not None else ErrorLog(), opener=opener, depth=depth)
