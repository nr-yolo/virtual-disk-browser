"""Minimal read-only XFS driver (v4 and v5/CRC file systems).

The Sleuth Kit does not handle XFS, the default file system of RHEL, CentOS,
Rocky and Alma Linux, so it is implemented here.  Supports short-form, block,
leaf and node/b-tree directories, extent and b-tree mapped files, inline and
remote symlinks.  Checksums are not enforced so damaged metadata is still
read where possible.
"""

import struct

from .fs import FileSystem, Entry

S_IFMT = 0o170000
S_IFDIR = 0o040000
S_IFREG = 0o100000
S_IFLNK = 0o120000

DIR2_LEAF_OFFSET = 1 << 35  # directory data blocks live below 32 GiB
DIFLAG2_BIGTIME = 1 << 3
DIFLAG2_NREXT64 = 1 << 4


class XfsError(Exception):
    pass


class _Inode:
    __slots__ = ("ino", "mode", "fmt", "size", "nextents", "fork", "atime", "mtime", "ctime",
                 "crtime", "v3")


class XfsFileSystem(FileSystem):
    type_name = "XFS"

    def __init__(self, image, errors):
        self.image = image
        self.errors = errors
        sb = image.read(0, 512)
        if sb[:4] != b"XFSB":
            raise XfsError("XFS superblock magic not found")
        self.blocksize = struct.unpack_from(">I", sb, 4)[0]
        self.dblocks = struct.unpack_from(">Q", sb, 8)[0]
        self.rootino = struct.unpack_from(">Q", sb, 56)[0]
        self.agblocks, self.agcount = struct.unpack_from(">II", sb, 84)
        self.versionnum = struct.unpack_from(">H", sb, 100)[0]
        self.inodesize = struct.unpack_from(">H", sb, 104)[0]
        self.label = sb[108:120].split(b"\0", 1)[0].decode("utf-8", "replace")
        self.blocklog, _sectlog, self.inodelog, self.inopblog, self.agblklog = sb[120:125]
        self.dirblklog = sb[192]
        features2 = struct.unpack_from(">I", sb, 200)[0]
        incompat = struct.unpack_from(">I", sb, 216)[0]
        self.v5 = (self.versionnum & 0xF) == 5
        self.has_ftype = bool(incompat & 0x1) if self.v5 else bool(features2 & 0x200)
        if not (512 <= self.blocksize <= 65536 and 256 <= self.inodesize <= 2048):
            raise XfsError("XFS superblock is damaged")
        self.dirblksize = self.blocksize << self.dirblklog
        self._extent_cache = {}

    # -- addressing ----------------------------------------------------------
    def _fsb_to_byte(self, fsb):
        agno = fsb >> self.agblklog
        agbno = fsb & ((1 << self.agblklog) - 1)
        return (agno * self.agblocks + agbno) * self.blocksize

    def _ino_to_byte(self, ino):
        shift = self.agblklog + self.inopblog
        agno = ino >> shift
        agbno = (ino >> self.inopblog) & ((1 << self.agblklog) - 1)
        off = ino & ((1 << self.inopblog) - 1)
        return (agno * self.agblocks + agbno) * self.blocksize + off * self.inodesize

    # -- inodes ----------------------------------------------------------------
    def _inode(self, ino):
        raw = self.image.read(self._ino_to_byte(ino), self.inodesize)
        if raw[:2] != b"IN":
            raise XfsError(f"inode {ino} is damaged (bad magic)")
        i = _Inode()
        i.ino = ino
        i.mode = struct.unpack_from(">H", raw, 2)[0]
        version = raw[4]
        i.fmt = raw[5]
        i.v3 = version >= 3
        flags2 = struct.unpack_from(">Q", raw, 120)[0] if i.v3 else 0
        i.size = struct.unpack_from(">Q", raw, 56)[0]
        if flags2 & DIFLAG2_NREXT64:
            i.nextents = struct.unpack_from(">Q", raw, 24)[0]
        else:
            i.nextents = struct.unpack_from(">I", raw, 76)[0]
        forkoff = raw[82]
        core = 176 if i.v3 else 100
        fork_end = core + forkoff * 8 if forkoff else self.inodesize
        i.fork = raw[core:fork_end]

        def ts(off):
            if flags2 & DIFLAG2_BIGTIME:
                return struct.unpack_from(">Q", raw, off)[0] // 1_000_000_000 - (1 << 31)
            return struct.unpack_from(">i", raw, off)[0]

        i.atime, i.mtime, i.ctime = ts(32), ts(40), ts(48)
        i.crtime = ts(144) if i.v3 else 0
        return i

    @staticmethod
    def _kind(mode):
        t = mode & S_IFMT
        return {S_IFDIR: "dir", S_IFREG: "file", S_IFLNK: "link"}.get(t, "other")

    # -- extent maps -----------------------------------------------------------
    @staticmethod
    def _unpack_extents(buf, count):
        out = []
        for k in range(count):
            if (k + 1) * 16 > len(buf):
                break
            hi, lo = struct.unpack_from(">QQ", buf, k * 16)
            unwritten = hi >> 63
            startoff = (hi >> 9) & ((1 << 54) - 1)
            startblock = ((hi & 0x1FF) << 43) | (lo >> 21)
            count_ = lo & ((1 << 21) - 1)
            out.append((startoff, startblock, count_, bool(unwritten)))
        return out

    def _extents(self, inode):
        cached = self._extent_cache.get(inode.ino)
        if cached is not None:
            return cached
        if inode.fmt == 2:
            ext = self._unpack_extents(inode.fork, min(inode.nextents, len(inode.fork) // 16))
        elif inode.fmt == 3:
            ext = []
            level, numrecs = struct.unpack_from(">HH", inode.fork, 0)
            maxrecs = (len(inode.fork) - 4) // 16
            ptrs = struct.unpack_from(f">{min(numrecs, maxrecs)}Q", inode.fork, 4 + maxrecs * 8)
            for p in ptrs:
                self._walk_bmbt(p, ext, depth=0)
        else:
            ext = []
        ext.sort()
        if len(self._extent_cache) > 4096:
            self._extent_cache.clear()
        self._extent_cache[inode.ino] = ext
        return ext

    def _walk_bmbt(self, fsb, out, depth):
        if depth > 10:
            return
        blk = self.image.read(self._fsb_to_byte(fsb), self.blocksize)
        magic = blk[:4]
        if magic not in (b"BMAP", b"BMA3"):
            self.errors.add(f"XFS: damaged extent b-tree block at {fsb} - part of a file is missing",
                            key=("xfs-bmbt", fsb))
            return
        hdr = 72 if magic == b"BMA3" else 24
        level, numrecs = struct.unpack_from(">HH", blk, 4)
        if level == 0:
            out.extend(self._unpack_extents(blk[hdr:], min(numrecs, (self.blocksize - hdr) // 16)))
        else:
            maxrecs = (self.blocksize - hdr) // 16
            n = min(numrecs, maxrecs)
            for p in struct.unpack_from(f">{n}Q", blk, hdr + maxrecs * 8):
                self._walk_bmbt(p, out, depth + 1)

    def _read_mapped(self, inode, offset, length):
        bs = self.blocksize
        out = bytearray(length)
        end = offset + length
        for startoff, startblock, count, unwritten in self._extents(inode):
            a = startoff * bs
            b = a + count * bs
            if b <= offset or a >= end or unwritten:
                continue
            lo = max(a, offset)
            hi = min(b, end)
            data = self.image.read(self._fsb_to_byte(startblock) + (lo - a), hi - lo)
            out[lo - offset:lo - offset + len(data)] = data
        return bytes(out)

    # -- directories ------------------------------------------------------------
    def _dir_entries(self, inode):
        """Yield (name, inode_number) pairs."""
        if inode.fmt == 1:
            yield from self._shortform(inode.fork)
            return
        bs = self.blocksize
        blocks = set()
        per = self.dirblksize // bs
        for startoff, _sb, count, _u in self._extents(inode):
            if startoff * bs >= DIR2_LEAF_OFFSET:
                continue
            for lb in range(startoff, startoff + count):
                if lb * bs < DIR2_LEAF_OFFSET:
                    blocks.add(lb // per)
        for db in sorted(blocks):
            data = self._read_mapped(inode, db * self.dirblksize, self.dirblksize)
            yield from self._data_block(data, db)

    def _shortform(self, fork):
        if len(fork) < 6:
            return
        count, i8 = fork[0], fork[1]
        isz = 8 if i8 else 4
        pos = 2 + isz
        for _ in range(count):
            if pos + 3 > len(fork):
                break
            namelen = fork[pos]
            pos += 3  # namelen + 2-byte offset
            name = fork[pos:pos + namelen]
            pos += namelen
            if self.has_ftype:
                pos += 1
            if pos + isz > len(fork):
                break
            ino = int.from_bytes(fork[pos:pos + isz], "big")
            pos += isz
            if namelen:
                yield name.decode("utf-8", "replace"), ino

    def _data_block(self, blk, db):
        magic = blk[:4]
        if magic in (b"XD2B", b"XD2D"):
            pos = 16
        elif magic in (b"XDB3", b"XDD3"):
            pos = 64
        else:
            if any(blk[:64]):
                self.errors.add(f"XFS: damaged directory block {db} - some names may be missing",
                                key=("xfs-dir", db))
            return
        end = len(blk)
        if magic in (b"XD2B", b"XDB3"):
            count = struct.unpack_from(">I", blk, end - 8)[0]
            end = end - 8 - count * 8
            if end < pos:
                end = len(blk) - 8
        while pos + 12 <= end:
            if blk[pos:pos + 2] == b"\xff\xff":
                length = struct.unpack_from(">H", blk, pos + 2)[0]
                if length < 8 or length % 8:
                    break
                pos += length
                continue
            ino = struct.unpack_from(">Q", blk, pos)[0]
            namelen = blk[pos + 8]
            if namelen == 0:
                break
            name = blk[pos + 9:pos + 9 + namelen]
            size = 8 + 1 + namelen + (1 if self.has_ftype else 0) + 2
            size = (size + 7) & ~7
            pos += size
            if name in (b".", b".."):
                continue
            yield name.decode("utf-8", "replace"), ino

    # -- FileSystem API ---------------------------------------------------------
    def root(self):
        return Entry("", self.rootino, "dir")

    def list_dir(self, entry):
        out = []
        try:
            ino = self._inode(entry.addr)
        except XfsError as e:
            self.errors.add(f"XFS: {e}")
            return out
        try:
            for name, child in self._dir_entries(ino):
                try:
                    ci = self._inode(child)
                    e = Entry(name, child, self._kind(ci.mode), size=ci.size if (ci.mode & S_IFMT) != S_IFDIR else 0,
                              mtime=ci.mtime, atime=ci.atime, ctime=ci.ctime, crtime=ci.crtime)
                except XfsError as ex:
                    self.errors.add(f"XFS: {name}: {ex}")
                    e = Entry(name, child, "other")
                e.parent = entry
                out.append(e)
        except (struct.error, IndexError) as ex:
            self.errors.add(f"XFS: directory '{entry.name or '/'}' is damaged ({ex}) - listing incomplete")
        return out

    def read(self, entry, offset, length):
        try:
            ino = self._inode(entry.addr)
        except XfsError as e:
            self.errors.add(f"XFS: {e} - content replaced with zeros", key=("xfs-ino", entry.addr))
            return bytes(max(0, min(length, entry.size - offset)))
        length = max(0, min(length, ino.size - offset))
        if ino.fmt == 1:
            return bytes(ino.fork[offset:offset + length]).ljust(length, b"\0")
        return self._read_mapped(ino, offset, length)

    def readlink(self, entry):
        try:
            ino = self._inode(entry.addr)
        except XfsError:
            return None
        if ino.fmt == 1:
            return ino.fork[:ino.size].decode("utf-8", "replace")
        data = self._read_mapped(ino, 0, self.blocksize)
        if data[:4] == b"XSLM":
            data = data[56:]
        return data[:ino.size].decode("utf-8", "replace")

    def info(self):
        return [("File system", f"XFS v{5 if self.v5 else 4}"), ("Label", self.label or "-"),
                ("Block size", str(self.blocksize)), ("Blocks", f"{self.dblocks:,}"),
                ("Allocation groups", str(self.agcount))]
