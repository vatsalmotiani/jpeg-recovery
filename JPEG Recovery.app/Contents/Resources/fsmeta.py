"""File-system aware pass ("quick scan"), like Disk Drill / PhotoRec use.

Reads the partition table (MBR, GPT or none) and FAT12/16/32 / exFAT
directories, including deleted entries, to learn each JPEG's original name,
folder, date and exact on-disk location. The carver uses this to:
  * give recovered photos their original names and dates,
  * recover the exact original file size,
  * recover files stored in pieces (fragmented) when the file system still
    knows where the pieces are.

Everything here is best effort: a damaged file system just yields fewer
records, and the deep scan (signature carving) still finds the photos.
"""

import calendar
import struct
import time

JPEG_EXT = (".jpg", ".jpeg", ".jpe", ".jfif")
MAX_ENTRIES = 2_000_000
MAX_DEPTH = 40
MAX_DELETED_DIR_CLUSTERS = 512


class FileRec:
    __slots__ = ("name", "folder", "size", "mtime", "deleted", "start", "extents", "exact")

    def __init__(self, name, folder, size, mtime, deleted, start, extents, exact):
        self.name = name          # original file name (first letter may be "_" for old FAT deletes)
        self.folder = folder      # e.g. "/DCIM/100CANON"
        self.size = size          # size in bytes from the directory entry
        self.mtime = mtime        # unix time or None
        self.deleted = deleted
        self.start = start        # absolute byte offset of the first cluster
        self.extents = extents    # [(offset, length), ...] covering `size` bytes
        self.exact = exact        # True if extents come from the FAT/flags (not assumed)


def _is_jpeg_name(name):
    return name.lower().endswith(JPEG_EXT)


def _fat_datetime(date, tim, local=True):
    try:
        y = 1980 + (date >> 9)
        mo = (date >> 5) & 15
        d = date & 31
        h = tim >> 11
        mi = (tim >> 5) & 63
        s = (tim & 31) * 2
        if not (1 <= mo <= 12 and 1 <= d <= 31 and h < 24 and mi < 60 and s < 60):
            return None
        tup = (y, mo, d, h, mi, s, 0, 0, -1)
        return time.mktime(tup) if local else calendar.timegm(tup)
    except (OverflowError, ValueError):
        return None


# ------------------------------------------------------------------ partitions
def _looks_fat(bs):
    if len(bs) < 512 or bs[0] not in (0xEB, 0xE9):
        return False
    bps = struct.unpack_from("<H", bs, 11)[0]
    spc = bs[13]
    rsvd = struct.unpack_from("<H", bs, 14)[0]
    nfats = bs[16]
    return (bps in (512, 1024, 2048, 4096) and spc and (spc & (spc - 1)) == 0
            and rsvd > 0 and nfats in (1, 2))


def _looks_exfat(bs):
    return len(bs) >= 512 and bs[3:11] == b"EXFAT   "


def find_volumes(src, sector=512):
    """Return [(byte_offset, kind)] of FAT/exFAT volumes on the device."""
    s0 = src.get(0, 512)
    if len(s0) < 512:
        return []
    if _looks_exfat(s0):
        return [(0, "exfat")]
    if _looks_fat(s0) and s0[510:512] == b"\x55\xaa":
        return [(0, "fat")]
    starts = []
    if s0[510:512] == b"\x55\xaa":
        parts = [s0[446 + 16 * i:462 + 16 * i] for i in range(4)]
        if any(p[4] == 0xEE for p in parts):
            for lba in sorted({sector, 512, 4096}):
                hdr = src.get(lba, 92)
                if hdr[:8] == b"EFI PART":
                    ent_lba, n, esz = struct.unpack_from("<QII", hdr, 72)
                    if not (128 <= esz <= 1024 and 0 < n <= 512):
                        continue
                    lba_size = lba  # header sits at LBA 1
                    table = src.get(ent_lba * lba_size, n * esz)
                    for i in range(n):
                        e = table[i * esz:(i + 1) * esz]
                        if len(e) < 48 or e[:16] == b"\0" * 16:
                            continue
                        first = struct.unpack_from("<Q", e, 32)[0]
                        starts.append(first * lba_size)
                    break
        else:
            for p in parts:
                ptype = p[4]
                first, count = struct.unpack_from("<II", p, 8)
                if ptype and count:
                    if ptype in (0x05, 0x0F, 0x85):  # extended partition
                        starts.extend(_ebr_chain(src, first * sector, sector))
                    else:
                        starts.append(first * sector)
    vols = []
    for off in starts:
        bs = src.get(off, 512)
        if _looks_exfat(bs):
            vols.append((off, "exfat"))
        elif _looks_fat(bs):
            vols.append((off, "fat"))
    return vols


def _ebr_chain(src, ext_start, sector):
    out, cur, seen = [], ext_start, set()
    while cur not in seen and len(seen) < 128:
        seen.add(cur)
        ebr = src.get(cur, 512)
        if len(ebr) < 512 or ebr[510:512] != b"\x55\xaa":
            break
        e1, e2 = ebr[446:462], ebr[462:478]
        f1, c1 = struct.unpack_from("<II", e1, 8)
        if e1[4] and c1:
            out.append(cur + f1 * sector)
        f2, c2 = struct.unpack_from("<II", e2, 8)
        if not (e2[4] and c2):
            break
        cur = ext_start + f2 * sector
    return out


# ------------------------------------------------------------------ helpers
def _coalesce(offsets, cs):
    ext = []
    for off in offsets:
        if ext and ext[-1][0] + ext[-1][1] == off:
            ext[-1][1] += cs
        else:
            ext.append([off, cs])
    return ext


def _trim(ext, size):
    out, left = [], size
    for off, ln in ext:
        if left <= 0:
            break
        take = min(ln, left)
        out.append((off, take))
        left -= take
    return out if left <= 0 else None


class _Vol:
    """Common cluster/FAT-chain logic."""

    def chain(self, first, max_clusters):
        out, c, seen = [], first, set()
        while self.valid_cluster(c) and len(out) <= max_clusters:
            if c in seen:
                return None
            seen.add(c)
            out.append(c)
            c = self.fat_entry(c)
            if c is None:
                return None
            if c >= self.eoc:
                return out
        return None  # free/bad/out-of-range entry: chain is broken

    def valid_cluster(self, c):
        return 2 <= c < self.nclusters + 2

    def coff(self, c):
        return self.heap + (c - 2) * self.cs


# ------------------------------------------------------------------ FAT12/16/32
class FatVolume(_Vol):
    def __init__(self, src, off):
        self.src = src
        bs = src.get(off, 512)
        self.bps = struct.unpack_from("<H", bs, 11)[0]
        spc = bs[13]
        rsvd = struct.unpack_from("<H", bs, 14)[0]
        nfats = bs[16]
        root_ents = struct.unpack_from("<H", bs, 17)[0]
        tot = struct.unpack_from("<H", bs, 19)[0] or struct.unpack_from("<I", bs, 32)[0]
        fatsz = struct.unpack_from("<H", bs, 22)[0] or struct.unpack_from("<I", bs, 36)[0]
        self.cs = self.bps * spc
        self.fat_off = off + rsvd * self.bps
        root_secs = (root_ents * 32 + self.bps - 1) // self.bps
        self.root_off = off + (rsvd + nfats * fatsz) * self.bps
        self.root_len = root_ents * 32
        first_data = rsvd + nfats * fatsz + root_secs
        self.heap = off + first_data * self.bps
        self.nclusters = max(0, (tot - first_data) // spc)
        if self.nclusters < 4085:
            self.bits, self.eoc = 12, 0xFF8
        elif self.nclusters < 65525:
            self.bits, self.eoc = 16, 0xFFF8
        else:
            self.bits, self.eoc = 32, 0x0FFFFFF8
        self.root_cluster = struct.unpack_from("<I", bs, 44)[0] if self.bits == 32 else None
        self.end = self.heap + self.nclusters * self.cs

    def fat_entry(self, c):
        if self.bits == 32:
            b = self.src.get(self.fat_off + c * 4, 4)
            return struct.unpack("<I", b)[0] & 0x0FFFFFFF if len(b) == 4 else None
        if self.bits == 16:
            b = self.src.get(self.fat_off + c * 2, 2)
            return struct.unpack("<H", b)[0] if len(b) == 2 else None
        b = self.src.get(self.fat_off + c + c // 2, 2)
        if len(b) != 2:
            return None
        v = struct.unpack("<H", b)[0]
        return (v >> 4) if c & 1 else (v & 0xFFF)

    def walk(self, out):
        if self.bits == 32:
            root = self._dir_bytes(self.root_cluster, deleted=False)
        else:
            root = self.src.get(self.root_off, self.root_len)
        if root is None:
            return
        self._parse_dir(root, "", False, out, 0, set())

    def _dir_bytes(self, first, deleted):
        if not self.valid_cluster(first):
            return None
        if not deleted:
            ch = self.chain(first, 65536)
            if ch:
                return b"".join(self.src.get(self.coff(c), self.cs) for c in ch)
        # Deleted directory: its FAT chain is gone; read clusters while they look like a directory.
        parts = []
        for k in range(MAX_DELETED_DIR_CLUSTERS):
            c = first + k
            if not self.valid_cluster(c):
                break
            data = self.src.get(self.coff(c), self.cs)
            if k and not _looks_like_dir(data):
                break
            parts.append(data)
            if any(data[i] == 0 for i in range(0, len(data), 32)):
                break  # end-of-directory marker reached
        return b"".join(parts)

    def _parse_dir(self, data, folder, parent_deleted, out, depth, seen):
        if depth > MAX_DEPTH or len(out) > MAX_ENTRIES:
            return
        lfn = []
        for i in range(0, len(data) - 31, 32):
            e = data[i:i + 32]
            first = e[0]
            if first == 0x00:
                break
            attr = e[11]
            if attr == 0x0F:  # long file name piece
                lfn.append(e)
                continue
            pieces, lfn = lfn, []
            if attr & 0x08:  # volume label
                continue
            deleted = first == 0xE5
            raw = bytearray(e[:11])
            if raw[0] == 0x05:
                raw[0] = 0xE5
            if raw[:2] == b". " or raw[:3] == b".. ":
                continue
            name = _lfn_name(pieces, raw, deleted)
            if name is None:
                name = _sfn_name(raw, e[12], deleted)
            if not name:
                continue
            hi = struct.unpack_from("<H", e, 20)[0] if self.bits == 32 else 0
            clus = (hi << 16) | struct.unpack_from("<H", e, 26)[0]
            size = struct.unpack_from("<I", e, 28)[0]
            mtime = _fat_datetime(struct.unpack_from("<H", e, 24)[0], struct.unpack_from("<H", e, 22)[0])
            is_del = deleted or parent_deleted
            if attr & 0x10:
                if clus in seen or not self.valid_cluster(clus):
                    continue
                seen.add(clus)
                sub = self._dir_bytes(clus, is_del)
                if sub and sub[:11] == b".          " and sub[11] & 0x10:
                    self._parse_dir(sub, folder + "/" + name, is_del, out, depth + 1, seen)
                continue
            if not _is_jpeg_name(name) or size == 0 or not self.valid_cluster(clus):
                continue
            start = self.coff(clus)
            extents, exact = None, False
            if not is_del:
                ch = self.chain(clus, size // self.cs + 2)
                if ch:
                    extents = _trim(_coalesce([self.coff(c) for c in ch], self.cs), size)
                    exact = extents is not None
            if extents is None:
                extents = [(start, size)]  # deleted on FAT: assume stored in one piece
            out.append(FileRec(name, folder or "/", size, mtime, is_del, start, extents, exact))


def _looks_like_dir(data):
    ok = total = 0
    for i in range(0, len(data) - 31, 32):
        first, attr = data[i], data[i + 11]
        if first == 0:
            break
        total += 1
        if (first == 0xE5 or 0x20 <= first < 0x7F or first >= 0x80) and attr & 0xC0 == 0:
            ok += 1
    return total > 0 and ok * 10 >= total * 9


def _sfn_checksum(raw):
    s = 0
    for b in raw:
        s = (((s & 1) << 7) + (s >> 1) + b) & 0xFF
    return s


def _lfn_name(pieces, raw, deleted):
    if not pieces:
        return None
    chk = pieces[-1][13]
    if deleted:
        ok = any(_sfn_checksum(bytes([c]) + bytes(raw[1:])) == chk for c in range(0x20, 0x7F))
    else:
        ok = _sfn_checksum(bytes(raw)) == chk
    if not ok or any(p[13] != chk for p in pieces):
        return None
    chars = b""
    for p in reversed(pieces):
        chars += p[1:11] + p[14:26] + p[28:32]
    name = chars.decode("utf-16-le", "replace")
    name = name.split("\x00")[0].replace("￿", "")
    return name or None


def _sfn_name(raw, case, deleted):
    base = bytes(raw[:8]).rstrip(b" ")
    ext = bytes(raw[8:11]).rstrip(b" ")
    base = base.decode("latin-1")
    ext = ext.decode("latin-1")
    if deleted:
        base = "_" + base[1:]
    if case & 0x08:
        base = base.lower()
    if case & 0x10:
        ext = ext.lower()
    if not base.strip("_ ") and not ext:
        return None
    return base + ("." + ext if ext else "")


# ------------------------------------------------------------------ exFAT
class ExFatVolume(_Vol):
    def __init__(self, src, off):
        self.src = src
        bs = src.get(off, 512)
        fat_off, _fat_len, heap_off, ncl, root = struct.unpack_from("<IIIII", bs, 80)
        self.bps = 1 << bs[108]
        self.cs = self.bps << bs[109]
        self.fat_off = off + fat_off * self.bps
        self.heap = off + heap_off * self.bps
        self.nclusters = ncl
        self.root = root
        self.eoc = 0xFFFFFFF8  # >= this means end of chain (0xFFFFFFF7 = bad cluster)
        self.end = self.heap + ncl * self.cs

    def fat_entry(self, c):
        b = self.src.get(self.fat_off + c * 4, 4)
        return struct.unpack("<I", b)[0] if len(b) == 4 else None

    def _read(self, first, length, nofat, deleted):
        n = max(1, (length + self.cs - 1) // self.cs)
        if not self.valid_cluster(first) or not self.valid_cluster(first + (n - 1 if nofat else 0)):
            return None, None, False
        if not nofat:
            ch = self.chain(first, n + 1)
            if ch and len(ch) == n:
                ext = _trim(_coalesce([self.coff(c) for c in ch], self.cs), length)
                if ext:
                    return ext, True, True
            if not deleted:
                return None, None, False
            # deleted & chain unusable: assume contiguous
            return [(self.coff(first), length)], False, True
        return [(self.coff(first), length)], True, True

    def walk(self, out):
        ch = self.chain(self.root, 1 << 16)
        if not ch:
            return
        data = b"".join(self.src.get(self.coff(c), self.cs) for c in ch)
        self._parse_dir(data, "", False, out, 0, set())

    def _parse_dir(self, data, folder, parent_deleted, out, depth, seen):
        if depth > MAX_DEPTH or len(out) > MAX_ENTRIES:
            return
        n = len(data) // 32
        i = 0
        while i < n:
            t = data[i * 32]
            if t == 0x00:
                break
            if t not in (0x85, 0x05):
                i += 1
                continue
            e = data[i * 32:i * 32 + 32]
            sec = e[1]
            if sec < 2 or sec > 18 or i + sec >= n:
                i += 1
                continue
            entries = [data[(i + k) * 32:(i + k + 1) * 32] for k in range(sec + 1)]
            deleted = t == 0x05
            want = 0x00 if deleted else 0x80
            st = entries[1]
            if st[0] != (0x40 | want) or any(x[0] != (0x41 | want) for x in entries[2:]):
                i += 1
                continue
            if not _exfat_checksum_ok(entries, deleted):
                i += 1
                continue
            attrs = struct.unpack_from("<H", e, 4)[0]
            flags = st[1]
            name_len = st[3]
            first = struct.unpack_from("<I", st, 20)[0]
            length = struct.unpack_from("<Q", st, 24)[0]
            raw = b"".join(x[2:32] for x in entries[2:])
            name = raw[:name_len * 2].decode("utf-16-le", "replace")
            mtime = _exfat_time(struct.unpack_from("<I", e, 12)[0], e[21], e[24])
            is_del = deleted or parent_deleted
            nofat = bool(flags & 0x02)
            i += sec + 1
            if not name or not (flags & 0x01) or length == 0:
                continue
            if attrs & 0x10:
                if first in seen:
                    continue
                seen.add(first)
                ext, _, ok = self._read(first, length, nofat, is_del)
                if ok and length <= 64 << 20:
                    sub = b"".join(self.src.get(o, ln) for o, ln in ext)
                    self._parse_dir(sub, folder + "/" + name, is_del, out, depth + 1, seen)
                continue
            if not _is_jpeg_name(name):
                continue
            ext, exact, ok = self._read(first, length, nofat, is_del)
            if not ok:
                continue
            out.append(FileRec(name, folder or "/", length, mtime, is_del,
                               self.coff(first), ext, bool(exact)))


def _exfat_checksum_ok(entries, deleted):
    chk = 0
    for k, ent in enumerate(entries):
        b = bytearray(ent)
        if deleted:
            b[0] |= 0x80
        for j, v in enumerate(b):
            if k == 0 and j in (2, 3):
                continue
            chk = (((chk & 1) << 15) | (chk >> 1)) + v
            chk &= 0xFFFF
    return chk == struct.unpack_from("<H", entries[0], 2)[0]


def _exfat_time(ts, ms10, utc):
    date, tim = ts >> 16, ts & 0xFFFF
    if utc & 0x80:
        t = _fat_datetime(date, tim, local=False)
        if t is None:
            return None
        off = utc & 0x7F
        if off & 0x40:
            off -= 0x80
        return t - off * 15 * 60 + (ms10 // 100)
    t = _fat_datetime(date, tim)
    return None if t is None else t + (ms10 // 100)


# ------------------------------------------------------------------ entry point
def scan(src, sector=512):
    """Return (list_of_FileRec, list_of_volume_descriptions). Never raises on bad data."""
    recs, vols = [], []
    try:
        found = find_volumes(src, sector)
    except Exception:
        return recs, vols
    for off, kind in found:
        try:
            v = ExFatVolume(src, off) if kind == "exfat" else FatVolume(src, off)
            if v.cs <= 0 or v.nclusters <= 0:
                continue
            vols.append("%s at %d" % ("exFAT" if kind == "exfat" else "FAT%d" % v.bits, off))
            v.walk(recs)
        except Exception:
            continue  # damaged volume: fall back to deep scan only
    return recs, vols
