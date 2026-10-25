"""JPEG recovery engine.

Two passes, like professional recovery tools:
  1. File-system pass (fsmeta.py): reads FAT/exFAT directories, including
     deleted entries, for original names, dates and exact locations.
  2. Deep scan: reads the whole device and finds JPEGs by walking their marker
     structure, so the exact original bytes are recovered (no re-encoding, no
     downscaling) even after deletion or formatting.

Unreadable (bad) sectors are skipped and replaced with zeros instead of
stopping the scan.
"""

import errno
import os
import re
import struct
import threading
import time
from collections import Counter, OrderedDict

import fsmeta

BLOCK = 1 << 20            # 1 MiB aligned reads (raw devices need aligned I/O)
CHUNK_BLOCKS = 16          # main scan window = 16 MiB
CACHE_BLOCKS = 96          # 96 MiB block cache, so each byte is read from the card once
MAX_JPEG = 256 << 20       # ignore anything claiming to be larger than 256 MiB
MIN_JPEG = 1024            # ignore fragments smaller than 1 KiB
MIN_DIM = 16               # ignore images smaller than 16x16
ALIGN = 512                # files on FAT/exFAT/NTFS/HFS/APFS always start on a sector boundary
ENTROPY_WIN = 4 << 20
ZERO_BLOCK = b"\x00" * 65536  # 16 zero blocks in a row (1 MiB) never occur inside real image data
ZERO_BLOCKS_LIMIT = 16
FS_SIZE_SLACK = 64 << 20   # trust a directory entry's size if it's at most this much bigger
MIN_EMBED_DIM = 96         # JPEGs inside other files (thumbnail caches, previews) must be at least this big

SIG = b"\xff\xd8\xff"
FIRST_OK = set(range(0xE0, 0xF0)) | {0xDB, 0xC4, 0xC0, 0xC1, 0xC2, 0xFE, 0xDD}
SOF = {0xC0, 0xC1, 0xC2, 0xC3, 0xC5, 0xC6, 0xC7, 0xC9, 0xCA, 0xCB, 0xCD, 0xCE, 0xCF}
HEADER_OK = set(range(0xC0, 0xD0)) | set(range(0xDB, 0xE0)) | set(range(0xE0, 0xF0)) | {0xFE, 0xDA}
AFTER_SCAN_OK = {0xD9, 0xC4, 0xDB, 0xDA, 0xDD, 0xDC, 0xFE} | set(range(0xE0, 0xF0))
ENTROPY_MARKER = re.compile(rb"\xff[^\x00\xd0-\xd7\xff]")


class DeviceGone(OSError):
    pass


class Source:
    """Random-access, block-cached reader over a device or image file.

    Read errors are retried in smaller pieces; sectors that still can't be
    read are returned as zeros and counted in `bad_bytes`.
    """

    def __init__(self, path, size, sector=512):
        self.path = path
        self.size = size
        self.sector = max(512, sector)
        self.fd = os.open(path, os.O_RDONLY)
        self.bad_bytes = 0
        self._cache = OrderedDict()
        self._lock = threading.Lock()

    def close(self):
        try:
            os.close(self.fd)
        except OSError:
            pass

    def _gone(self, e):
        return e.errno in (errno.ENXIO, errno.ENODEV, errno.EBADF) or not os.path.exists(self.path)

    def _pread_once(self, n, off):
        parts = []
        while n > 0:
            b = os.pread(self.fd, n, off)
            if not b:
                break
            parts.append(b)
            n -= len(b)
            off += len(b)
        return b"".join(parts)

    def _pread(self, n, off, stats=None):
        """Aligned read that survives bad sectors."""
        try:
            return self._pread_once(n, off)
        except OSError as e:
            if self._gone(e):
                raise DeviceGone(e.errno, "The drive was disconnected")
        out = bytearray()
        step = (64 << 10) if n > (64 << 10) else self.sector
        pos, end = off, off + n
        while pos < end:
            m = min(step, end - pos)
            try:
                out += self._pread_once(m, pos)
            except OSError as e:
                if self._gone(e):
                    raise DeviceGone(e.errno, "The drive was disconnected")
                if m > self.sector:
                    out += self._pread(m, pos, stats)  # retry this piece sector by sector
                else:
                    out += b"\x00" * m
                    with self._lock:
                        self.bad_bytes += m
                    if stats is not None:
                        stats["bad"] = stats.get("bad", 0) + m
            pos += m
        return bytes(out)

    def _block(self, i):
        with self._lock:
            b = self._cache.get(i)
            if b is not None:
                self._cache.move_to_end(i)
                return b
        off = i * BLOCK
        b = self._pread(min(BLOCK, self.size - off), off)
        with self._lock:
            self._cache[i] = b
            while len(self._cache) > CACHE_BLOCKS:
                self._cache.popitem(last=False)
        return b

    def get(self, off, n):
        """Cached read used by the scanner."""
        end = min(off + n, self.size)
        if off < 0 or off >= end:
            return b""
        first, last = off // BLOCK, (end - 1) // BLOCK
        if first == last:
            b = self._block(first)
        else:
            b = b"".join(self._block(i) for i in range(first, last + 1))
        s = off - first * BLOCK
        return b[s:s + (end - off)]

    def read_range(self, off, n, stats=None):
        """Uncached exact read for previews/recovery (raw devices need aligned reads)."""
        a = off - (off % 4096)
        end = min(off + n, self.size)
        e = min(end + (-end % 4096), self.size)
        data = self._pread(e - a, a, stats)
        out = data[off - a:off - a + n]
        if len(out) != n:
            raise IOError("Could not read the full photo from the drive (was it removed?)")
        return out


class BufSource:
    """Same interface as Source, over bytes already in memory."""

    def __init__(self, data):
        self.data = data
        self.size = len(data)

    def get(self, off, n):
        return self.data[off:off + n] if off >= 0 else b""


def read_item(src, item, rel=0, n=None, stats=None):
    """Read bytes [rel, rel+n) of a found photo, following its extents."""
    if n is None:
        n = item["length"] - rel
    out, pos = [], 0
    for off, ln in item["extents"]:
        lo, hi = max(rel, pos), min(rel + n, pos + ln)
        if lo < hi:
            out.append(src.read_range(off + (lo - pos), hi - lo, stats))
        pos += ln
        if pos >= rel + n:
            break
    return b"".join(out)


def _u16(b, i):
    return (b[i] << 8) | b[i + 1]


def _tiff(seg, base):
    """Return (endian, tiff_bytes) for a TIFF header at seg[base:], or (None, None)."""
    t = seg[base:]
    bo = {b"II": "<", b"MM": ">"}.get(t[:2])
    return bo, t


def _ifd_entries(bo, t, ifd):
    (count,) = struct.unpack_from(bo + "H", t, ifd)
    for k in range(min(count, 512)):
        e = ifd + 2 + 12 * k
        yield struct.unpack_from(bo + "HHI", t, e) + (e + 8,)


def _exif_info(seg):
    """APP1 payload -> (orientation, thumb_rel_off, thumb_len, 'YYYY:MM:DD HH:MM:SS' or None)."""
    orientation, t_off, t_len, date = 1, None, 0, None
    if not seg.startswith(b"Exif\x00\x00") or len(seg) < 14:
        return orientation, t_off, t_len, date
    bo, t = _tiff(seg, 6)
    try:
        if bo:
            (ifd,) = struct.unpack_from(bo + "I", t, 4)
            exif_ifd = None
            for tag, typ, cnt, voff in _ifd_entries(bo, t, ifd):
                if tag == 0x0112 and typ == 3:
                    (orientation,) = struct.unpack_from(bo + "H", t, voff)
                elif tag == 0x8769:
                    (exif_ifd,) = struct.unpack_from(bo + "I", t, voff)
                elif tag == 0x0132 and typ == 2 and cnt >= 19:
                    (p,) = struct.unpack_from(bo + "I", t, voff)
                    date = date or t[p:p + 19].decode("ascii", "replace")
            if exif_ifd:
                for tag, typ, cnt, voff in _ifd_entries(bo, t, exif_ifd):
                    if tag == 0x9003 and typ == 2 and cnt >= 19:
                        (p,) = struct.unpack_from(bo + "I", t, voff)
                        date = t[p:p + 19].decode("ascii", "replace")
    except (struct.error, IndexError):
        pass
    s = seg.find(SIG, 6)
    if s != -1:
        e = seg.rfind(b"\xff\xd9")
        if e > s:
            t_off, t_len = s, e + 2 - s
    if orientation not in range(1, 9):
        orientation = 1
    if date and not re.match(r"^\d{4}:\d\d:\d\d \d\d:\d\d:\d\d$", date):
        date = None
    return orientation, t_off, t_len, date


def _mpf_end(seg, seg_abs):
    """APP2 'MPF' payload -> absolute end offset of the last attached image, or None.

    Ultra HDR photos (Android), many cameras and 3D/MPO files store extra
    images right after the main image; their offsets are listed here.
    """
    if not seg.startswith(b"MPF\x00"):
        return None
    base_abs = seg_abs + 4
    bo, t = _tiff(seg, 4)
    if not bo:
        return None
    try:
        (ifd,) = struct.unpack_from(bo + "I", t, 4)
        end = None
        for tag, typ, cnt, voff in _ifd_entries(bo, t, ifd):
            if tag == 0xB002 and cnt >= 16:
                (p,) = struct.unpack_from(bo + "I", t, voff)
                for k in range(cnt // 16):
                    _attr, size, off = struct.unpack_from(bo + "III", t, p + 16 * k)
                    if off and size:
                        e = base_abs + off + size
                        end = e if end is None else max(end, e)
        return end
    except (struct.error, IndexError):
        return None


def _fail(why, msg):
    if why is not None:
        why.append(msg)
    return None


def parse_jpeg(src, p, why=None, header_only=False):
    """Validate a JPEG starting at offset p of `src`.

    Returns a dict (start, length, width, height, orientation, thumb_rel,
    thumb_len, exif_date) or None if this is not a complete, well-formed JPEG.
    """
    head = src.get(p, 4)
    if len(head) < 4 or head[:3] != SIG or head[3] not in FIRST_OK:
        return _fail(why, 'not a JPEG start (FF D8 FF + valid marker)')
    limit = p + MAX_JPEG
    pos = p + 2
    seen_sof = seen_sos = after_scan = exif_done = False
    width = height = 0
    orientation, thumb_rel, thumb_len, date, mpf_end = 1, None, 0, None, None
    while True:
        if pos >= limit:
            return _fail(why, 'bigger than the size limit')
        b = src.get(pos, 4)
        if len(b) < 2 or b[0] != 0xFF:
            return _fail(why, 'structure broken (expected a marker)')
        m = b[1]
        while m == 0xFF:  # fill bytes
            pos += 1
            b = src.get(pos, 4)
            if len(b) < 2:
                return _fail(why, 'ran off the end of the drive')
            m = b[1]
        if after_scan and m not in AFTER_SCAN_OK:
            return _fail(why, 'invalid marker after image data (damaged/overwritten)')
        if not seen_sos and m not in HEADER_OK and m != 0xD9:
            return _fail(why, 'invalid marker in header')
        after_scan = False
        if m == 0xD9:  # EOI
            end = pos + 2
            if not (seen_sof and seen_sos) or end - p < MIN_JPEG:
                return _fail(why, 'no image frame/scan before end, or under 1 KB')
            if width < MIN_DIM or height < MIN_DIM:
                return _fail(why, 'image smaller than 16x16')
            if mpf_end and end < mpf_end <= limit and src.get(end, 3) == SIG:
                tail = src.get(mpf_end - 2, 2)
                if tail == b"\xff\xd9":
                    end = mpf_end
            return {
                "start": p, "length": end - p, "width": width, "height": height,
                "orientation": orientation, "thumb_rel": thumb_rel, "thumb_len": thumb_len,
                "exif_date": date,
            }
        if len(b) < 4:
            return _fail(why, 'ran off the end of the drive')
        seg_len = _u16(b, 2)
        if seg_len < 2:
            return _fail(why, 'invalid segment length')
        if m in SOF:
            seg = src.get(pos + 4, 6)
            if seg_len < 8 or len(seg) < 5:
                return _fail(why, 'bad frame header')
            height, width = _u16(seg, 1), _u16(seg, 3)
            if height == 0 or width == 0:
                return _fail(why, 'zero width/height')
            seen_sof = True
        elif m == 0xE1 and not exif_done:
            seg = src.get(pos + 4, seg_len - 2)
            if seg.startswith(b"Exif\x00\x00"):
                exif_done = True
                orientation, t, tl, date = _exif_info(seg)
                if t is not None:
                    thumb_rel, thumb_len = pos + 4 + t - p, tl
        elif m == 0xE2 and mpf_end is None:
            seg = src.get(pos + 4, min(seg_len - 2, 4096))
            mpf_end = _mpf_end(seg, pos + 4)
        if m == 0xDA:  # start of scan -> skip entropy-coded data
            if not seen_sof:
                return _fail(why, 'image data before frame header')
            if header_only:
                if width < MIN_DIM or height < MIN_DIM:
                    return _fail(why, 'image smaller than 16x16')
                return {
                    "start": p, "length": None, "width": width, "height": height,
                    "orientation": orientation, "thumb_rel": thumb_rel, "thumb_len": thumb_len,
                    "exif_date": date,
                }
            pos = _skip_entropy(src, pos + 2 + seg_len, limit)
            if pos is None:
                return _fail(why, 'image data never ends (overwritten, zero-filled, or stored in pieces)')
            seen_sos = True
            after_scan = True
            continue
        pos += 2 + seg_len


def _zero_run(data, end):
    """True if data[:end] contains about 1 MiB of zero bytes in a row (an erased
    area, so the photo can't continue). Compares 64 KiB blocks: fast in all cases."""
    mv = memoryview(data)
    run = 0
    for i in range(0, end - 65535, 65536):
        if mv[i:i + 65536] == ZERO_BLOCK:
            run += 1
            if run >= ZERO_BLOCKS_LIMIT:
                return True
        else:
            run = 0
    return False


def _skip_entropy(src, pos, limit):
    while pos < limit:
        data = src.get(pos, ENTROPY_WIN)
        if len(data) < 2:
            return None
        mt = ENTROPY_MARKER.search(data)
        end = mt.start() if mt else len(data)
        if _zero_run(data, end):
            return None
        if mt:
            return pos + end
        pos += len(data) - 1
    return None


def _clean_name(name):
    name = "".join(c for c in name if c >= " " and c not in '/\\:\x7f').strip().lstrip(".")
    return name[:200] or None


class Scanner:
    """Runs both passes in a background thread, collecting found JPEGs."""

    def __init__(self, src):
        self.src = src
        self.found = []
        self.scanned = 0
        self.phase = "Reading file system"
        self.volumes = []
        self.cancelled = False
        self.done = False
        self.error = None
        self.stats = Counter()  # diagnostics: candidates checked and why they were rejected
        self._lock = threading.Lock()
        self.recs = []
        self._fs_by_start = {}
        self._fs_used = set()
        self._known = {}  # start offset -> bytes to skip, for photos already listed
        self._lost = {}   # start offset -> FileRec, photos listed from a lost folder (verified later)
        self._starts = set()
        self._vols = []

    def cancel(self):
        self.cancelled = True

    def log(self, msg):
        """Overridden by the app to write to its log file."""

    def snapshot(self, since):
        with self._lock:
            return self.found[since:]

    def run(self):
        try:
            self._fs_pass()
            self._existing_pass()
            self._deep_pass()
            if not self.cancelled:
                self._fs_only_pass()
        except DeviceGone:
            self.error = "The drive was disconnected during the scan. Photos found so far are listed."
        except Exception as e:  # report, never die silently
            self.error = "%s: %s" % (type(e).__name__, e)
        finally:
            self.done = True

    # -- pass 1
    def _fs_pass(self):
        try:
            recs, self.volumes, self._vols = fsmeta.scan_volumes(self.src, self.src.sector)
        except DeviceGone:
            raise
        except Exception:
            recs = []
        recs = [r for r in recs if not r.name.startswith("._")]  # macOS metadata files
        self.log("file system: %s; JPEG entries: %d existing, %d deleted" % (
            ", ".join(self.volumes) or "none readable", sum(not r.deleted for r in recs),
            sum(r.deleted for r in recs)))
        for r in recs[:5]:
            self.log("  entry %s%s size %d at %d (%s, %d piece(s)) first bytes %s" % (
                r.folder.rstrip("/") + "/", r.name, r.size, r.start,
                "deleted" if r.deleted else "existing", len(r.extents), self.src.get(r.start, 8).hex(" ")))
        recs.sort(key=lambda r: r.deleted)  # existing files win over deleted ones at the same place
        for r in recs:
            self._fs_by_start.setdefault(r.start, r)
        self.recs = recs

    def _match(self, p):
        return self._fs_by_start.get(p)

    def _add(self, info, rec, extents, status=None):
        item = dict(info)
        item["extents"] = [tuple(e) for e in extents]
        item["length"] = sum(ln for _, ln in item["extents"])
        if rec is not None:
            item.update(name=_clean_name(rec.name), folder=rec.folder, mtime=rec.mtime,
                        status="deleted" if rec.deleted else "existing")
            self._fs_used.add(id(rec))
        else:
            item.update(name=None, folder=None, mtime=None, status=status or "unknown")
        with self._lock:
            item["id"] = len(self.found)
            self.found.append(item)
            self._starts.add(item["extents"][0][0])

    def _quick_header(self, extents, size):
        """Check that a file the file system knows about starts with a real JPEG
        header (reads only the first 128 KB, so it's fast anywhere on the card)."""
        tmp = {"extents": extents, "length": size}
        for n in (128 << 10, 2 << 20):
            head = read_item(self.src, tmp, 0, min(n, size))
            info = parse_jpeg(BufSource(head), 0, header_only=True)
            if info is not None or n >= size:
                return info
        return None

    # -- lost folders (left behind after a quick format or folder delete)
    def _find_lost_dirs(self, cstart, data, limit):
        if not self._vols:
            return
        end = cstart + limit
        new = []
        for v in self._vols:
            if v.end <= cstart or v.heap >= end:
                continue
            if isinstance(v, fsmeta.FatVolume):
                k = data.find(b".          ", 0, limit)
                while k != -1:
                    off = cstart + k
                    if (off - v.heap) % v.cs == 0 and v.heap <= off < v.end:
                        v.lost_dir_at(off, new)
                    k = data.find(b".          ", k + 1, limit)
            else:
                first = max(v.heap, cstart)
                first += -(first - v.heap) % v.cs
                for off in range(first, min(end, v.end), v.cs):
                    if data[off - cstart] in (0x85, 0x05):
                        v.lost_dir_at(off, new)
        if not new:
            return
        jpgs = [r for r in new if not r.name.startswith("._")]
        self.stats["lost folder entries"] += len(jpgs)
        listed = 0
        for r in jpgs:
            self._fs_by_start.setdefault(r.start, r)
            if r.start in self._known or r.start in self._starts or r.start < cstart:
                continue
            if not (MIN_JPEG <= r.size <= MAX_JPEG) or r.start + r.size > self.src.size:
                continue
            info = self._quick_header(r.extents, r.size)
            if info is None:
                continue  # overwritten: the deep scan still looks there
            info["start"] = r.start
            self._add(info, r, r.extents)
            self._known[r.start] = r.extents[0][1]
            self._lost[r.start] = r
            listed += 1
        self.stats["lost folder photos listed early"] += listed
        self.log("lost folder(s) near %d: %d JPEG entries, %d listed right away" % (cstart, len(jpgs), listed))

    # -- pass 1b
    def _existing_pass(self):
        """List photos the file system says exist right away, instead of waiting
        for the deep scan to reach their position on the card."""
        self.phase = "Listing existing photos"
        for rec in sorted(self.recs, key=lambda r: r.start):
            if self.cancelled:
                return
            if rec.deleted or not rec.exact or not (MIN_JPEG <= rec.size <= MAX_JPEG):
                continue
            if rec.start in self._known:
                continue
            tmp = {"extents": rec.extents, "length": rec.size}
            info = None
            for n in (128 << 10, 2 << 20):  # header is normally in the first 128 KB
                head = read_item(self.src, tmp, 0, min(n, rec.size))
                info = parse_jpeg(BufSource(head), 0, header_only=True)
                if info is not None or n >= rec.size:
                    break
            if info is None:
                self.stats["existing entry not a valid JPEG header"] += 1
                continue  # damaged/not really a JPEG: let the deep scan decide
            info["start"] = rec.start
            self._add(info, rec, rec.extents)
            self._known[rec.start] = rec.extents[0][1]
        self.log("listed %d existing photos from the file system" % len(self.found))

    # -- pass 2
    def _deep_pass(self):
        self.phase = "Deep scan"
        src = self.src
        size = src.size
        chunk = CHUNK_BLOCKS * BLOCK
        i = 0
        while i < size and not self.cancelled:
            cstart = i - (i % chunk)
            data = src.get(cstart, chunk + 2)
            if not data:
                break
            local = i - cstart
            limit = min(chunk, len(data))
            next_i = cstart + chunk
            try:
                self._find_lost_dirs(cstart, data, limit)
            except DeviceGone:
                raise
            except Exception as e:  # never let a damaged folder stop the scan
                self.log("lost-folder check failed near %d: %s" % (cstart, e))
            while not self.cancelled:
                k = data.find(SIG, local)
                if k == -1 or k >= limit:
                    break
                p = cstart + k
                if p % ALIGN:
                    # Not on a sector boundary: a JPEG inside another file, e.g. a phone's
                    # thumbnail cache or a preview inside a video/RAW file.
                    info = parse_jpeg(src, p)
                    if info and info["width"] >= MIN_EMBED_DIM and info["height"] >= MIN_EMBED_DIM:
                        self.stats["inside other files"] += 1
                        self._add(info, None, [(p, info["length"])], status="embedded")
                        end = p + info["length"]
                        if end >= cstart + chunk:
                            next_i = end
                            break
                        local = end - cstart
                    else:
                        local = k + 1
                    continue
                if p in self._known and p not in self._lost:  # listed from the file system
                    end = p + self._known[p]
                    end += -end % ALIGN
                    if end >= cstart + chunk:
                        next_i = end
                        break
                    local = end - cstart
                    continue
                why = []
                info = parse_jpeg(src, p, why)
                self.stats["checked"] += 1
                if p in self._lost:
                    rec = self._lost.pop(p)
                    if info and info["length"] <= rec.size <= info["length"] + FS_SIZE_SLACK:
                        end = p + rec.size  # listed early from a lost folder and confirmed
                        end += -end % ALIGN
                        if end >= cstart + chunk:
                            next_i = end
                            break
                        local = end - cstart
                        continue
                    if info:  # a different photo now sits there: list it too
                        self._add(info, None, [(p, info["length"])])
                        end = p + info["length"]
                        end += -end % ALIGN
                        if end >= cstart + chunk:
                            next_i = end
                            break
                        local = end - cstart
                        continue
                if info is None:
                    self.stats["rejected: " + (why[0] if why else "?")] += 1
                    if self.stats["logged_rejects"] < 20:
                        self.stats["logged_rejects"] += 1
                        self.log("rejected candidate at %d: %s; bytes %s" % (
                            p, why[0] if why else "?", src.get(p, 12).hex(" ")))
                    local = k + 1
                    continue
                rec = self._match(p)
                extents = [(p, info["length"])]
                if rec is not None:
                    if rec.exact and rec.size >= info["length"] - 2:
                        extents = rec.extents  # exact original file from the file system
                    elif info["length"] <= rec.size <= info["length"] + FS_SIZE_SLACK:
                        extents = [(p, rec.size)]  # original size incl. any trailing data
                self._add(info, rec, extents)
                end = p + info["length"]
                end += -end % ALIGN
                if end >= cstart + chunk:
                    next_i = end
                    break
                local = end - cstart
            i = max(next_i, i + 1)
            self.scanned = min(i, size)
        if not self.cancelled:
            self.scanned = size

    # -- pass 3
    def _fs_only_pass(self):
        """Photos the file system knows about that the deep scan couldn't piece
        together (stored in fragments)."""
        self.phase = "Checking fragmented files"
        with self._lock:
            starts = {it["extents"][0][0] for it in self.found} | set(self._known)
        for rec in self.recs:
            if self.cancelled:
                return
            if id(rec) in self._fs_used or not rec.exact or len(rec.extents) < 2:
                continue
            if rec.size > MAX_JPEG or rec.size < MIN_JPEG:
                continue
            if rec.start in starts:
                continue
            tmp = {"extents": rec.extents, "length": rec.size}
            data = read_item(self.src, tmp)
            info = parse_jpeg(BufSource(data), 0)
            if info is None:
                continue
            self._add(info, rec, rec.extents)
            starts.add(rec.start)


def exif_time(s):
    try:
        return time.mktime(time.strptime(s, "%Y:%m:%d %H:%M:%S"))
    except (ValueError, OverflowError, TypeError):
        return None
