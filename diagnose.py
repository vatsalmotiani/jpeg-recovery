#!/usr/bin/env python3
"""Check what is on a card and why photos are or aren't being found.

    sudo python3 diagnose.py              (auto-picks the card if only one is plugged in)
    sudo python3 diagnose.py /dev/rdisk4

Read-only. Takes about 30 seconds. Paste the output when asking for help.
"""

import collections
import os
import sys
import time
import zlib

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "JPEG Recovery.app", "Contents", "Resources"))
import app  # noqa: E402
import carver  # noqa: E402
import fsmeta  # noqa: E402

MiB = 1 << 20
HEAD_BYTES = 1024 * MiB     # read the first 1 GiB fully
SAMPLES = 48                # plus this many 4 MiB samples spread over the rest
OTHER = [  # (label, test(bytes at a sector start))
    ("HEIC/HEIF photo (iPhone/Android)", lambda b: b[4:8] == b"ftyp" and b[8:12] in (b"heic", b"heix", b"mif1", b"msf1", b"hevc", b"heim", b"heis", b"avif")),
    ("MP4/MOV video", lambda b: b[4:8] == b"ftyp" and b[8:12] not in (b"heic", b"heix", b"mif1", b"msf1", b"hevc", b"heim", b"heis", b"avif")),
    ("RAW photo / TIFF (CR2, NEF, ARW, DNG)", lambda b: b[:4] in (b"II*\x00", b"MM\x00*")),
    ("Canon CR3 / Fuji RAF", lambda b: b[4:12] == b"ftypcrx " or b[:8] == b"FUJIFILM"),
    ("PNG image", lambda b: b[:8] == b"\x89PNG\r\n\x1a\n"),
]


def pick_device():
    if len(sys.argv) > 1:
        return sys.argv[1]
    devs = app.list_devices()
    if len(devs) == 1:
        return devs[0]["path"]
    print("Plugged-in drives:" if devs else "No external drives found.")
    for d in devs:
        print("  %s  %s  %.1f GB  %s" % (d["path"], d["name"], d["size"] / 1e9, ", ".join(d["volumes"])))
    print("\nRun again with the drive, e.g.:  sudo python3 diagnose.py /dev/rdisk4")
    sys.exit(1)


def main():
    path = pick_device()
    print("JPEG Recovery diagnostics\n=========================")
    print("macOS %s, Python %s, running as %s" % (
        os.uname().release, sys.version.split()[0], "root" if os.geteuid() == 0 else "normal user (use sudo!)"))
    try:
        size, sector = app.source_geometry(path)
        src = carver.Source(path, size, sector)
    except OSError as e:
        print("Cannot open %s: %s" % (path, e))
        sys.exit(1)
    print("Drive: %s  size %.2f GB  sector %d bytes" % (path, size / 1e9, sector))
    m = app.re.match(r"r?(disk\d+)", os.path.basename(path))
    if m:
        info = app._diskutil_plist("info", m.group(1))
        print("Device: %s, %s, %s" % (info.get("MediaName"), info.get("BusProtocol"),
                                      "removable" if info.get("RemovableMedia") else "fixed"))

    # ---- file system
    print("\n[1] File system")
    exts = collections.Counter()
    real_is_jpeg = fsmeta._is_jpeg_name

    def count_all(name):
        exts[os.path.splitext(name)[1].lower() or "(none)"] += 1
        return real_is_jpeg(name)
    fsmeta._is_jpeg_name = count_all
    try:
        vols = fsmeta.find_volumes(src, sector)
        recs, desc = fsmeta.scan(src, sector)
    finally:
        fsmeta._is_jpeg_name = real_is_jpeg
    print("  Volumes: %s" % (", ".join(desc) or "none readable (not FAT/exFAT, e.g. NTFS/HFS+/APFS/ext4, encrypted, or wiped)"))
    if not vols:
        print("  First sector: %s" % src.get(0, 16).hex(" "))
    if exts:
        print("  Files by type (existing + deleted): %s" % ", ".join("%s %d" % kv for kv in exts.most_common(12)))
    jpg = [r for r in recs if not r.name.startswith("._")]
    print("  JPEG entries: %d existing, %d deleted" % (sum(not r.deleted for r in jpg), sum(r.deleted for r in jpg)))
    for r in jpg[:6]:
        why = []
        if len(r.extents) == 1:
            ok = carver.parse_jpeg(src, r.start, why)
        else:
            ok = carver.parse_jpeg(carver.BufSource(carver.read_item(src, {"extents": r.extents, "length": r.size})), 0, why)
        print("    %-28s %-8s %8d KB at %d: %s  first bytes: %s" % (
            (r.folder.rstrip("/") + "/" + r.name)[-28:], "deleted" if r.deleted else "existing",
            r.size // 1024, r.start, "OK (%dx%d)" % (ok["width"], ok["height"]) if ok else "REJECTED: " + why[0],
            src.get(r.start, 8).hex(" ")))

    # ---- raw data sample
    print("\n[2] Raw data sample")
    spans = [(0, min(HEAD_BYTES, size))]
    if size > HEAD_BYTES:
        step = (size - HEAD_BYTES) // SAMPLES
        spans += [(HEAD_BYTES + k * step - (HEAD_BYTES + k * step) % MiB, 4 * MiB) for k in range(SAMPLES)]
    total = sum(n for _, n in spans)
    zero = ff = blocks = random_like = 0
    sig_aligned = sig_unaligned = 0
    reasons = collections.Counter()
    good = []
    other = collections.Counter()
    done, t0 = 0, time.time()
    for off, n in spans:
        for b_off in range(off, min(off + n, size), MiB):
            data = src.get(b_off, MiB)
            if not data:
                break
            blocks += 1
            done += len(data)
            if data.count(0) == len(data):
                zero += 1
                continue
            if data.count(255) == len(data):
                ff += 1
                continue
            if len(zlib.compress(data[:65536], 1)) > 65000:
                random_like += 1
            for s in range(0, len(data), 512):
                head = data[s:s + 12]
                for label, test in OTHER:
                    if test(head):
                        other[label] += 1
            k = data.find(carver.SIG)
            while k != -1:
                p = b_off + k
                if p % carver.ALIGN:
                    sig_unaligned += 1
                else:
                    sig_aligned += 1
                    if sum(reasons.values()) + len(good) < 400:
                        why = []
                        r = carver.parse_jpeg(src, p, why)
                        if r:
                            good.append((p, r))
                        else:
                            reasons[why[0] if why else "?"] += 1
                k = data.find(carver.SIG, k + 1)
            sys.stdout.write("\r  read %d / %d MB" % (done // MiB, total // MiB))
            sys.stdout.flush()
    print("\r  Read %d MB in %.0fs (%.0f MB/s)%s" % (done // MiB, time.time() - t0,
          done / MiB / max(time.time() - t0, 0.01), " " * 20))
    if src.bad_bytes:
        print("  UNREADABLE (bad) areas: %d KB" % (src.bad_bytes // 1024))
    print("  1 MB blocks: %d all-zero, %d all-FF (erased), %d random-looking, %d other" % (
        zero, ff, random_like, blocks - zero - ff - random_like))
    print("  JPEG starts: %d at sector boundaries, %d elsewhere (inside other files)" % (sig_aligned, sig_unaligned))
    print("  Valid JPEGs found in sample: %d" % len(good))
    for p, r in good[:3]:
        print("    at %d: %dx%d, %d KB" % (p, r["width"], r["height"], r["length"] // 1024))
    for msg, c in reasons.most_common(6):
        print("  Rejected %d: %s" % (c, msg))
    if other:
        print("  Other file types seen: %s" % ", ".join("%s x%d" % kv for kv in other.most_common()))

    # ---- verdict
    print("\n[3] Verdict")
    nz = blocks - zero - ff
    if good or any(not r.deleted for r in jpg):
        print("  JPEG photos ARE present. If the app shows none, that's a bug: please send this output.")
    elif blocks and zero + ff >= blocks * 0.95:
        print("  The sampled card areas are empty (all zeros/FF). The card was probably erased/TRIMmed")
        print("  or never held data in these areas. Data that was wiped can't be recovered.")
    elif other.get("HEIC/HEIF photo (iPhone/Android)"):
        print("  The photos on this card are HEIC, not JPEG. This tool only recovers .jpg files.")
    elif nz and random_like >= nz * 0.9 and not sig_aligned and not other:
        print("  The data looks encrypted (random, no file signatures at all). This happens with Android")
        print("  'internal storage' cards or encrypted drives; no recovery tool can read photos from it.")
    elif other:
        print("  No JPEGs in the sample, but other file types are present (see above).")
    else:
        print("  No JPEG photos in the sampled areas. They may be elsewhere on the card; let the full scan finish.")
    src.close()


if __name__ == "__main__":
    main()
