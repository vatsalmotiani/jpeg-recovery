#!/usr/bin/env python3
"""Check what is on a card and why photos are or aren't being found.

    sudo python3 diagnose.py              (auto-picks the card if only one is plugged in)
    sudo python3 diagnose.py /dev/rdisk4

Read-only. Takes about a minute. Saves a report to your Desktop
(jpeg-recovery-report.txt): send that file when asking for help.
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
HEAD_BYTES = 256 * MiB      # read the first 256 MiB fully
TRIAL_BYTES = 1024 * MiB    # run the real scanner over the first 1 GiB
SAMPLES = 48                # plus this many 4 MiB samples spread over the rest
OTHER = [  # (label, test(bytes at a sector start))
    ("HEIC/HEIF photo (iPhone/Android)", lambda b: b[4:8] == b"ftyp" and b[8:12] in (b"heic", b"heix", b"mif1", b"msf1", b"hevc", b"heim", b"heis", b"avif")),
    ("MP4/MOV video", lambda b: b[4:8] == b"ftyp" and b[8:12] not in (b"heic", b"heix", b"mif1", b"msf1", b"hevc", b"heim", b"heis", b"avif")),
    ("RAW photo / TIFF (CR2, NEF, ARW, DNG)", lambda b: b[:4] in (b"II*\x00", b"MM\x00*")),
    ("Canon CR3 / Fuji RAF", lambda b: b[4:12] == b"ftypcrx " or b[:8] == b"FUJIFILM"),
    ("PNG image", lambda b: b[:8] == b"\x89PNG\r\n\x1a\n"),
]


class Tee:
    """Print to the terminal and collect everything for the report file."""

    def __init__(self, stream):
        self.stream, self.parts = stream, []

    def write(self, s):
        self.stream.write(s)
        if "\r" not in s:
            self.parts.append(s)

    def flush(self):
        self.stream.flush()


def save_report(text):
    uid = int(os.environ.get("SUDO_UID") or os.getuid())
    gid = int(os.environ.get("SUDO_GID") or os.getgid())
    home = app.pwd.getpwuid(uid).pw_dir
    path = os.environ.get("JPEG_RECOVERY_REPORT") or os.path.join(home, "Desktop", "jpeg-recovery-report.txt")
    with open(path, "w") as f:
        f.write(text)
    if os.geteuid() == 0:
        os.chown(path, uid, gid)
    return path


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
    tee = Tee(sys.stdout)
    sys.stdout = tee
    try:
        run()
    except Exception:
        import traceback
        traceback.print_exc(file=tee)
    finally:
        sys.stdout = tee.stream
        try:
            print("\nReport saved to: %s\nPlease send that file." % save_report("".join(tee.parts)))
        except OSError as e:
            print("\nCould not save the report (%s). Please copy the text above instead." % e)


def git_version():
    try:
        return app.subprocess.run(["git", "-C", HERE, "log", "-1", "--format=%h %cd"],
                                  capture_output=True, text=True, timeout=5).stdout.strip()
    except Exception:
        return "unknown"


def run():
    path = pick_device()
    print("JPEG Recovery diagnostics\n=========================")
    print("Version: %s" % git_version())
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
        print("Device: %s, %s, %s, mounted volumes: %s" % (
            info.get("MediaName"), info.get("BusProtocol"),
            "removable" if info.get("RemovableMedia") else "fixed", app._volumes_of(path) or "none"))
        lst = app._diskutil_plist("list", m.group(1))
        for e in lst.get("AllDisksAndPartitions", []):
            for part in e.get("Partitions", []):
                print("  partition %s: %s, %.2f GB, %s" % (part.get("DeviceIdentifier"), part.get("Content"),
                      part.get("Size", 0) / 1e9, part.get("VolumeName") or ""))

    # ---- read test
    print("\n[0] Read test")
    speed = 0
    t0 = time.time()
    test = carver.Source(path, size, sector)
    got = 0
    try:
        for off in range(0, min(size, 64 * MiB), MiB):
            got += len(test._pread(MiB, off))
        dt = max(time.time() - t0, 0.001)
        speed = got / dt
        print("  64 MB sequential read: %.1f MB/s, unreadable %d KB" % (speed / 1e6, test.bad_bytes // 1024))
        sample = test._pread(4096, 0)
        print("  first 4 KB: %d zero bytes, starts %s" % (sample.count(0), sample[:16].hex(" ")))
    except OSError as e:
        print("  READ FAILED: %s" % e)
    test.close()

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
    sys.stdout.write("\r" + " " * 40 + "\r")
    print("  Read %d MB in %.0fs (%.0f MB/s)" % (done // MiB, time.time() - t0,
          done / MiB / max(time.time() - t0, 0.01)))
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

    # ---- the real scanner, on the first part of the card
    print("\n[2b] Real scanner on the first %d MB" % (min(size, TRIAL_BYTES) // MiB))
    trial = carver.Source(path, min(size, TRIAL_BYTES), sector)
    sc = carver.Scanner(trial)
    sc.log = lambda msg: print("  log: " + msg)
    t0 = time.time()
    sc.run()
    print("  finished in %.0fs, found %d photos, error: %s" % (time.time() - t0, len(sc.found), sc.error))
    print("  stats: %s" % {k: v for k, v in sc.stats.items() if k != "logged_rejects"})
    for f in sc.found[:5]:
        print("    %s (%s) %dx%d %d KB at %d" % (f["name"] or "(no name)", f["status"], f["width"],
              f["height"], f["length"] // 1024, f["extents"][0][0]))
    trial.close()

    # ---- the app's own log from earlier scans
    lp = app.log_path()
    print("\n[4] App log (%s)" % lp)
    try:
        with open(lp) as f:
            lines = f.readlines()
        print("".join("  " + ln for ln in lines[-150:]).rstrip() or "  (empty)")
    except OSError:
        print("  (no log yet: scans made with versions before today don't write one)")

    # ---- verdict
    print("\n[3] Verdict")
    nz = blocks - zero - ff
    if not jpg and vols:
        print("  The card's file list has no JPEG entries (formatted or emptied card), so original")
        print("  names can't be recovered; the deep scan finds photos by their content instead.")
    if sc.found or any(not r.deleted for r in jpg):
        print("  JPEG photos ARE present and the scanner finds them. If the app shows none, that's a")
        print("  bug: please send this report.")
    elif good:
        first_gb = min(p for p, _ in good) / 1e9
        print("  JPEG photos ARE present, starting around %.1f GB into the card, so the app finds" % first_gb)
        print("  them once its scan gets that far (about %d min at this card's read speed). The"
              % max(1, round(first_gb * 1e9 / max(speed, 1) / 60)))
        print("  full card takes about %d min. Let the scan finish." % max(1, round(size / max(speed, 1) / 60)))
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
