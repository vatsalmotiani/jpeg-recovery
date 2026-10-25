"""End-to-end tests on real macOS disk images, like real SD cards / pendrives.

Creates FAT16 / FAT32 / exFAT / HFS+ / APFS images with MBR, GPT or no
partition table, copies photos into camera-style folders, deletes some,
then scans the raw device exactly as the app does.

Run:  python3 -m unittest tests.test_real_disks -v      (macOS only, ~1 minute)
"""

import hashlib
import io
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "JPEG Recovery.app", "Contents", "Resources"))
import app  # noqa: E402
import carver  # noqa: E402

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

HAVE_HDIUTIL = sys.platform == "darwin" and shutil.which("hdiutil")


def sha(b):
    return hashlib.sha256(b).hexdigest()


def make_photo(seed, w, h):
    rnd = random.Random(seed)
    img = Image.frombytes("RGB", (w, h), rnd.randbytes(w * h * 3))
    exif = Image.Exif()
    exif[0x0132] = "2023:07:%02d 10:20:30" % (1 + seed % 28)
    buf = io.BytesIO()
    img.save(buf, "JPEG", quality=90, exif=exif.tobytes(), progressive=bool(seed % 2))
    return buf.getvalue()


def sh(*cmd):
    return subprocess.run(cmd, check=True, capture_output=True, text=True).stdout


class Disk:
    def __init__(self, tmp, fs, layout, size="120m"):
        self.img = tempfile.mktemp(suffix=".dmg", dir=tmp)
        self.mnt = tempfile.mkdtemp(dir=tmp)
        sh("hdiutil", "create", "-size", size, "-fs", fs, "-volname", "CARD", "-layout", layout,
           self.img, "-quiet")
        self.dev = None

    def mount(self):
        out = sh("hdiutil", "attach", "-mountpoint", self.mnt, "-nobrowse", self.img)
        self.dev = out.split()[0]
        return self.mnt

    def unmount(self):
        subprocess.run(["sync"])
        sh("hdiutil", "detach", self.dev, "-force")
        self.dev = None

    def attach_raw(self):
        out = sh("hdiutil", "attach", "-nomount", "-readonly", self.img)
        self.dev = out.split()[0]
        return "/dev/r" + self.dev[len("/dev/"):]


def scan_device(raw):
    size, sector = app.source_geometry(raw)
    src = carver.Source(raw, size, sector)
    sc = carver.Scanner(src)
    sc.run()
    assert sc.error is None, sc.error
    return sc, src


@unittest.skipUnless(HAVE_HDIUTIL and Image is not None, "needs macOS hdiutil and Pillow")
class RealDiskTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jpegrec_disk_")
        cls.photos = {i: make_photo(i, 640 + 32 * (i % 5), 480) for i in range(12)}

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def tearDown(self):
        d = getattr(self, "disk", None)
        if d and d.dev:
            subprocess.run(["hdiutil", "detach", d.dev, "-force"], capture_output=True)

    def write(self, path, data, mtime):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        os.utime(path, (mtime, mtime))

    def run_case(self, fs, layout, expect_names=True, deleted_names="full"):
        self.disk = d = Disk(self.tmp, fs, layout)
        m = d.mount()
        mt = 1688000000
        files = {
            "DCIM/100CANON/IMG_0001.JPG": 0,
            "DCIM/100CANON/IMG_0002.JPG": 1,
            "DCIM/100CANON/IMG_0003.JPG": 2,
            "DCIM/101CANON/IMG_0101.JPG": 3,
            "DCIM/101CANON/IMG_0102.JPG": 4,
            "Holiday Photos/Beach sunset at Goa.jpg": 5,
            "Holiday Photos/family.jpeg": 6,
            "photo.jpg": 7,
        }
        for k, (rel, idx) in enumerate(files.items()):
            self.write(os.path.join(m, rel), self.photos[idx], mt + k * 60)
        d.unmount()
        m = d.mount()
        deleted = ["DCIM/100CANON/IMG_0002.JPG", "Holiday Photos/Beach sunset at Goa.jpg"]
        for rel in deleted:
            os.remove(os.path.join(m, rel))
        sh("rm", "-rf", os.path.join(m, "DCIM/101CANON"))  # whole folder deleted
        deleted += ["DCIM/101CANON/IMG_0101.JPG", "DCIM/101CANON/IMG_0102.JPG"]
        d.unmount()

        raw = d.attach_raw()
        sc, src = scan_device(raw)
        got = {sha(carver.read_item(src, f)): f for f in sc.found}
        want = {rel: sha(self.photos[idx]) for rel, idx in files.items()}
        missing = [rel for rel, h in want.items() if h not in got]
        self.assertEqual(missing, [], "%s/%s missed %s" % (fs, layout, missing))
        self.assertEqual(len(sc.found), len(files), "unexpected extra results")
        if expect_names:
            for rel, h in want.items():
                f = got[h]
                name = os.path.basename(rel)
                is_deleted = rel in deleted
                self.assertEqual(f["status"], "deleted" if is_deleted else "existing", rel)
                if is_deleted and deleted_names == "first-char-lost" and f["name"] != name:
                    self.assertEqual(f["name"][1:].lower(), name[1:].lower(), rel)
                else:
                    self.assertEqual(f["name"].lower(), name.lower(), rel)
                want_folder = ("/" + os.path.dirname(rel)).rstrip("/").lower() or "/"
                if deleted_names == "first-char-lost" and "101CANON" in rel:
                    want_folder = want_folder.replace("101canon", "_01canon")  # FAT drops 1st letter
                self.assertEqual(f["folder"].lower(), want_folder, rel)
                k = list(files).index(rel)
                self.assertAlmostEqual(f["mtime"], mt + k * 60, delta=2, msg=rel)
        src.close()
        return sc

    def test_fat32_mbr(self):
        self.run_case("MS-DOS FAT32", "MBRSPUD", deleted_names="first-char-lost")

    def test_fat32_no_partition_table(self):
        self.run_case("MS-DOS FAT32", "NONE", deleted_names="first-char-lost")

    def test_fat16_mbr(self):
        self.run_case("MS-DOS FAT16", "MBRSPUD", deleted_names="first-char-lost")

    def test_exfat_mbr(self):
        self.run_case("ExFAT", "MBRSPUD")

    def test_exfat_gpt(self):
        self.run_case("ExFAT", "GPTSPUD")

    def test_hfs_gpt_deep_scan_only(self):
        sc = self.run_case("HFS+", "GPTSPUD", expect_names=False)
        self.assertTrue(all(f["status"] == "unknown" for f in sc.found))

    def test_apfs_gpt_deep_scan_only(self):
        self.run_case("APFS", "GPTSPUD", expect_names=False)

    def test_quick_formatted_card(self):
        """Camera-style quick format: fresh empty file-system tables, photo data left in place.
        (macOS Disk Utility "Erase" may TRIM/wipe the data, which no tool can undo.)"""
        for fs in ("ExFAT", "MS-DOS FAT32"):
            with self.subTest(fs=fs):
                self.disk = d = Disk(self.tmp, fs, "MBRSPUD")
                m = d.mount()
                for i in range(6):
                    self.write(os.path.join(m, "DCIM/100MEDIA/DJI_%04d.JPG" % i), self.photos[i], 1688000000)
                d.unmount()
                blank = Disk(self.tmp, fs, "MBRSPUD")
                src_b = carver.Source(blank.img, os.path.getsize(blank.img))
                import fsmeta
                (off, kind), = fsmeta.find_volumes(src_b)
                v = fsmeta.ExFatVolume(src_b, off) if kind == "exfat" else fsmeta.FatVolume(src_b, off)
                root = v.root if kind == "exfat" else (v.root_cluster or 2)
                meta_end = v.coff(root) + v.cs  # boot sectors, FAT, bitmap, root folder
                with open(blank.img, "rb") as f:
                    fresh = f.read(meta_end)
                src_b.close()
                with open(d.img, "r+b") as f:
                    f.write(fresh)
                raw = d.attach_raw()
                sc, src = scan_device(raw)
                got = {sha(carver.read_item(src, f)) for f in sc.found}
                lost = [i for i in range(6) if sha(self.photos[i]) not in got]
                self.assertEqual(lost, [], "%s: photos lost after quick format" % fs)
                src.close()
                sh("hdiutil", "detach", d.dev, "-force")
                d.dev = None

    def test_fragmented_existing_file(self):
        for fs in ("MS-DOS FAT32", "ExFAT"):
            with self.subTest(fs=fs):
                self.disk = d = Disk(self.tmp, fs, "MBRSPUD")
                m = d.mount()
                small = [make_photo(100 + i, 200, 150) for i in range(3)]
                for i, data in enumerate(small):
                    self.write(os.path.join(m, "s%d.jpg" % i), data, 1688000000)
                d.unmount()
                m = d.mount()
                os.remove(os.path.join(m, "s1.jpg"))  # leaves a hole
                big = make_photo(200, 1600, 1200)
                self.write(os.path.join(m, "big.jpg"), big, 1688000000)
                d.unmount()
                raw = d.attach_raw()
                sc, src = scan_device(raw)
                got = {sha(carver.read_item(src, f)): f for f in sc.found}
                self.assertIn(sha(big), got, "%s: fragmented file not recovered" % fs)
                f = got[sha(big)]
                self.assertEqual(f["name"], "big.jpg")
                print("\n    %s: big.jpg stored in %d piece(s), recovered exactly" % (fs, f.get("pieces", len(f["extents"]))), end="")
                src.close()
                sh("hdiutil", "detach", d.dev, "-force")
                d.dev = None


if __name__ == "__main__":
    unittest.main()
