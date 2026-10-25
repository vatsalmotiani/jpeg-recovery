"""Tests for the JPEG carver and the HTTP API.

Run:  python3 -m unittest discover -s tests -v
Needs Pillow only to *generate* test photos (the app itself needs nothing):
      python3 -m pip install --user pillow
"""

import hashlib
import io
import json
import os
import random
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "JPEG Recovery.app", "Contents", "Resources"))
import carver  # noqa: E402

try:
    from PIL import Image
except ImportError:  # pragma: no cover
    Image = None

MiB = 1 << 20


def read(path):
    with open(path, "rb") as f:
        return f.read()


def sha(b):
    return hashlib.sha256(b).hexdigest()


def photo(w, h, seed, mode="RGB", **save):
    rnd = random.Random(seed)
    img = Image.new(mode, (w, h))
    px = img.load()
    # smooth gradient + noise, like a real photo
    for y in range(h):
        for x in range(w):
            n = rnd.randint(0, 40)
            if mode == "L":
                px[x, y] = (x * 255 // w + n) % 256
            else:
                px[x, y] = ((x * 255 // w + n) % 256, (y * 255 // h + n) % 256, (seed * 37 + n) % 256)
    buf = io.BytesIO()
    img.save(buf, "JPEG", **save)
    return buf.getvalue()


def noise_photo(w, h, seed, **save):
    img = Image.frombytes("RGB", (w, h), random.Random(seed).randbytes(w * h * 3))
    buf = io.BytesIO()
    img.save(buf, "JPEG", **save)
    return buf.getvalue()


def with_exif_thumb(seed):
    img = Image.open(io.BytesIO(photo(640, 480, seed)))
    exif = Image.Exif()
    exif[0x0112] = 6  # orientation: rotate 90
    thumb = io.BytesIO()
    img.resize((160, 120)).save(thumb, "JPEG")
    # Build EXIF with IFD1 thumbnail via Pillow's raw bytes support.
    raw = exif.tobytes()
    out = io.BytesIO()
    img.save(out, "JPEG", exif=raw, quality=90)
    data = out.getvalue()
    # Insert a second APP1-contained thumbnail-like JPEG to mimic camera EXIF thumbnails.
    t = thumb.getvalue()
    payload = b"Exif\x00\x00" + raw[6:] if raw.startswith(b"Exif") else b"Exif\x00\x00" + raw
    payload += t
    seg = b"\xff\xe1" + (len(payload) + 2).to_bytes(2, "big") + payload
    # replace the APP1 Pillow wrote with ours
    i = data.find(b"\xff\xe1")
    L = int.from_bytes(data[i + 2:i + 4], "big")
    return data[:i] + seg + data[i + 2 + L:]


def scan(path):
    src = carver.Source(path, os.path.getsize(path))
    sc = carver.Scanner(src)
    sc.run()
    assert sc.error is None, sc.error
    out = [carver.read_item(src, f) for f in sc.found]
    return sc, src, out


@unittest.skipIf(Image is None, "Pillow is needed to generate test photos")
class CarverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="jpegrec_")
        cls.photos = [
            photo(800, 600, 1, quality=92),
            photo(1024, 768, 2, progressive=True, quality=85),
            photo(500, 400, 3, mode="L"),
            photo(640, 480, 4, subsampling=0, quality=100),
            with_exif_thumb(5),
            noise_photo(3000, 2000, 6, quality=95),        # large (~several MB)
            noise_photo(1200, 900, 7, progressive=True, quality=95),
        ]
        # restart markers (DRI) — Pillow supports restart_marker_blocks in newer versions
        try:
            cls.photos.append(photo(700, 500, 8, restart_marker_blocks=4))
        except TypeError:
            pass

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def build_image(self, layout, size):
        """layout: list of (offset, bytes). Rest is random junk / zeros."""
        rnd = random.Random(99)
        buf = bytearray(rnd.randbytes(size // 2)) + bytearray(size - size // 2)
        for off, data in layout:
            buf[off:off + len(data)] = data
        path = os.path.join(self.tmp, "img_%d.bin" % len(os.listdir(self.tmp)))
        with open(path, "wb") as f:
            f.write(buf)
        return path

    def test_all_photos_recovered_byte_exact(self):
        layout, off = [], 512 * 7
        for p in self.photos:
            layout.append((off, p))
            off += len(p) + random.Random(off).randint(0, 70000)
            off += -off % 512  # files start on sector boundaries
        path = self.build_image(layout, off + 3 * MiB)
        sc, src, out = scan(path)
        self.assertEqual(sorted(sha(p) for p in self.photos), sorted(sha(o) for o in out))
        for f, (o, p) in zip(sc.found, layout):
            self.assertEqual(f["start"], o)
        src.close()

    def test_chunk_boundary_and_junk(self):
        chunk = carver.CHUNK_BLOCKS * carver.BLOCK
        a, b, c = self.photos[0], self.photos[5], self.photos[1]
        layout = [
            (chunk - 512, a),               # header near the chunk boundary
            (2 * chunk - 1024, b),          # body spans boundary
            (3 * chunk - 512, c),           # starts in the last sector of a chunk
        ]
        path = self.build_image(layout, 3 * chunk + 4 * MiB)
        _, src, out = scan(path)
        self.assertEqual(sorted(map(sha, [a, b, c])), sorted(map(sha, out)))
        src.close()

    def test_rejects_truncated_tiny_and_fake(self):
        good = self.photos[0]
        truncated = self.photos[1][: len(self.photos[1]) // 2]
        tiny = photo(8, 8, 9)
        fake = b"\xff\xd8\xff\xe0\x00\x10JFIF\x00" + os.urandom(5000) + b"\xff\xd9"
        layout = [(1024, truncated), (2 * MiB, tiny), (3 * MiB, fake), (5 * MiB, good)]
        # zeros after truncated photo -> must not swallow anything
        path = self.build_image(layout, 8 * MiB)
        _, src, out = scan(path)
        self.assertEqual([sha(good)], [sha(o) for o in out])
        src.close()

    def test_exif_thumbnail_not_duplicated_and_orientation(self):
        p = self.photos[4]
        path = self.build_image([(4096, p)], 2 * MiB)
        sc, src, out = scan(path)
        self.assertEqual([sha(p)], [sha(o) for o in out])
        f = sc.found[0]
        self.assertEqual(f["orientation"], 6)
        self.assertIsNotNone(f["thumb_rel"])
        thumb = carver.read_item(src, f, f["thumb_rel"], f["thumb_len"])
        self.assertEqual(Image.open(io.BytesIO(thumb)).size, (160, 120))
        src.close()

    def test_all_outputs_decode_at_full_size(self):
        layout, off = [], 0
        for p in self.photos:
            layout.append((off, p))
            off += len(p)
            off += -off % 512
        path = self.build_image(layout, off + MiB)
        _, src, out = scan(path)
        for o, p in zip(out, self.photos):
            self.assertEqual(Image.open(io.BytesIO(o)).size, Image.open(io.BytesIO(p)).size)
        src.close()


    def test_finds_jpegs_inside_other_files_and_labels_them(self):
        # e.g. an Android thumbnail cache or the preview inside a RAW/video file:
        # not on a sector boundary, still worth recovering, but labelled.
        good, embedded, icon = self.photos[0], self.photos[2], photo(40, 40, 77)
        path = self.build_image([(4096, good), (2 * MiB + 77, embedded), (3 * MiB + 5, icon)], 4 * MiB)
        sc, src, out = scan(path)
        self.assertEqual([sha(good), sha(embedded)], [sha(o) for o in out])  # tiny icon ignored
        self.assertEqual([f["status"] for f in sc.found], ["unknown", "embedded"])
        src.close()

    def test_ultra_hdr_mpf_kept_whole(self):
        main_img = Image.open(io.BytesIO(photo(600, 400, 11)))
        second = io.BytesIO()
        Image.open(io.BytesIO(photo(300, 200, 12))).save(second, "JPEG")
        buf = io.BytesIO()
        try:
            main_img.save(buf, "MPO", save_all=True, append_images=[Image.open(second)])
        except (KeyError, ValueError, OSError):
            self.skipTest("Pillow can't write MPO files")
        mpo = buf.getvalue()
        first_eoi = mpo.find(b"\xff\xd9\xff\xd8")
        self.assertGreater(first_eoi, 0)
        path = self.build_image([(8192, mpo)], 2 * MiB)
        _, src, out = scan(path)
        self.assertEqual([sha(mpo)], [sha(o) for o in out])
        src.close()

    def test_bad_sectors_are_skipped_not_fatal(self):
        a, b = self.photos[0], self.photos[3]
        path = self.build_image([(4096, a), (6 * MiB, b)], 8 * MiB)
        src = carver.Source(path, os.path.getsize(path))
        real = src._pread_once
        bad = (3 * MiB, 3 * MiB + 8192)  # unreadable area between the two photos

        def flaky(n, off):
            if off < bad[1] and off + n > bad[0]:
                raise OSError(5, "Input/output error")
            return real(n, off)
        src._pread_once = flaky
        sc = carver.Scanner(src)
        sc.run()
        self.assertIsNone(sc.error)
        self.assertEqual(src.bad_bytes, 8192)
        self.assertEqual(sorted(map(sha, [a, b])), sorted(sha(carver.read_item(src, f)) for f in sc.found))
        src.close()

    def test_disconnect_reports_cleanly(self):
        path = self.build_image([(4096, self.photos[0])], 40 * MiB)
        src = carver.Source(path, os.path.getsize(path))
        real = src._pread_once

        def gone(n, off):
            if off >= 20 * MiB:
                raise OSError(6, "Device not configured")  # ENXIO
            return real(n, off)
        src._pread_once = gone
        sc = carver.Scanner(src)
        sc.run()
        self.assertIn("disconnected", sc.error)
        self.assertEqual(len(sc.found), 1)
        src.close()


@unittest.skipIf(Image is None, "Pillow is needed to generate test photos")
class ApiTests(unittest.TestCase):
    def test_end_to_end_http(self):
        tmp = tempfile.mkdtemp(prefix="jpegrec_api_")
        try:
            photos = [photo(400, 300, s) for s in range(5)]
            blob = bytearray(os.urandom(MiB))
            for p in photos:
                blob += p + os.urandom(3000)
                blob += os.urandom(-len(blob) % 512)  # next file starts on a sector boundary
            img = os.path.join(tmp, "card.img")
            with open(img, "wb") as f:
                f.write(blob)
            port = 18000 + random.randint(0, 2000)
            env = dict(os.environ, JPEG_RECOVERY_PORT=str(port), JPEG_RECOVERY_NO_BROWSER="1",
                       JPEG_RECOVERY_LOG=os.path.join(tmp, "scan.log"))
            app = os.path.join(os.path.dirname(HERE), "JPEG Recovery.app", "Contents", "Resources", "app.py")
            proc = subprocess.Popen([sys.executable, "-I", app], env=env,
                                    stdout=subprocess.PIPE, text=True)
            try:
                line = ""
                while "Open:" not in line:
                    line = proc.stdout.readline()
                url = line.split("Open:")[1].strip()
                token = url.split("t=")[1]
                base = "http://127.0.0.1:%d" % port

                def call(path, body=None):
                    req = urllib.request.Request(base + path, headers={"X-Token": token,
                                                 "Content-Type": "application/json"},
                                                 data=None if body is None else json.dumps(body).encode())
                    with urllib.request.urlopen(req, timeout=30) as r:
                        return r.read()

                self.assertIn(b"JPEG Recovery", urllib.request.urlopen(url).read())
                # wrong token is rejected
                with self.assertRaises(urllib.error.HTTPError):
                    urllib.request.urlopen(base + "/api/status?t=nope")
                call("/api/scan", {"path": img})
                for _ in range(100):
                    st = json.loads(call("/api/status?since=0"))
                    if st["state"] == "done":
                        break
                    time.sleep(0.1)
                self.assertEqual(st["count"], 5)
                self.assertEqual(call("/img/0?t=" + token), photos[0])
                dest = os.path.join(tmp, "out", "nested")
                call("/api/recover", {"ids": [i["id"] for i in st["items"]], "dest": dest})
                for _ in range(100):
                    rec = json.loads(call("/api/status?since=5"))["recover"]
                    if rec["done"]:
                        break
                    time.sleep(0.1)
                self.assertEqual(rec["saved"], 5)
                got = sorted(sha(read(os.path.join(dest, n))) for n in os.listdir(dest))
                self.assertEqual(got, sorted(map(sha, photos)))
                # saving again must not overwrite existing files
                call("/api/recover", {"ids": [0], "dest": dest})
                time.sleep(0.5)
                self.assertEqual(len(os.listdir(dest)), 6)
            finally:
                proc.terminate()
                proc.wait(5)
                proc.stdout.close()
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
