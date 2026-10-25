#!/usr/bin/env python3
"""JPEG Recovery for macOS: local web UI.

Started by "JPEG Recovery.app" (or ./run.sh). It needs admin rights to read the
raw data on the card. Only Python's standard library is used.
"""

import errno
import fcntl
import json
import os
import plistlib
import pwd
import re
import secrets
import socket
import stat
import struct
import subprocess
import sys
import threading
import time
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import carver  # noqa: E402

TOKEN = os.environ.get("JPEG_RECOVERY_TOKEN") or secrets.token_urlsafe(24)
IDLE_EXIT = 15 * 60  # quit after 15 minutes with no browser activity (and nothing running)
STATE = {"scanner": None, "source": None, "label": "", "recover": None, "gen": 0,
         "last_seen": time.time()}
STATE_LOCK = threading.Lock()


# ---------------------------------------------------------------- user/identity
def real_user():
    """(uid, gid, home) of the person using the app, even when running as root."""
    uid = int(os.environ.get("JPEG_RECOVERY_UID") or os.environ.get("SUDO_UID") or os.getuid())
    gid = int(os.environ.get("JPEG_RECOVERY_GID") or os.environ.get("SUDO_GID") or os.getgid())
    try:
        home = pwd.getpwuid(uid).pw_dir
    except KeyError:
        home = os.path.expanduser("~")
    return uid, gid, home


def as_user(cmd):
    """Run a command as the real user, inside their desktop session (needed for dialogs)."""
    uid = real_user()[0]
    if os.geteuid() == 0 and uid != 0:
        return ["launchctl", "asuser", str(uid), "sudo", "-u", "#%d" % uid] + cmd
    return cmd


# ---------------------------------------------------------------- devices
def _diskutil_plist(verb, *args):
    try:
        out = subprocess.run(["diskutil", verb, "-plist"] + list(args),
                             capture_output=True, timeout=30)
    except (subprocess.TimeoutExpired, OSError):
        return {}
    if out.returncode != 0:
        return {}
    try:
        return plistlib.loads(out.stdout)
    except Exception:
        return {}


def list_devices():
    lst = _diskutil_plist("list", "external", "physical")
    devices = []
    for entry in lst.get("AllDisksAndPartitions", []):
        ident = entry.get("DeviceIdentifier")
        if not ident:
            continue
        info = _diskutil_plist("info", ident)
        removable = info.get("RemovableMedia") or info.get("Removable") or info.get("Ejectable")
        if info.get("Internal") and not removable:
            continue  # never offer the Mac's own disk
        vols = [p.get("VolumeName") for p in entry.get("Partitions", []) if p.get("VolumeName")]
        if entry.get("VolumeName"):
            vols.append(entry["VolumeName"])
        fs = [p.get("Content") for p in entry.get("Partitions", []) if p.get("Content")]
        devices.append({
            "path": "/dev/r" + ident,
            "id": ident,
            "name": info.get("MediaName") or info.get("IORegistryEntryName") or ident,
            "size": info.get("TotalSize") or info.get("Size") or entry.get("Size") or 0,
            "volumes": vols,
            "formats": fs,
            "protocol": info.get("BusProtocol", ""),
        })
    return devices


DKIOCGETBLOCKSIZE = 0x40046418
DKIOCGETBLOCKCOUNT = 0x40086419


def source_geometry(path):
    """(size_in_bytes, sector_size). Tries several methods, since some card
    readers don't answer every kind of size query."""
    st = os.stat(path)
    if not (stat.S_ISCHR(st.st_mode) or stat.S_ISBLK(st.st_mode)):  # image file
        return st.st_size, 512
    fd = os.open(path, os.O_RDONLY)
    try:
        # 1. Ask the disk driver directly.
        try:
            bs = struct.unpack("I", fcntl.ioctl(fd, DKIOCGETBLOCKSIZE, b"\0" * 4))[0]
            bc = struct.unpack("Q", fcntl.ioctl(fd, DKIOCGETBLOCKCOUNT, b"\0" * 8))[0]
            if bs and bc:
                return bs * bc, bs
        except OSError:
            pass
        # 2. Ask diskutil.
        m = re.match(r"r?(disk\d+(?:s\d+)?)$", os.path.basename(path))
        if m:
            info = _diskutil_plist("info", m.group(1))
            size = info.get("TotalSize") or info.get("Size") or 0
            bs = info.get("DeviceBlockSize") or 512
            if size:
                return int(size), int(bs)
        # 3. Find the last readable 4 KiB block (binary search, ~40 tiny reads).
        def readable(off):
            try:
                return len(os.pread(fd, 4096, off)) == 4096
            except OSError:
                return False
        if readable(0):
            lo, hi = 0, 1 << 30  # in 4 KiB blocks: up to 4 TiB
            while hi - lo > 1:
                mid = (lo + hi) // 2
                if readable(mid * 4096):
                    lo = mid
                else:
                    hi = mid
            return (lo + 1) * 4096, 512
        raise OSError(errno.EIO, "Could not read the drive's size")
    finally:
        os.close(fd)


def source_size(path):
    return source_geometry(path)[0]


# ---------------------------------------------------------------- scanning
def unmount_device(path):
    """Unmount all volumes of the device so macOS stops writing to it."""
    if not path.startswith("/dev/"):
        return None
    m = re.match(r"r?(disk\d+)", os.path.basename(path))  # rdisk4s1 -> disk4
    if not m:
        return None
    try:
        r = subprocess.run(["diskutil", "unmountDisk", "/dev/" + m.group(1)],
                           capture_output=True, text=True, timeout=60)
    except (subprocess.TimeoutExpired, OSError) as e:
        return "Could not unmount the card (%s). Scanning anyway; avoid opening it in Finder." % e
    if r.returncode == 0:
        return "The card was unmounted so macOS can't write to it. Unplug and re-insert it to use it again."
    return "Could not unmount the card (%s). Scanning anyway; avoid opening it in Finder." % (
        (r.stderr or r.stdout).strip() or "unknown error")


def start_scan(path, unmount=False):
    path = os.path.realpath(path)
    if not os.path.exists(path):
        raise ValueError("Not found: %s. Is the card still plugged in?" % path)
    if os.path.isdir(path):
        raise ValueError("Pick a drive (or a disk image file), not a folder.")
    with STATE_LOCK:
        old = STATE["scanner"]
        if old and not old.done:
            raise ValueError("A scan is already running.")
        rec = STATE["recover"]
        if rec and not rec["done"]:
            raise ValueError("Wait for the current save to finish.")
        note = unmount_device(path) if unmount else None
        try:
            size, sector = source_geometry(path)
            src = carver.Source(path, size, sector)
        except PermissionError:
            raise ValueError("Permission denied reading %s. Open the app again and enter your "
                             "Mac password when asked." % path)
        except OSError as e:
            raise ValueError("Cannot open %s: %s. If it's a card reader, check the card is "
                             "inserted." % (path, e.strerror or e))
        if size <= 0:
            src.close()
            raise ValueError("The drive reports zero size. Is the card inserted properly?")
        if STATE["source"]:
            STATE["source"].close()
        sc = carver.Scanner(src)
        sc.note = note
        sc.started = time.time()
        STATE.update(scanner=sc, source=src, label=path, recover=None, gen=STATE["gen"] + 1)
    threading.Thread(target=sc.run, daemon=True).start()


def _item_json(f):
    return {
        "id": f["id"], "length": f["length"], "width": f["width"], "height": f["height"],
        "orientation": f["orientation"], "has_thumb": f["thumb_rel"] is not None,
        "name": f["name"], "folder": f["folder"], "status": f["status"],
        "date": f["exif_date"], "pieces": len(f["extents"]),
    }


def status(since):
    sc = STATE["scanner"]
    rec = STATE["recover"]
    out = {"state": "idle", "recover": dict(rec) if rec else None}
    if sc:
        done = sc.done  # read before the snapshot so no photo is ever missed
        elapsed = max(time.time() - sc.started, 0.001)
        items = [_item_json(f) for f in sc.snapshot(since)]
        out.update(
            state="done" if done else "scanning", phase=sc.phase,
            cancelled=sc.cancelled, error=sc.error, path=STATE["label"], gen=STATE["gen"],
            note=getattr(sc, "note", None), volumes=sc.volumes,
            bad_bytes=sc.src.bad_bytes,
            scanned=sc.scanned, total=sc.src.size, speed=sc.scanned / elapsed,
            elapsed=elapsed, count=since + len(items), items=items,
        )
    return out


def get_item(i, sc=None):
    sc = sc or STATE["scanner"]
    if not sc or i < 0 or i >= len(sc.found):
        return None
    return sc.found[i]


# ---------------------------------------------------------------- recovery
def choose_folder():
    script = ('POSIX path of (choose folder with prompt '
              '"Choose where to save the recovered photos")')
    try:
        r = subprocess.run(as_user(["osascript", "-e", script]),
                           capture_output=True, text=True, timeout=600)
    except (subprocess.TimeoutExpired, OSError):
        return None
    if r.returncode != 0:
        return None
    return r.stdout.strip() or None


def _unique(dest, name):
    base, ext = os.path.splitext(name)
    cand, n = os.path.join(dest, name), 1
    while os.path.exists(cand) or os.path.exists(cand + ".part"):
        cand = os.path.join(dest, "%s_%d%s" % (base, n, ext))
        n += 1
    return cand


def _file_name(it):
    if it["name"]:
        name = it["name"]
        if not name.lower().endswith(carver.fsmeta.JPEG_EXT):
            name += ".jpg"
        return name
    if it["exif_date"]:
        return "Photo %s.jpg" % it["exif_date"].replace(":", "-", 2).replace(":", ".")
    return "recovered_%05d.jpg" % (it["id"] + 1)


def _makedirs_as_user(path, uid, gid):
    """Create missing folders one level at a time, each owned by the user."""
    missing = []
    p = path
    while not os.path.exists(p):
        missing.append(p)
        parent = os.path.dirname(p)
        if parent == p:
            break
        p = parent
    if not os.path.isdir(p):
        raise ValueError("%s is not a folder." % p)
    for d in reversed(missing):
        os.mkdir(d, 0o755)
        _chown(d, uid, gid)


def _volumes_of(path):
    """Mount points of the partitions on the source device (empty for image files)."""
    if not path.startswith("/dev/"):
        return []
    m = re.match(r"r?(disk\d+)", os.path.basename(path))
    if not m:
        return []
    lst = _diskutil_plist("list", m.group(1))
    mounts = []
    for entry in lst.get("AllDisksAndPartitions", []):
        for p in [entry] + entry.get("Partitions", []):
            mp = p.get("MountPoint")
            if mp:
                mounts.append(os.path.realpath(mp))
    return mounts


def start_recover(ids, dest):
    if not dest or not dest.strip():
        raise ValueError("Choose a destination folder.")
    uid, gid, home = real_user()
    dest = dest.strip()
    if dest.startswith("~"):
        dest = home + dest[1:]
    dest = os.path.realpath(os.path.abspath(dest))
    with STATE_LOCK:
        sc, src, label = STATE["scanner"], STATE["source"], STATE["label"]
        if not sc:
            raise ValueError("Scan a drive first.")
        rec = STATE["recover"]
        if rec and not rec["done"]:
            raise ValueError("A save is already in progress.")
        if dest == os.path.realpath(label) or dest.startswith(os.path.realpath(label) + "/"):
            raise ValueError("Choose a folder that is not on the drive being recovered.")
        for vol in _volumes_of(label):
            if dest == vol or dest.startswith(vol.rstrip("/") + "/"):
                raise ValueError("Don't save onto the card you're recovering from: it can overwrite "
                                 "photos that aren't recovered yet. Pick a folder on your Mac.")
        try:
            items = [get_item(int(i), sc) for i in ids]
        except (TypeError, ValueError):
            raise ValueError("Invalid selection.")
        items = [it for it in items if it]
        if not items:
            raise ValueError("Select at least one photo.")
        rec = {"done": False, "total": len(items), "saved": 0, "failed": 0, "damaged": 0,
               "dest": dest, "error": None}
        STATE["recover"] = rec
    threading.Thread(target=_recover_worker, args=(rec, src, items, dest, uid, gid),
                     daemon=True).start()


def _chown(path, uid, gid):
    if os.geteuid() == 0:
        try:
            os.chown(path, uid, gid)
        except OSError:
            pass


def _recover_worker(rec, src, items, dest, uid, gid):
    try:
        _makedirs_as_user(dest, uid, gid)
        for it in items:
            path = tmp = None
            try:
                stats = {}
                data = carver.read_item(src, it, stats=stats)
                path = _unique(dest, _file_name(it))
                tmp = path + ".part"
                fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
                with os.fdopen(fd, "wb") as f:
                    f.write(data)
                    f.flush()
                    os.fsync(f.fileno())
                t = it["mtime"] or carver.exif_time(it["exif_date"])
                if t:
                    os.utime(tmp, (t, t))
                _chown(tmp, uid, gid)
                os.rename(tmp, path)
                tmp = None
                rec["saved"] += 1
                if stats.get("bad"):
                    rec["damaged"] += 1
            except (OSError, ValueError) as e:
                rec["failed"] += 1
                rec["error"] = str(e)
                if isinstance(e, carver.DeviceGone):
                    rec["error"] = "The card was disconnected. Plug it in and scan again."
                    rec["failed"] = rec["total"] - rec["saved"]
                    break
            finally:
                if tmp and os.path.exists(tmp):
                    try:
                        os.unlink(tmp)  # never leave a half-written photo behind
                    except OSError:
                        pass
    except (OSError, ValueError) as e:
        rec["error"] = "Cannot write to %s: %s" % (dest, getattr(e, "strerror", None) or e)
        rec["failed"] = rec["total"] - rec["saved"]
    finally:
        rec["done"] = True


# ---------------------------------------------------------------- HTTP
class Handler(BaseHTTPRequestHandler):
    server_version = "JPEGRecovery"

    def log_message(self, *a):
        pass

    def _host_ok(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        return host in ("127.0.0.1", "localhost")

    def _authed(self, qs):
        t = self.headers.get("X-Token") or (qs.get("t") or [""])[0]
        return secrets.compare_digest(t.encode("utf-8", "replace"), TOKEN.encode())

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body).encode()
        elif isinstance(body, str):
            body = body.encode()
        try:
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/ping" and self._host_ok():
            return self._send(200, "ok", "text/plain")
        qs = parse_qs(u.query)
        if not self._host_ok() or not self._authed(qs):
            return self._send(403, "Forbidden. Open JPEG Recovery again to get a fresh link.",
                              "text/plain")
        STATE["last_seen"] = time.time()
        try:
            if u.path == "/":
                with open(os.path.join(HERE, "ui.html"), "rb") as f:
                    html = f.read().replace(b"__TOKEN__", TOKEN.encode())
                return self._send(200, html, "text/html; charset=utf-8",
                                  {"Cache-Control": "no-store"})
            if u.path == "/api/devices":
                return self._send(200, {"devices": list_devices(), "root": os.geteuid() == 0})
            if u.path == "/api/status":
                return self._send(200, status(int((qs.get("since") or ["0"])[0])))
            if u.path.startswith("/img/") or u.path.startswith("/thumb/"):
                kind, _, num = u.path[1:].partition("/")
                sc = STATE["scanner"]
                it = get_item(int(num), sc)
                if not it:
                    return self._send(404, {"error": "not found"})
                src = sc.src
                if kind == "thumb" and it["thumb_rel"] is not None:
                    data = carver.read_item(src, it, it["thumb_rel"], it["thumb_len"])
                else:
                    data = carver.read_item(src, it)
                return self._send(200, data, "image/jpeg", {"Cache-Control": "private, max-age=86400"})
            return self._send(404, {"error": "not found"})
        except Exception as e:  # always answer, never drop the connection
            return self._send(500, {"error": str(e)})

    def do_POST(self):
        u = urlparse(self.path)
        if not self._host_ok() or not self._authed({}):
            return self._send(403, {"error": "forbidden"})
        STATE["last_seen"] = time.time()
        try:
            n = int(self.headers.get("Content-Length") or 0)
            body = json.loads(self.rfile.read(n) or b"{}")
            if u.path == "/api/ping":
                return self._send(200, {"ok": True})
            if u.path == "/api/scan":
                start_scan(str(body.get("path", "")), bool(body.get("unmount")))
                return self._send(200, {"ok": True})
            if u.path == "/api/cancel":
                sc = STATE["scanner"]
                if sc:
                    sc.cancel()
                return self._send(200, {"ok": True})
            if u.path == "/api/choose-folder":
                return self._send(200, {"path": choose_folder()})
            if u.path == "/api/default-folder":
                home = real_user()[2]
                return self._send(200, {"path": os.path.join(
                    home, "Desktop", time.strftime("Recovered Photos %Y-%m-%d %H.%M"))})
            if u.path == "/api/recover":
                start_recover(body.get("ids") or [], str(body.get("dest") or ""))
                return self._send(200, {"ok": True})
            if u.path == "/api/reveal":
                rec = STATE["recover"]
                if rec and os.path.isdir(rec["dest"]):
                    subprocess.run(as_user(["open", rec["dest"]]), timeout=20)
                return self._send(200, {"ok": True})
            if u.path == "/api/quit":
                self._send(200, {"ok": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()
                return
            return self._send(404, {"error": "not found"})
        except (ValueError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired) as e:
            return self._send(400, {"error": str(e)})
        except Exception as e:
            return self._send(500, {"error": "%s: %s" % (type(e).__name__, e)})


def _busy():
    sc, rec = STATE["scanner"], STATE["recover"]
    return (sc is not None and not sc.done) or (rec is not None and not rec["done"])


def _idle_watchdog(server):
    while True:
        time.sleep(30)
        if not _busy() and time.time() - STATE["last_seen"] > IDLE_EXIT:
            server.shutdown()
            return


class Server(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 256  # browsers load many thumbnails at once


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _daemonize():
    """Detach from the launcher (used by the .app; replaces nohup)."""
    if os.fork() > 0:
        os._exit(0)
    os.setsid()
    if os.fork() > 0:
        os._exit(0)
    devnull = os.open(os.devnull, os.O_RDWR)
    os.dup2(devnull, 0)
    os.close(devnull)


def main():
    if os.environ.get("JPEG_RECOVERY_DAEMON"):
        _daemonize()
    if sys.platform != "darwin":
        print("This tool is for macOS.")
    port = int(os.environ.get("JPEG_RECOVERY_PORT") or free_port())
    server = Server(("127.0.0.1", port), Handler)
    url = "http://127.0.0.1:%d/?t=%s" % (port, TOKEN)
    print("\n  JPEG Recovery is running.\n  Open: %s\n  Press Ctrl+C here to quit.\n" % url, flush=True)
    threading.Thread(target=_idle_watchdog, args=(server,), daemon=True).start()
    if not os.environ.get("JPEG_RECOVERY_NO_BROWSER"):
        if os.geteuid() == 0:
            subprocess.Popen(as_user(["open", url]))
        else:
            webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
        if STATE["source"]:
            STATE["source"].close()
        print("  Stopped.", flush=True)


if __name__ == "__main__":
    main()
