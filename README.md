# JPEG Recovery for Mac

Recover deleted or lost **.jpg photos** from a pendrive, an SD card, or an SD card in a USB
card reader. It scans the whole card, shows you previews of every photo it finds, and saves
the ones you pick to any folder on your Mac. Photos are saved **byte for byte at their original
full size and quality**: no re-compression and no downscaling.

- Recovers **deleted** photos and photos from **formatted** cards (if not yet overwritten)
- Gets back **original file names, folders and dates** when the card's file system still has them (FAT16/FAT32/exFAT)
- Rebuilds photos stored in **pieces** (fragmented) when the file system still knows where the pieces are
- Keeps going past **damaged areas** on failing cards instead of stopping
- **Read-only:** nothing is ever written to the card
- **Save while scanning:** pick the photos you like as they appear; no need to wait for the scan to finish
- Fast: reads as quickly as your card reader allows. No extra software, no Homebrew.

## Install

Open **Terminal** (press `⌘ Space`, type *Terminal*, press Enter), paste this and press Enter:

```bash
git clone https://github.com/vatsalmotiani/jpeg-recovery.git && open jpeg-recovery
```

A Finder window opens. **Double-click "JPEG Recovery"** (the app with the blue photo icon).
Drag it to your Applications folder if you like.

> **No git?** This version needs nothing extra:
> ```bash
> curl -L https://github.com/vatsalmotiani/jpeg-recovery/archive/refs/heads/main.tar.gz | tar xz && open jpeg-recovery-main
> ```

**Or run it straight from Terminal** (same app, no double-clicking):

```bash
git clone https://github.com/vatsalmotiani/jpeg-recovery.git && cd jpeg-recovery && ./run.sh
```

Next time, run `cd jpeg-recovery && ./run.sh`. Keep the Terminal window open while you use the app,
and press `Ctrl+C` there to stop it. To update to the latest version, run `cd jpeg-recovery && git pull`.

**First launch:** the app asks for your **Mac password**. It needs admin rights to read the card's
raw data; nothing is written to the card. The app then opens in your web browser.

### Requirements

- macOS 10.15 or newer (Apple Silicon or Intel)
- Python 3, which comes with Apple's free **Command Line Tools**. If they're missing, the app
  tells you and opens Apple's installer: click **Install**, wait a few minutes, then open the app
  again. You do **not** need the full Xcode app.

## How to use

1. **Plug in** the pendrive, SD card or card reader. Don't copy anything onto the card.
2. Open **JPEG Recovery** and enter your Mac password.
3. **Pick the card** in the list and click **Scan for photos**. Keep *Unmount the card before
   scanning* ticked. It stops macOS from writing to the card and overwriting deleted photos.
4. Photos appear as they are found, marked **Deleted**, **Existing** or **Deep scan** (found in
   raw data; the name is unknown). Click a photo to see it at full resolution. Use the filter to
   show only deleted photos.
5. Tick the photos you want (or **Select all**), click **Recover selected**, choose a folder **on
   your Mac** (not on the card), and click **Save**. You can do this while the scan is still running.
6. Click **Show in Finder** to see them. Click **Quit** when you're done. The app also closes itself
   after 15 minutes without use.

## How it works

It works like professional tools such as Disk Drill and PhotoRec, in two passes:

1. **File-system pass (quick).** Reads the card's partition table (MBR, GPT or none) and its
   FAT16/FAT32/exFAT folders, including deleted entries. This gives original names, folders and
   dates, the exact file size, and the location of every piece of a fragmented file.
2. **Deep scan (whole card).** Reads every sector and finds JPEGs by following their internal
   structure from start to end. This finds photos even after the file system is gone (formatted
   card, corrupted card, HFS+/APFS pendrives). Like PhotoRec, it only looks where files can start
   (sector boundaries). That skips the preview images hidden inside RAW files and avoids junk results.
   Multi-image JPEGs (Android Ultra HDR, MPO) are kept whole.

Saved files are named after the original file when it's known. Otherwise they're named after the
date the photo was taken (from its EXIF data), or `recovered_00001.jpg`. File dates are restored too.

## Good to know

- **Only JPEG (.jpg/.jpeg)** photos are recovered. RAW, HEIC, PNG and videos are ignored.
- On FAT/FAT32 cards, the **first letter** of a deleted file's name is lost by design (for example
  `_MG_0001.JPG`). exFAT cards (most cards over 32 GB) keep the full name.
- **Don't use Disk Utility's "Erase"** on a card you want to recover. On many devices it wipes
  the data for good. A camera's "format" usually doesn't, so recovery still works after one.
- A photo can't be recovered once new data has been written over it. Stop using the card as soon
  as you notice missing photos.
- If the card has damaged areas, the app warns you, skips them and keeps going. Photos touching a
  damaged area may show grey patches.

## Troubleshooting

| Problem | Fix |
|---|---|
| "JPEG Recovery can't be opened" / "Apple could not verify…" | This only happens if you downloaded a ZIP in the browser. Open **System Settings → Privacy & Security** and click **Open Anyway**. Or run `xattr -dr com.apple.quarantine "JPEG Recovery.app"`. Installing with the commands above avoids this. |
| Card not listed | Re-insert it and click **Refresh list**. Try another USB port or card reader. A card reader with no card in it isn't listed. |
| "Permission denied" | Quit, open the app again, and enter your Mac password when asked. |
| Browser didn't open | Open the app again; it reopens the page. |
| No photos found, or fewer than expected | In Terminal, run `cd jpeg-recovery && git pull && sudo python3 diagnose.py`. It takes about 30 seconds and reports what is on the card (JPEG, HEIC, encrypted, wiped) and why. Send the output when asking for help. |
| Prefer Terminal? | `./run.sh` in the project folder does the same thing. |

## Privacy and safety

Everything runs locally on your Mac. The app only listens on `127.0.0.1` (your own computer) behind
a random one-time access key, never uploads anything, and only reads from the card.

## For developers

The code lives inside the app bundle: `JPEG Recovery.app/Contents/Resources/`

| File | What it does |
|---|---|
| `fsmeta.py` | File-system pass: MBR/GPT, FAT12/16/32 and exFAT directory reading, including deleted entries |
| `carver.py` | Deep scan: JPEG structure parser, bad-sector-tolerant reader, merging with file-system results |
| `app.py` | Local web server: drive list (`diskutil`), scanning thread, previews, saving |
| `ui.html` | The interface |
| `../MacOS/launcher` | Double-click launcher: finds Python, asks for the password, starts the server, opens the browser |

Tests (Pillow is only used to create test photos):

```bash
python3 -m pip install --user pillow
python3 -m unittest discover -s tests -v
```

`tests/test_real_disks.py` builds real FAT16/FAT32/exFAT/HFS+/APFS disk images (MBR, GPT, no
partition table) with `hdiutil`. It deletes files and whole folders, simulates a quick format and
a fragmented file, and checks that every photo comes back byte-identical with the right name and date.

## License

MIT
