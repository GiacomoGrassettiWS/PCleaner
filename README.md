# Disk Cleaner

A lightweight desktop disk-space analyzer for **Windows**. It scans a drive
and shows the largest files and folders, telling you which are **safe to
delete**, which to **review**, and which to **keep** — along with the program
associated with each file.

Built with Python's standard library only (Tkinter + ctypes): **no third‑party
runtime dependencies**.

## Features

- 🔍 **Fast recursive scan** of any drive or folder, running in a background
  thread so the window never freezes.
- 📁 Three views: **Largest files**, **Largest folders**, and a **Space chart**
  (a native pie chart of the space breakdown — no matplotlib).
- 🚦 **Color-coded category** with a reason for every item:
  - 🟢 **Safe to delete** — temp files, caches, downloaded installers
  - 🟡 **Review** — personal files (documents, media, downloads)
  - 🔴 **Keep** — system and program files
- 🧩 **Associated program** for each file, read from the Windows registry.
- 🖱️ **Right-click actions**: open location in Explorer, copy path, or
  **delete to the Recycle Bin** (recoverable, with confirmation).
- 🛠️ **System tools** dialog for the big system files (`hiberfil.sys`,
  `pagefile.sys`): detects their size and opens the official Windows tools
  (disable hibernation, virtual memory settings, Disk Cleanup, Storage sense).
- ⤓ **Export to CSV** (opens cleanly in Excel).

## Requirements

- Windows 10 / 11
- Python 3.8+ with Tkinter (included in the standard python.org installer)

## Run from source

```powershell
python disk_cleaner.py
```

> Tip: to scan the whole `C:` drive without "access denied" errors, run it as
> administrator.

## Build a standalone .exe

A double-clickable executable (no Python required on the target machine) can be
built with [PyInstaller](https://pyinstaller.org/):

```powershell
pip install pyinstaller
.\build.bat
```

The resulting `DiskCleaner.exe` will be in the `dist` folder.

## Usage

1. Choose the drive/folder (default `C:\`).
2. Set the minimum file size to show (e.g. 50 MB).
3. Press **Scan**.
4. Browse the **Largest files**, **Largest folders** and **Space chart** tabs.
5. Right-click any row to open its location, copy the path, or move it to the
   Recycle Bin. Use **Export CSV** to save the table.

## How deletion works

Deleting moves items to the **Recycle Bin** via the Windows shell API, so
nothing is permanently removed and you can always restore it. The app never
deletes anything without an explicit confirmation.

## Notes & safety

- The 🟢/🟡/🔴 classification is a **heuristic guide**. When in doubt, keep the
  file (yellow/red categories).
- Large system files like `pagefile.sys` and `hiberfil.sys` are flagged 🔴 on
  purpose: don't delete them by hand — use the **System tools** dialog, which
  opens the official, reversible Windows settings.

## License

[MIT](LICENSE)
