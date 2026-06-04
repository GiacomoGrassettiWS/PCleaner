# -*- coding: utf-8 -*-
"""
PCleaner - Disk space analyzer for Windows
------------------------------------------
Scans a drive and shows the largest files and folders, marking which are
safe to delete, which to review and which to keep, together with the
program associated with each file.

Run:      python pcleaner.py
Requires: Python 3.8+ with Tkinter (both bundled with Windows installers).
"""

import os
import sys
import heapq
import threading
import subprocess
import ctypes
from ctypes import wintypes

import tkinter as tk
from tkinter import ttk, messagebox

try:
    import winreg
except ImportError:
    winreg = None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def resource_path(name):
    """Path to a bundled resource, working both from source and frozen exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


def human_size(num):
    """Convert a number of bytes into a readable string (KB, MB, GB...)."""
    for unit in ("B", "KB", "MB", "GB", "TB", "PB"):
        if abs(num) < 1024.0:
            return f"{num:.1f} {unit}" if unit != "B" else f"{int(num)} B"
        num /= 1024.0
    return f"{num:.1f} EB"


# ---------------------------------------------------------------------------
# Program associated with a file extension (read from the Windows registry)
# ---------------------------------------------------------------------------

_prog_cache = {}


def get_associated_program(ext):
    """Return the name of the program associated with a file extension."""
    ext = ext.lower()
    if not ext:
        return ""
    if ext in _prog_cache:
        return _prog_cache[ext]
    if winreg is None:
        _prog_cache[ext] = ""
        return ""

    result = ""
    try:
        progid = None
        # 1) Explicit user choice
        try:
            key_path = (r"Software\Microsoft\Windows\CurrentVersion"
                        r"\Explorer\FileExts" + "\\" + ext + r"\UserChoice")
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as k:
                progid, _ = winreg.QueryValueEx(k, "ProgId")
        except OSError:
            progid = None

        # 2) Default association in HKEY_CLASSES_ROOT
        if not progid:
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, ext) as k:
                    progid, _ = winreg.QueryValueEx(k, "")
            except OSError:
                progid = None

        if progid:
            # Friendly name of the file type
            friendly = ""
            try:
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, progid) as k:
                    friendly, _ = winreg.QueryValueEx(k, "")
            except OSError:
                friendly = ""
            # Open command -> executable
            exe = ""
            try:
                cmd_path = progid + r"\shell\open\command"
                with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, cmd_path) as k:
                    cmd, _ = winreg.QueryValueEx(k, "")
                exe = _exe_from_command(cmd)
            except OSError:
                exe = ""
            if exe and friendly:
                result = f"{exe} ({friendly})"
            elif exe:
                result = exe
            elif friendly:
                result = friendly
    except Exception:
        result = ""

    _prog_cache[ext] = result
    return result


def _exe_from_command(cmd):
    """Extract the executable name from a registry open-command string."""
    if not cmd:
        return ""
    cmd = cmd.strip()
    if cmd.startswith('"'):
        end = cmd.find('"', 1)
        exe = cmd[1:end] if end != -1 else cmd.strip('"')
    else:
        exe = cmd.split(" ")[0]
    return os.path.basename(exe)


# ---------------------------------------------------------------------------
# Classification: safe / review / keep
# ---------------------------------------------------------------------------

SAFE = ("safe", "🟢 Safe to delete")
CHECK = ("check", "🟡 Review")
KEEP = ("keep", "🔴 Keep")

# System folders to never touch (lowercase, as path segments)
_KEEP_DIRS = (
    "\\windows\\", "\\program files\\", "\\program files (x86)\\",
    "\\system volume information\\", "\\$windows.~",
    "\\programdata\\microsoft\\", "\\drivers\\",
)

# System files managed by Windows
_KEEP_FILES = ("pagefile.sys", "hiberfil.sys", "swapfile.sys", "ntuser.dat")

# Sensitive system extensions
_KEEP_EXT = (".sys", ".dll", ".drv", ".ocx", ".cpl", ".efi")

# Markers of deletable temporary / cache files
_SAFE_MARKERS = (
    "\\temp\\", "\\tmp\\", "\\appdata\\local\\temp\\",
    "\\windows\\temp\\", "\\inetcache\\", "\\cache\\", "\\cache2\\",
    "\\code cache\\", "\\gpucache\\", "\\thumbnails\\",
    "\\crashdumps\\", "\\windows\\softwaredistribution\\download\\",
    "\\$recycle.bin\\", "\\temporary internet files\\",
)
_SAFE_EXT = (".tmp", ".temp", ".log", ".dmp", ".old", ".bak", ".chk", ".cache")

# Personal folders: large files that may still be important
_PERSONAL_MARKERS = (
    "\\downloads\\", "\\documents\\", "\\desktop\\", "\\pictures\\",
    "\\videos\\", "\\music\\", "\\onedrive\\", "\\dropbox\\",
)


def classify(path_lower, name_lower, ext):
    """Return (code, label, reason) for a path."""
    # Specific system files
    if name_lower in _KEEP_FILES:
        return KEEP[0], KEEP[1], "Windows system file: manage it from settings, don't delete it by hand."

    # System folders
    for d in _KEEP_DIRS:
        if d in path_lower:
            return KEEP[0], KEEP[1], "Inside a system/programs folder: deleting may break Windows or an app."

    # Cache / temporary (check before system extensions)
    for m in _SAFE_MARKERS:
        if m in path_lower:
            return SAFE[0], SAFE[1], "Temporary or cache file: safe to delete, it will be recreated if needed."
    if ext in _SAFE_EXT:
        return SAFE[0], SAFE[1], "Temporary/log/backup file: usually safe to delete."

    # Sensitive system extensions (outside system folders)
    if ext in _KEEP_EXT:
        return KEEP[0], KEEP[1], "System library/component: better not to delete it."

    # Downloaded installers
    if ext in (".msi", ".exe") and "\\downloads\\" in path_lower:
        return SAFE[0], SAFE[1], "Downloaded installer: usually not needed after installation."

    # Personal folders
    for m in _PERSONAL_MARKERS:
        if m in path_lower:
            return CHECK[0], CHECK[1], "Personal file (documents/media): large but you may want to keep it."

    return CHECK[0], CHECK[1], "Unclear origin: check what it is before deleting."


# ---------------------------------------------------------------------------
# Disk scan (in a background thread)
# ---------------------------------------------------------------------------

class Scanner:
    def __init__(self):
        self.cancel = False
        self.files_count = 0
        self.total_bytes = 0
        self.current_dir = ""

    def scan(self, root, min_size, top_n):
        """Scan recursively and return (top_files, top_folders, breakdown)."""
        self.cancel = False
        self.files_count = 0
        self.total_bytes = 0

        file_heap = []            # heap of the largest files (size, path)
        dir_own = {}              # bytes of files directly inside a folder
        dir_parent = {}          # map folder -> parent folder

        stack = [root]
        while stack:
            if self.cancel:
                break
            d = stack.pop()
            self.current_dir = d
            own = 0
            try:
                with os.scandir(d) as it:
                    for entry in it:
                        if self.cancel:
                            break
                        try:
                            if entry.is_symlink():
                                continue
                            if entry.is_dir(follow_symlinks=False):
                                dir_parent[entry.path] = d
                                stack.append(entry.path)
                            elif entry.is_file(follow_symlinks=False):
                                size = entry.stat(follow_symlinks=False).st_size
                                own += size
                                self.files_count += 1
                                self.total_bytes += size
                                if size >= min_size:
                                    if len(file_heap) < top_n:
                                        heapq.heappush(file_heap, (size, entry.path))
                                    elif size > file_heap[0][0]:
                                        heapq.heapreplace(file_heap, (size, entry.path))
                        except (OSError, ValueError):
                            continue
            except (OSError, ValueError):
                continue
            dir_own[d] = own

        # Recursive sum of folder sizes (from the deepest folders up)
        dir_total = dict(dir_own)
        for d in sorted(dir_total.keys(), key=lambda p: p.count(os.sep), reverse=True):
            parent = dir_parent.get(d)
            if parent is not None:
                dir_total[parent] = dir_total.get(parent, 0) + dir_total[d]

        top_files = sorted(file_heap, key=lambda x: x[0], reverse=True)
        top_folders = heapq.nlargest(top_n, dir_total.items(), key=lambda x: x[1])

        # NON-overlapping breakdown: direct subfolders of root + files directly
        # inside root. Used for the pie chart.
        root_norm = root.rstrip("\\")
        breakdown = []
        for d, parent in dir_parent.items():
            if parent.rstrip("\\") == root_norm:
                breakdown.append((os.path.basename(d.rstrip("\\")) or d,
                                  dir_total.get(d, 0)))
        loose = dir_own.get(root, dir_own.get(root_norm + "\\", 0))
        if loose:
            breakdown.append(("(files in this folder)", loose))
        breakdown.sort(key=lambda x: x[1], reverse=True)

        return top_files, top_folders, breakdown


# ---------------------------------------------------------------------------
# Delete to the Recycle Bin (recoverable)
# ---------------------------------------------------------------------------

def send_to_recycle_bin(path):
    """Move a file/folder to the Windows Recycle Bin. Return True on success."""
    class SHFILEOPSTRUCTW(ctypes.Structure):
        _fields_ = [
            ("hwnd", wintypes.HWND),
            ("wFunc", wintypes.UINT),
            ("pFrom", wintypes.LPCWSTR),
            ("pTo", wintypes.LPCWSTR),
            ("fFlags", ctypes.c_ushort),
            ("fAnyOperationsAborted", wintypes.BOOL),
            ("hNameMappings", ctypes.c_void_p),
            ("lpszProgressTitle", wintypes.LPCWSTR),
        ]

    FO_DELETE = 3
    FOF_ALLOWUNDO = 0x0040
    FOF_NOCONFIRMATION = 0x0010
    FOF_SILENT = 0x0004

    op = SHFILEOPSTRUCTW()
    op.hwnd = None
    op.wFunc = FO_DELETE
    op.pFrom = path + "\0\0"
    op.pTo = None
    op.fFlags = FOF_ALLOWUNDO | FOF_NOCONFIRMATION | FOF_SILENT
    res = ctypes.windll.shell32.SHFileOperationW(ctypes.byref(op))
    return res == 0


def run_elevated(exe, params=""):
    """Launch a command with administrator privileges (UAC). True if started."""
    try:
        r = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe, params, None, 1)
        return int(r) > 32
    except Exception:
        return False


def shell_open(target, params=None):
    """Open a file/exe/URI via ShellExecute, handling UAC elevation if needed.

    Use this instead of subprocess.Popen for executables that require
    elevation: CreateProcess would fail with WinError 740, while
    ShellExecute correctly raises the UAC prompt.
    """
    for verb in ("open", "runas"):
        try:
            r = ctypes.windll.shell32.ShellExecuteW(None, verb, target, params, None, 1)
            if int(r) > 32:
                return True
        except Exception:
            continue
    return False


def system_file_size(drive, name):
    """Size (bytes) of a system file at the drive root, or None."""
    path = os.path.join(drive.rstrip("\\") + "\\", name)
    try:
        return os.stat(path).st_size
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Graphical interface
# ---------------------------------------------------------------------------

class App(tk.Tk):
    TAG_COLORS = {
        "safe": "#1a7f37",
        "check": "#9a6700",
        "keep": "#b42318",
    }

    def __init__(self):
        super().__init__()
        self.title("PCleaner - Disk space analyzer")
        self.geometry("1150x680")
        self.minsize(900, 500)
        try:
            self.iconbitmap(resource_path("icon.ico"))
        except Exception:
            pass

        self.scanner = Scanner()
        self.scan_thread = None
        self.file_rows = {}     # iid -> path
        self.folder_rows = {}   # iid -> path

        self._build_ui()

    # -- UI construction ---------------------------------------------------
    def _build_ui(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

        # Top control bar
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text="Drive/folder:").pack(side="left")
        self.path_var = tk.StringVar(value="C:\\")
        ttk.Entry(top, textvariable=self.path_var, width=22).pack(side="left", padx=(4, 4))
        ttk.Button(top, text="Browse...", command=self._browse).pack(side="left", padx=(0, 12))

        ttk.Label(top, text="Show files of at least:").pack(side="left")
        self.minsize_var = tk.StringVar(value="50 MB")
        ttk.Combobox(
            top, textvariable=self.minsize_var, width=8, state="readonly",
            values=("1 MB", "10 MB", "50 MB", "100 MB", "500 MB", "1 GB"),
        ).pack(side="left", padx=(4, 12))

        self.scan_btn = ttk.Button(top, text="▶  Scan", command=self._start_scan)
        self.scan_btn.pack(side="left")
        self.cancel_btn = ttk.Button(top, text="Cancel", command=self._cancel_scan, state="disabled")
        self.cancel_btn.pack(side="left", padx=(6, 0))

        self.export_btn = ttk.Button(top, text="⤓  Export CSV", command=self._export_csv, state="disabled")
        self.export_btn.pack(side="right")
        ttk.Button(top, text="🛠  System tools", command=self._open_system_tools).pack(side="right", padx=(0, 8))

        # Progress bar + status
        prog = ttk.Frame(self, padding=(10, 0))
        prog.pack(fill="x")
        self.progress = ttk.Progressbar(prog, mode="indeterminate")
        self.progress.pack(fill="x", side="left", expand=True)
        self.status_var = tk.StringVar(value="Ready. Choose a drive and press Scan.")
        ttk.Label(prog, textvariable=self.status_var, width=46, anchor="e").pack(side="right", padx=(10, 0))

        # Tabs: files / folders / chart
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)
        self.nb = nb

        self.file_tree = self._make_file_tree(nb)
        self.folder_tree = self._make_folder_tree(nb)
        self.pie_frame = self._make_pie_tab(nb)
        nb.add(self.file_tree.master, text="  Largest files  ")
        nb.add(self.folder_tree.master, text="  Largest folders  ")
        nb.add(self.pie_frame, text="  Space chart  ")

        # Legend at the bottom
        legend = ttk.Frame(self, padding=(10, 0, 10, 10))
        legend.pack(fill="x")
        for code, text in (
            ("safe", "🟢 Safe to delete (temp/cache/installers)"),
            ("check", "🟡 Review (personal files)"),
            ("keep", "🔴 Keep (system/programs)"),
        ):
            lbl = tk.Label(legend, text=text, fg=self.TAG_COLORS[code], font=("Segoe UI", 9, "bold"))
            lbl.pack(side="left", padx=(0, 18))
        ttk.Label(legend, text="Right-click a row for actions.").pack(side="right")

    def _make_file_tree(self, parent):
        frame = ttk.Frame(parent)
        cols = ("size", "category", "program", "path", "reason")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        tree.heading("size", text="Size")
        tree.heading("category", text="Category")
        tree.heading("program", text="Associated program")
        tree.heading("path", text="Path")
        tree.heading("reason", text="Why")
        tree.column("size", width=100, anchor="e", stretch=False)
        tree.column("category", width=130, anchor="w", stretch=False)
        tree.column("program", width=190, anchor="w", stretch=False)
        tree.column("path", width=360, anchor="w")
        tree.column("reason", width=300, anchor="w")
        self._add_scroll_and_menu(frame, tree, self.file_rows)
        return tree

    def _make_folder_tree(self, parent):
        frame = ttk.Frame(parent)
        cols = ("size", "category", "path", "reason")
        tree = ttk.Treeview(frame, columns=cols, show="headings", selectmode="extended")
        tree.heading("size", text="Size")
        tree.heading("category", text="Category")
        tree.heading("path", text="Folder")
        tree.heading("reason", text="Why")
        tree.column("size", width=100, anchor="e", stretch=False)
        tree.column("category", width=130, anchor="w", stretch=False)
        tree.column("path", width=480, anchor="w")
        tree.column("reason", width=340, anchor="w")
        self._add_scroll_and_menu(frame, tree, self.folder_rows)
        return tree

    def _add_scroll_and_menu(self, frame, tree, rowmap):
        vsb = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")
        tree.pack(side="left", fill="both", expand=True)
        for code, color in self.TAG_COLORS.items():
            tree.tag_configure(code, foreground=color)

        menu = tk.Menu(tree, tearoff=0)
        menu.add_command(label="Open location in File Explorer",
                         command=lambda: self._open_location(tree, rowmap))
        menu.add_command(label="Copy path",
                         command=lambda: self._copy_path(tree, rowmap))
        menu.add_separator()
        menu.add_command(label="Delete (move to Recycle Bin)",
                         command=lambda: self._delete_selected(tree, rowmap))

        def popup(event):
            iid = tree.identify_row(event.y)
            if iid:
                if iid not in tree.selection():
                    tree.selection_set(iid)
                menu.tk_popup(event.x_root, event.y_root)

        tree.bind("<Button-3>", popup)
        tree.bind("<Double-1>", lambda e: self._open_location(tree, rowmap))

    # -- pie chart ---------------------------------------------------------
    PIE_COLORS = (
        "#4e79a7", "#f28e2b", "#e15759", "#76b7b2", "#59a14f",
        "#edc948", "#b07aa1", "#ff9da7", "#9c755f", "#bab0ac",
    )

    def _make_pie_tab(self, parent):
        frame = ttk.Frame(parent)
        self.pie_canvas = tk.Canvas(frame, bg="white", highlightthickness=0)
        self.pie_canvas.pack(fill="both", expand=True)
        self.pie_canvas.bind("<Configure>", lambda e: self._draw_pie())
        return frame

    def _draw_pie(self, breakdown=None):
        if breakdown is not None:
            self._breakdown = breakdown
        breakdown = getattr(self, "_breakdown", None)
        c = self.pie_canvas
        c.delete("all")
        w = c.winfo_width() or 800
        h = c.winfo_height() or 500
        if not breakdown:
            c.create_text(w // 2, h // 2, text="Run a scan to see the chart.",
                          fill="#666", font=("Segoe UI", 11))
            return

        total = sum(s for _, s in breakdown) or 1
        # Group small entries under "Other"
        top = breakdown[:9]
        rest = sum(s for _, s in breakdown[9:])
        items = list(top)
        if rest > 0:
            items.append(("Other", rest))

        # Pie on the left
        d = min(h - 60, w * 0.55 - 60)
        d = max(d, 80)
        x0, y0 = 30, (h - d) / 2
        x1, y1 = x0 + d, y0 + d
        start = 90.0
        for i, (name, size) in enumerate(items):
            extent = -360.0 * size / total
            color = self.PIE_COLORS[i % len(self.PIE_COLORS)]
            c.create_arc(x0, y0, x1, y1, start=start, extent=extent,
                         fill=color, outline="white", width=2)
            start += extent

        # Legend on the right
        lx = x1 + 40
        ly = y0 + 6
        c.create_text(lx, ly, anchor="nw", text="Space breakdown",
                      font=("Segoe UI", 11, "bold"))
        ly += 28
        for i, (name, size) in enumerate(items):
            color = self.PIE_COLORS[i % len(self.PIE_COLORS)]
            pct = 100.0 * size / total
            c.create_rectangle(lx, ly, lx + 14, ly + 14, fill=color, outline="")
            label = name if len(name) <= 38 else name[:35] + "..."
            c.create_text(lx + 22, ly + 7, anchor="w",
                          text=f"{label}  -  {human_size(size)}  ({pct:.1f}%)",
                          font=("Segoe UI", 9))
            ly += 22

    # -- CSV export --------------------------------------------------------
    def _export_csv(self):
        import csv
        from tkinter import filedialog
        tab = self.nb.index(self.nb.select())
        if tab == 0:
            tree, headers = self.file_tree, ("Size", "Category", "Program", "Path", "Why")
            default = "largest_files.csv"
        elif tab == 1:
            tree, headers = self.folder_tree, ("Size", "Category", "Folder", "Why")
            default = "largest_folders.csv"
        else:
            messagebox.showinfo("Export CSV",
                                "Select the 'Files' or 'Folders' tab to export data.")
            return

        rows = tree.get_children()
        if not rows:
            messagebox.showinfo("Export CSV", "Nothing to export. Run a scan first.")
            return

        path = filedialog.asksaveasfilename(
            title="Save CSV", defaultextension=".csv",
            initialfile=default, filetypes=[("CSV file", "*.csv")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f, delimiter=";")
                writer.writerow(headers)
                for iid in rows:
                    writer.writerow(tree.item(iid, "values"))
            self.status_var.set(f"Exported: {os.path.basename(path)}")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    # -- system tools ------------------------------------------------------
    def _open_system_tools(self):
        drive = (self.path_var.get().strip()[:2] or "C:")
        if len(drive) < 2 or drive[1] != ":":
            drive = "C:"

        win = tk.Toplevel(self)
        win.title("System tools - large Windows files")
        win.geometry("640x560")
        win.transient(self)
        win.grab_set()

        pad = ttk.Frame(win, padding=16)
        pad.pack(fill="both", expand=True)

        ttk.Label(pad, text="System files on " + drive,
                  font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(pad, wraplength=600, foreground="#444",
                  text=("These files often take several GB but must NOT be "
                        "deleted by hand: manage them with the official Windows "
                        "tools below (some require administrator "
                        "privileges).")).pack(anchor="w", pady=(2, 12))

        # Summary of detected sizes
        info = ttk.Frame(pad)
        info.pack(fill="x", pady=(0, 12))
        for fname, desc in (("hiberfil.sys", "hibernation"),
                            ("pagefile.sys", "virtual memory"),
                            ("swapfile.sys", "modern apps")):
            size = system_file_size(drive, fname)
            txt = (f"{fname}  ({desc}):  "
                   + (human_size(size) if size is not None else "not present / not accessible"))
            ttk.Label(info, text="•  " + txt, font=("Segoe UI", 9)).pack(anchor="w")

        ttk.Separator(pad).pack(fill="x", pady=8)

        def card(title, desc, btn_text, cmd):
            f = ttk.Frame(pad)
            f.pack(fill="x", pady=6)
            ttk.Label(f, text=title, font=("Segoe UI", 10, "bold")).pack(anchor="w")
            ttk.Label(f, text=desc, wraplength=600, foreground="#555",
                      font=("Segoe UI", 9)).pack(anchor="w", pady=(0, 4))
            ttk.Button(f, text=btn_text, command=cmd).pack(anchor="w")

        card("Disable hibernation (removes hiberfil.sys)",
             "Removes hiberfil.sys (often several GB) and disables hibernation "
             "and fast startup. Reversible with 'powercfg /h on'. Requires admin.",
             "Disable hibernation",
             lambda: self._disable_hibernation())

        card("Virtual memory (pagefile.sys)",
             "Opens Performance Options > Advanced tab, where you'll find the "
             "'Change...' button for virtual memory. Don't disable it entirely.",
             "Open virtual memory settings",
             lambda: self._open_virtual_memory())

        windir = os.environ.get("WINDIR", r"C:\Windows")
        cleanmgr = os.path.join(windir, "System32", "cleanmgr.exe")
        card("Windows Disk Cleanup",
             "Official tool to remove temporary files, old updates, the recycle "
             "bin and other recoverable system files.",
             "Open Disk Cleanup",
             lambda: self._launch(cleanmgr, "/d " + drive, "Disk Cleanup"))

        card("Storage sense / Storage settings",
             "Windows settings for automatic disk cleanup and disk usage "
             "analysis.",
             "Open Storage settings",
             lambda: self._launch("ms-settings:storagesense", None, "Storage settings"))

        ttk.Button(pad, text="Close", command=win.destroy).pack(side="bottom", pady=(12, 0))

    def _launch(self, target, params=None, label=""):
        """Start a target via ShellExecute, showing a warning if it fails."""
        if shell_open(target, params):
            self.status_var.set(f"Opening {label}..." if label else "Opening...")
            return True
        messagebox.showwarning(
            "Could not open",
            f"Could not open {label or 'the tool'} automatically.\n"
            "Try again or start the app as administrator.")
        return False

    def _open_virtual_memory(self):
        """Open the performance panel (Advanced tab -> virtual memory).

        These panels require elevation: they must be opened with ShellExecute
        (which handles the UAC prompt), not with subprocess/CreateProcess.
        """
        windir = os.environ.get("WINDIR", r"C:\Windows")
        for exe in ("SystemPropertiesPerformance.exe", "SystemPropertiesAdvanced.exe"):
            full = os.path.join(windir, "System32", exe)
            if os.path.exists(full) and shell_open(full):
                self.status_var.set("Opening virtual memory settings...")
                return
        messagebox.showwarning(
            "Could not open",
            "Could not open the panel automatically.\n\n"
            "Open it manually like this:\n"
            "1. Press Win + R\n"
            "2. Type:  SystemPropertiesPerformance\n"
            "3. Enter, then 'Advanced' tab > 'Change...' (Virtual memory)")

    def _disable_hibernation(self):
        if not messagebox.askyesno(
                "Disable hibernation",
                "hiberfil.sys will be removed and hibernation (and fast "
                "startup) disabled.\n\nContinue? The Windows administrator "
                "prompt will appear."):
            return
        if run_elevated("powercfg.exe", "/hibernate off"):
            self.status_var.set("Hibernation command sent. hiberfil.sys will be removed.")
            messagebox.showinfo(
                "Done",
                "Command sent. If you granted permission, hiberfil.sys has been "
                "removed.\nTo re-enable later: powercfg /hibernate on")
        else:
            messagebox.showerror(
                "Operation cancelled",
                "Administrator permission was not granted or the command did not start.")

    # -- control actions ---------------------------------------------------
    def _browse(self):
        from tkinter import filedialog
        d = filedialog.askdirectory(title="Choose a drive or folder to scan")
        if d:
            self.path_var.set(d)

    def _parse_minsize(self):
        txt = self.minsize_var.get()
        num, unit = txt.split()
        mult = {"MB": 1024 ** 2, "GB": 1024 ** 3}[unit]
        return int(float(num) * mult)

    def _start_scan(self):
        root = self.path_var.get().strip()
        if not os.path.isdir(root):
            messagebox.showerror("Error", f"Invalid path:\n{root}")
            return
        min_size = self._parse_minsize()

        self.file_tree.delete(*self.file_tree.get_children())
        self.folder_tree.delete(*self.folder_tree.get_children())
        self.file_rows.clear()
        self.folder_rows.clear()

        self.scan_btn.config(state="disabled")
        self.cancel_btn.config(state="normal")
        self.progress.start(12)
        self.status_var.set("Scanning...")

        self.scan_thread = threading.Thread(
            target=self._run_scan, args=(root, min_size), daemon=True)
        self.scan_thread.start()
        self.after(200, self._poll_progress)

    def _run_scan(self, root, min_size):
        try:
            result = self.scanner.scan(root, min_size, top_n=500)
            self._result = result
            self._error = None
        except Exception as e:
            self._result = None
            self._error = str(e)

    def _poll_progress(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.status_var.set(
                f"Scanned {self.scanner.files_count:,} files "
                f"({human_size(self.scanner.total_bytes)})...")
            self.after(200, self._poll_progress)
        else:
            self._finish_scan()

    def _cancel_scan(self):
        self.scanner.cancel = True
        self.status_var.set("Cancelling...")

    def _finish_scan(self):
        self.progress.stop()
        self.scan_btn.config(state="normal")
        self.cancel_btn.config(state="disabled")

        if getattr(self, "_error", None):
            messagebox.showerror("Error during scan", self._error)
            self.status_var.set("Error.")
            return

        top_files, top_folders, breakdown = self._result
        self._populate_files(top_files)
        self._populate_folders(top_folders)
        self._draw_pie(breakdown)
        self.export_btn.config(state="normal")

        self.status_var.set(
            f"Done: {self.scanner.files_count:,} files, "
            f"{human_size(self.scanner.total_bytes)} total.")

    def _populate_files(self, top_files):
        for size, path in top_files:
            pl = path.lower()
            name = os.path.basename(path)
            ext = os.path.splitext(name)[1].lower()
            code, label, reason = classify(pl, name.lower(), ext)
            program = get_associated_program(ext) or "-"
            iid = self.file_tree.insert(
                "", "end",
                values=(human_size(size), label, program, path, reason),
                tags=(code,))
            self.file_rows[iid] = path

    def _populate_folders(self, top_folders):
        for path, size in top_folders:
            pl = (path.lower().rstrip("\\") + "\\")
            code, label, reason = classify(pl, os.path.basename(path).lower(), "")
            iid = self.folder_tree.insert(
                "", "end",
                values=(human_size(size), label, path, reason),
                tags=(code,))
            self.folder_rows[iid] = path

    # -- context menu actions ----------------------------------------------
    def _selected_paths(self, tree, rowmap):
        return [rowmap[iid] for iid in tree.selection() if iid in rowmap]

    def _open_location(self, tree, rowmap):
        paths = self._selected_paths(tree, rowmap)
        if not paths:
            return
        p = paths[0]
        try:
            if os.path.isdir(p):
                subprocess.Popen(["explorer", p])
            else:
                subprocess.Popen(["explorer", "/select,", os.path.normpath(p)])
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _copy_path(self, tree, rowmap):
        paths = self._selected_paths(tree, rowmap)
        if paths:
            self.clipboard_clear()
            self.clipboard_append("\n".join(paths))
            self.status_var.set("Path copied to clipboard.")

    def _delete_selected(self, tree, rowmap):
        sel = tree.selection()
        paths = self._selected_paths(tree, rowmap)
        if not paths:
            return
        # Warn if there are "keep" items selected
        risky = [iid for iid in sel if "keep" in tree.item(iid, "tags")]
        warn = ""
        if risky:
            warn = ("\n\nWARNING: some items are marked as "
                    "'Keep' (system/programs).")
        msg = (f"Move {len(paths)} item(s) to the Recycle Bin?{warn}\n\n"
               "You can restore them from the Recycle Bin if needed.")
        if not messagebox.askyesno("Confirm deletion", msg):
            return

        ok, fail = 0, 0
        for iid, path in zip(sel, paths):
            try:
                if send_to_recycle_bin(path):
                    tree.delete(iid)
                    rowmap.pop(iid, None)
                    ok += 1
                else:
                    fail += 1
            except Exception:
                fail += 1
        self.status_var.set(f"Moved to Recycle Bin: {ok}. Failed: {fail}.")
        if fail:
            messagebox.showwarning(
                "Partial deletion",
                f"{fail} item(s) not deleted (likely missing permissions "
                "or files in use).")


def main():
    if sys.platform != "win32":
        print("This program is designed for Windows.")
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()
