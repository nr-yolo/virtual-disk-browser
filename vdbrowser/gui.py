"""Tkinter user interface."""

import os
import queue
import shutil
import subprocess
import sys
import tempfile
import threading
import traceback
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, font as tkfont

from . import APP_NAME, __version__
from .core import Session, extract, export_raw, entry_path, fmt_time, safe_name, ExtractStats
from .disk import fmt_size
from .fs import pytsk3

IMAGE_TYPES = [
    ("Disk images", "*.vmdk *.VMDK *.vdi *.VDI *.vhd *.VHD *.vhdx *.VHDX *.qcow2 *.qcow *.QCOW2 "
                    "*.img *.raw *.dd *.bin *.001"),
    ("VMware (VMDK)", "*.vmdk *.VMDK"),
    ("VirtualBox (VDI)", "*.vdi *.VDI"),
    ("Hyper-V / Virtual PC (VHD, VHDX)", "*.vhd *.VHD *.vhdx *.VHDX"),
    ("QEMU / KVM (QCOW2)", "*.qcow2 *.qcow *.QCOW2"),
    ("All files", "*"),
]
PREVIEW_LIMIT = 4 << 20


def resource_path(*parts):
    """Locate bundled data both from source and inside a PyInstaller executable."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    return os.path.join(base, *parts)


# ---------------------------------------------------------------------------
# Tiny procedurally drawn icons (no external assets needed)
# ---------------------------------------------------------------------------

def _icon(root, rows, palette, scale=1):
    h = len(rows)
    w = len(rows[0])
    img = tk.PhotoImage(master=root, width=w * scale, height=h * scale)
    for y, row in enumerate(rows):
        for x, ch in enumerate(row):
            c = palette.get(ch)
            if c:
                img.put(c, to=(x * scale, y * scale, (x + 1) * scale, (y + 1) * scale))
    return img


_FOLDER = [
    "................",
    "................",
    ".#####..........",
    "#yyyyy#.........",
    "#yyyyyy#######..",
    "#YYYYYYYYYYYYY#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    "#yyyyyyyyyyyyy#.",
    ".#############..",
    "................",
    "................",
]
_FILE = [
    "..#########.....",
    "..#wwwwwww##....",
    "..#wwwwwww#w#...",
    "..#wwwwwww####..",
    "..#wwwwwwwwww#..",
    "..#wggggggggw#..",
    "..#wwwwwwwwww#..",
    "..#wggggggggw#..",
    "..#wwwwwwwwww#..",
    "..#wggggggggw#..",
    "..#wwwwwwwwww#..",
    "..#wggggggw.w#..",
    "..#wwwwwwwwww#..",
    "..#wwwwwwwwww#..",
    "..############..",
    "................",
]
_DISK = [
    "................",
    "................",
    "................",
    "..############..",
    ".#ssssssssssss#.",
    ".#ssssssssssss#.",
    ".#ssssssssssss#.",
    ".##############.",
    ".#dddddddddddd#.",
    ".#dddddddddgGd#.",
    ".#dddddddddddd#.",
    "..############..",
    "................",
    "................",
    "................",
    "................",
]


class Icons:
    def __init__(self, root, scale):
        pal_folder = {"#": "#9a7b1a", "y": "#f4cf52", "Y": "#e9b93a"}
        pal_file = {"#": "#6b7280", "w": "#ffffff", "g": "#9ca3af"}
        pal_del = {"#": "#b91c1c", "w": "#fee2e2", "g": "#f87171"}
        pal_disk = {"#": "#374151", "s": "#9ca3af", "d": "#6b7280", "g": "#22c55e", "G": "#16a34a"}
        pal_vol = {"#": "#1e40af", "s": "#93c5fd", "d": "#3b82f6", "g": "#fbbf24", "G": "#f59e0b"}
        pal_bad = {"#": "#7f1d1d", "s": "#fca5a5", "d": "#ef4444", "g": "#111", "G": "#111"}
        self.folder = _icon(root, _FOLDER, pal_folder, scale)
        self.folder_del = _icon(root, _FOLDER, {"#": "#b91c1c", "y": "#fca5a5", "Y": "#f87171"}, scale)
        self.file = _icon(root, _FILE, pal_file, scale)
        self.file_del = _icon(root, _FILE, pal_del, scale)
        self.disk = _icon(root, _DISK, pal_disk, scale)
        self.volume = _icon(root, _DISK, pal_vol, scale)
        self.volume_bad = _icon(root, _DISK, pal_bad, scale)


# ---------------------------------------------------------------------------
# Main window
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self, path=None):
        super().__init__()
        self.title(f"{APP_NAME} {__version__}")
        self.scale = max(1.0, self.winfo_fpixels("1i") / 96.0)
        w = min(int(1150 * self.scale), int(self.winfo_screenwidth() * 0.9))
        h = min(int(700 * self.scale), int(self.winfo_screenheight() * 0.8))
        x = max(0, (self.winfo_screenwidth() - w) // 2)
        y = max(0, (self.winfo_screenheight() - h) // 3)
        self.geometry(f"{w}x{h}+{x}+{y}")
        self.minsize(700, 400)
        self._setup_style()
        self.icons = Icons(self, max(1, round(self.scale)))
        try:
            self._app_icon = tk.PhotoImage(master=self, file=resource_path("assets", "icon.png"))
            self.iconphoto(True, self._app_icon)
        except tk.TclError:
            self.iconphoto(True, self.icons.volume)

        self.session = None
        self.nodes = {}          # tree item id -> ("disk"|"vol"|"dir", volume, entry)
        self.list_rows = {}      # list item id -> Entry
        self.current = None      # (volume, entry) shown in the list
        self.show_deleted = tk.BooleanVar(value=False)
        self.show_system = tk.BooleanVar(value=False)
        self._q = queue.Queue()
        self._busy = 0
        self._sort = ("name", False)

        self._build_menu()
        self._build_toolbar()
        self._build_status()  # packed before the body so it is never squeezed out
        self._build_body()
        self._bind_keys()
        self.after(50, self._poll)
        if pytsk3 is None:
            messagebox.showwarning(APP_NAME, "pytsk3 is not installed - only XFS volumes can be browsed.\n"
                                             "Install it with: pip install pytsk3")
        if path:
            self.after(100, lambda: self.open_image(path))

    # -- setup -------------------------------------------------------------------
    def _setup_style(self):
        style = ttk.Style(self)
        themes = style.theme_names()
        for t in (("vista", "winnative") if sys.platform == "win32" else ("clam",)):
            if t in themes:
                style.theme_use(t)
                break
        row = int(22 * self.scale)
        style.configure("Treeview", rowheight=row)
        style.configure("Status.TLabel", padding=(6, 2))
        style.configure("Warn.TButton", foreground="#b45309")

    def _build_menu(self):
        m = tk.Menu(self)
        fm = tk.Menu(m, tearoff=False)
        fm.add_command(label="Open image...", accelerator="Ctrl+O", command=self.cmd_open)
        fm.add_command(label="Open (rebuild stream index)...", command=lambda: self.cmd_open(rebuild=True))
        fm.add_command(label="Close image", command=self.close_image)
        fm.add_separator()
        fm.add_command(label="Exit", command=self.destroy)
        m.add_cascade(label="File", menu=fm)

        am = tk.Menu(m, tearoff=False)
        am.add_command(label="Copy selected to...", accelerator="Ctrl+E", command=self.cmd_extract)
        am.add_command(label="Copy whole volume to...", command=self.cmd_extract_volume)
        am.add_command(label="Preview file", accelerator="Enter", command=self.cmd_preview)
        am.add_command(label="Open with default application", command=self.cmd_open_external)
        am.add_command(label="Properties", accelerator="Alt+Enter", command=self.cmd_properties)
        m.add_cascade(label="Actions", menu=am)

        tm = tk.Menu(m, tearoff=False)
        tm.add_command(label="Deep scan for lost partitions", command=self.cmd_deep_scan)
        tm.add_command(label="Export volume / disk as raw image...", command=self.cmd_export_raw)
        tm.add_command(label="Image information", command=self.cmd_info)
        tm.add_command(label="Problems log", command=self.cmd_problems)
        m.add_cascade(label="Tools", menu=tm)

        vm = tk.Menu(m, tearoff=False)
        vm.add_checkbutton(label="Show deleted files", variable=self.show_deleted, command=self.refresh_list)
        vm.add_checkbutton(label="Show system files", variable=self.show_system, command=self.refresh_list)
        vm.add_command(label="Refresh", accelerator="F5", command=self.refresh_list)
        m.add_cascade(label="View", menu=vm)

        hm = tk.Menu(m, tearoff=False)
        hm.add_command(label="About", command=self.cmd_about)
        m.add_cascade(label="Help", menu=hm)
        self.config(menu=m)

    def _build_toolbar(self):
        bar = ttk.Frame(self, padding=(4, 4))
        bar.pack(side=tk.TOP, fill=tk.X)

        def btn(text, cmd):
            b = ttk.Button(bar, text=text, command=cmd)
            b.pack(side=tk.LEFT, padx=2)
            return b

        btn("Open image", self.cmd_open)
        btn("Copy to...", self.cmd_extract)
        btn("Preview", self.cmd_preview)
        btn("Deep scan", self.cmd_deep_scan)
        btn("Info", self.cmd_info)
        ttk.Separator(bar, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=6)
        btn("Up", self.cmd_up)
        self.path_var = tk.StringVar()
        ent = ttk.Entry(bar, textvariable=self.path_var)
        ent.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ent.bind("<Return>", lambda e: self.goto_path(self.path_var.get()))
        ttk.Checkbutton(bar, text="Deleted", variable=self.show_deleted,
                        command=self.refresh_list).pack(side=tk.LEFT, padx=4)

    def _build_body(self):
        pw = ttk.PanedWindow(self, orient=tk.HORIZONTAL)
        pw.pack(fill=tk.BOTH, expand=True, padx=4)

        left = ttk.Frame(pw)
        self.tree = ttk.Treeview(left, show="tree", selectmode="browse")
        ys = ttk.Scrollbar(left, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=ys.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ys.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.bind("<<TreeviewOpen>>", self._on_tree_open)
        self.tree.bind("<<TreeviewSelect>>", self._on_tree_select)
        self.tree.bind("<Button-3>", self._tree_menu)
        pw.add(left, weight=1)

        right = ttk.Frame(pw)
        cols = ("size", "modified", "created", "type")
        self.list = ttk.Treeview(right, columns=cols, show="tree headings", selectmode="extended")
        self.list.heading("#0", text="Name", command=lambda: self._sort_by("name"))
        self.list.heading("size", text="Size", command=lambda: self._sort_by("size"))
        self.list.heading("modified", text="Modified", command=lambda: self._sort_by("modified"))
        self.list.heading("created", text="Created", command=lambda: self._sort_by("created"))
        self.list.heading("type", text="Type", command=lambda: self._sort_by("type"))
        s = self.scale
        self.list.column("#0", width=int(330 * s), stretch=True)
        self.list.column("size", width=int(90 * s), anchor=tk.E, stretch=False)
        date_w = tkfont.nametofont("TkDefaultFont").measure("0000-00-00 00:00:00") + int(16 * s)
        self.list.column("modified", width=date_w, stretch=False)
        self.list.column("created", width=date_w, stretch=False)
        self.list.column("type", width=int(90 * s), stretch=False)
        self.list.tag_configure("deleted", foreground="#b91c1c")
        self.list.tag_configure("system", foreground="#6b7280")
        ys2 = ttk.Scrollbar(right, orient=tk.VERTICAL, command=self.list.yview)
        self.list.configure(yscrollcommand=ys2.set)
        self.list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        ys2.pack(side=tk.RIGHT, fill=tk.Y)
        self.list.bind("<Double-1>", self._on_list_double)
        self.list.bind("<Return>", self._on_list_double)
        self.list.bind("<Button-3>", self._list_menu)
        self.list.bind("<BackSpace>", lambda e: self.cmd_up())
        pw.add(right, weight=3)
        self.after(200, lambda: pw.sashpos(0, int(330 * self.scale)))

        self.ctx = tk.Menu(self, tearoff=False)
        self.ctx.add_command(label="Open / Preview", command=self.cmd_preview)
        self.ctx.add_command(label="Open with default application", command=self.cmd_open_external)
        self.ctx.add_command(label="Copy to...", command=self.cmd_extract)
        self.ctx.add_separator()
        self.ctx.add_command(label="Properties", command=self.cmd_properties)

        self.tree_ctx = tk.Menu(self, tearoff=False)
        self.tree_ctx.add_command(label="Copy folder to...", command=lambda: self.cmd_extract(from_tree=True))
        self.tree_ctx.add_command(label="Export as raw image...", command=self.cmd_export_raw)
        self.tree_ctx.add_command(label="Information", command=self.cmd_info)

    def _build_status(self):
        bar = ttk.Frame(self)
        bar.pack(side=tk.BOTTOM, fill=tk.X)
        self.status = tk.StringVar(value="Open a VMDK, VDI, VHD/VHDX, QCOW2 or raw disk image to begin.  File > Open, or drag "
                                         "the file onto the program icon.")
        ttk.Label(bar, textvariable=self.status, style="Status.TLabel").pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.problems_btn = ttk.Button(bar, text="No problems", command=self.cmd_problems)
        self.problems_btn.pack(side=tk.RIGHT, padx=4, pady=2)
        self.progress = ttk.Progressbar(bar, mode="determinate", length=int(160 * self.scale))
        self.progress.pack(side=tk.RIGHT, padx=4)

    def _bind_keys(self):
        self.bind_all("<Control-o>", lambda e: self.cmd_open())
        self.bind_all("<Control-e>", lambda e: self.cmd_extract())
        self.bind_all("<F5>", lambda e: self.refresh_list())
        self.bind_all("<Alt-Return>", lambda e: self.cmd_properties())

    # -- background work ---------------------------------------------------------
    def run_bg(self, func, done=None, fail=None, busy_text=None):
        if busy_text:
            self.status.set(busy_text)
        self._set_busy(1)

        def worker():
            try:
                res = func()
            except Exception as e:  # noqa: BLE001
                tb = traceback.format_exc()
                self._q.put((self._finish_fail, (e, tb, fail)))
            else:
                self._q.put((self._finish_ok, (res, done)))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_ok(self, res, done):
        self._set_busy(-1)
        if done:
            done(res)
        self._update_problems()

    def _finish_fail(self, e, tb, fail):
        self._set_busy(-1)
        self._update_problems()
        if fail:
            fail(e)
        else:
            self.status.set(f"Error: {e}")
            messagebox.showerror(APP_NAME, f"{e}\n\n{tb[-1500:]}")

    def call_ui(self, fn, *args):
        """Schedule fn(*args) on the UI thread (safe from worker threads)."""
        self._q.put((fn, args))

    def _poll(self):
        try:
            while True:
                fn, args = self._q.get_nowait()
                try:
                    fn(*args)
                except Exception:  # noqa: BLE001
                    traceback.print_exc()
        except queue.Empty:
            pass
        self.after(50, self._poll)

    def _set_busy(self, delta):
        self._busy = max(0, self._busy + delta)
        if self._busy:
            self.progress.configure(mode="indeterminate")
            self.progress.start(12)
            self.config(cursor="watch")
        else:
            self.progress.stop()
            self.progress.configure(mode="determinate", value=0)
            self.config(cursor="")

    def _update_problems(self):
        n = self.session.errors.count if self.session else 0
        self.problems_btn.configure(text=f"{n} problem(s) - view" if n else "No problems",
                                    style="Warn.TButton" if n else "TButton")

    # -- opening -----------------------------------------------------------------
    def cmd_open(self, rebuild=False):
        path = filedialog.askopenfilename(title="Open disk image", filetypes=IMAGE_TYPES)
        if path:
            self.open_image(path, rebuild=rebuild)

    def open_image(self, path, rebuild=False, deep=False):
        self.close_image()
        prog = ProgressDialog(self, "Opening image", cancellable=deep)

        def work():
            return Session(path, deep=deep, rebuild_stream_index=rebuild,
                           progress=lambda i, n, msg: self.call_ui(prog.update, i, n, msg),
                           cancel=prog.cancel_event)

        def done(sess):
            prog.close()
            self.session = sess
            self.populate_tree()
            vols = sess.all_volumes()
            self.status.set(f"{os.path.basename(path)}: {sess.disk.format}, {fmt_size(sess.disk.size)}, "
                            f"{sess.scheme} partitioning, {len(vols)} volume(s)")
            self._update_problems()
            if not vols:
                if messagebox.askyesno(APP_NAME, "No partitions or file systems were found.\n\n"
                                                 "Run a deep scan for lost file systems?"):
                    self.cmd_deep_scan()

        def fail(e):
            prog.close()
            messagebox.showerror(APP_NAME, f"Could not open {path}:\n\n{e}")
            self.status.set("Open failed")

        self.run_bg(work, done, fail, busy_text=f"Opening {path} ...")

    def close_image(self):
        if self.session:
            try:
                self.session.close()
            except Exception:  # noqa: BLE001
                pass
        self.session = None
        self.tree.delete(*self.tree.get_children())
        self.list.delete(*self.list.get_children())
        self.nodes.clear()
        self.list_rows.clear()
        self.current = None
        self.path_var.set("")
        self._update_problems()

    # -- tree --------------------------------------------------------------------
    def populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        self.nodes.clear()
        s = self.session
        root = self.tree.insert("", tk.END, text=f" {s.disk.name}  ({fmt_size(s.disk.size)})",
                                image=self.icons.disk, open=True)
        self.nodes[root] = ("disk", None, None)
        first = None
        for v in s.volumes:
            item = self._add_volume(root, v)
            first = first or item
            for c in v.children:
                self._add_volume(item, c)
            if v.children:
                self.tree.item(item, open=True)
        if first:
            # select the first browsable volume
            for item, (kind, vol, _e) in self.nodes.items():
                if kind == "vol" and vol.fs_hint and vol.fs_hint not in ("LVM2 PV", "Linux swap"):
                    self.tree.selection_set(item)
                    self.tree.see(item)
                    break

    def _add_volume(self, parent, v):
        icon = self.icons.volume if v.fs_hint else self.icons.volume_bad
        title = " " + v.title() + (f"  [{v.note}]" if v.note else "")
        item = self.tree.insert(parent, tk.END, text=title, image=icon)
        self.nodes[item] = ("vol", v, None)
        if v.fs_hint and v.fs_hint != "LVM2 PV":
            self.tree.insert(item, tk.END, text="...")
        return item

    def _on_tree_open(self, _evt=None):
        item = self.tree.focus()
        self._expand(item)

    def _expand(self, item, then=None):
        kids = self.tree.get_children(item)
        if not (len(kids) == 1 and self.tree.item(kids[0], "text") == "..."):
            if then:
                then()
            return
        kind, vol, entry = self.nodes.get(item, (None, None, None))
        if kind not in ("vol", "dir"):
            return

        def work():
            fs = self.session.filesystem(vol)
            e = entry or fs.root()
            return e, fs.list_dir(e)

        def done(res):
            e, children = res
            if kind == "vol":
                self.nodes[item] = ("vol", vol, e)
            self.tree.delete(*self.tree.get_children(item))
            for c in sorted(children, key=lambda x: x.name.lower()):
                if c.kind != "dir" or (c.deleted and not self.show_deleted.get()):
                    continue
                if c.system and not self.show_system.get():
                    continue
                c.parent = e
                ci = self.tree.insert(item, tk.END, text=" " + c.name,
                                      image=self.icons.folder_del if c.deleted else self.icons.folder)
                self.nodes[ci] = ("dir", vol, c)
                self.tree.insert(ci, tk.END, text="...")
            if then:
                then()

        def fail(err):
            self.tree.delete(*self.tree.get_children(item))
            self.tree.item(item, image=self.icons.volume_bad)
            self.status.set(str(err))

        self.run_bg(work, done, fail)

    def _on_tree_select(self, _evt=None):
        sel = self.tree.selection()
        if not sel:
            return
        item = sel[0]
        kind, vol, entry = self.nodes.get(item, (None, None, None))
        if kind == "disk":
            self.list.delete(*self.list.get_children())
            self.current = None
            self.path_var.set("")
            return
        if kind not in ("vol", "dir"):
            return
        if kind == "vol" and (not vol.fs_hint or vol.fs_hint == "LVM2 PV"):
            self.list.delete(*self.list.get_children())
            self.current = None
            if vol.fs_hint == "LVM2 PV":
                self.status.set("LVM physical volume - expand it to see logical volumes")
            else:
                self.status.set("No recognised file system - try opening it anyway via Tools > Image "
                                "information, or export it as a raw image")
                self._try_unknown(item, vol)
            return
        self.show_dir(vol, entry, item)

    def _try_unknown(self, item, vol):
        def work():
            fs = self.session.filesystem(vol)
            return fs.root()

        def done(root):
            self.nodes[item] = ("vol", vol, root)
            self.tree.item(item, image=self.icons.volume)
            self.show_dir(vol, root, item)

        self.run_bg(work, done, fail=lambda e: self.status.set(str(e)))

    def _tree_menu(self, evt):
        item = self.tree.identify_row(evt.y)
        if item:
            self.tree.selection_set(item)
            self.tree_ctx.tk_popup(evt.x_root, evt.y_root)

    # -- file list -------------------------------------------------------------
    def show_dir(self, vol, entry, tree_item=None):
        def work():
            fs = self.session.filesystem(vol)
            e = entry or fs.root()
            return fs, e, fs.list_dir(e)

        def done(res):
            fs, e, children = res
            for c in children:
                c.parent = e
            self.current = (vol, e, tree_item, children)
            self.path_var.set(f"[{vol.label}] " + entry_path(e))
            self._fill_list()
            shown = self._visible(children)
            n_dirs = sum(1 for c in shown if c.is_dir)
            hidden = len(children) - len(shown)
            self.status.set(f"{fs.type_name}  {entry_path(e)}:  {n_dirs} folders, "
                            f"{len(shown) - n_dirs} files"
                            + (f"  ({hidden} hidden system/deleted entries)" if hidden else ""))

        def fail(err):
            self.list.delete(*self.list.get_children())
            self.status.set(f"{vol.label}: {err}")

        self.run_bg(work, done, fail, busy_text="Reading directory...")

    def _visible(self, children):
        sd = self.show_deleted.get()
        ss = self.show_system.get()
        return [c for c in children if (sd or not c.deleted) and (ss or not c.system)]

    def _fill_list(self):
        self.list.delete(*self.list.get_children())
        self.list_rows.clear()
        if not self.current:
            return
        children = self._visible(self.current[3])
        key, rev = self._sort
        keyf = {
            "name": lambda c: c.name.lower(),
            "size": lambda c: c.size,
            "modified": lambda c: c.mtime,
            "created": lambda c: c.crtime,
            "type": lambda c: (c.kind, os.path.splitext(c.name)[1].lower()),
        }[key]
        children = sorted(children, key=keyf, reverse=rev)
        children.sort(key=lambda c: not c.is_dir)  # folders first, stable
        for c in children:
            tags = ("deleted",) if c.deleted else (("system",) if c.system else ())
            if c.is_dir:
                icon = self.icons.folder_del if c.deleted else self.icons.folder
                typ = "Folder"
                size = ""
            else:
                icon = self.icons.file_del if c.deleted else self.icons.file
                ext = os.path.splitext(c.name)[1].lstrip(".").upper()
                typ = {"link": "Symlink", "other": "Special"}.get(c.kind, f"{ext} file" if ext else "File")
                size = fmt_size(c.size)
            name = " " + c.name + ("  (deleted)" if c.deleted else "")
            iid = self.list.insert("", tk.END, text=name, image=icon, tags=tags,
                                   values=(size, fmt_time(c.mtime), fmt_time(c.crtime), typ))
            self.list_rows[iid] = c

    def _sort_by(self, key):
        cur, rev = self._sort
        self._sort = (key, not rev if cur == key else False)
        self._fill_list()

    def refresh_list(self):
        if self.current:
            self._fill_list()

    def _on_list_double(self, _evt=None):
        sel = self.list.selection()
        if not sel:
            return
        e = self.list_rows.get(sel[0])
        if e is None:
            return
        if e.is_dir:
            self.open_child_dir(e)
        else:
            self.cmd_preview()

    def open_child_dir(self, e):
        vol, _cur, tree_item, _ch = self.current
        if tree_item:
            def select_child():
                for ci in self.tree.get_children(tree_item):
                    k, _v, ce = self.nodes.get(ci, (None, None, None))
                    if k == "dir" and ce.addr == e.addr and ce.name == e.name:
                        self.tree.item(tree_item, open=True)
                        self.tree.selection_set(ci)
                        self.tree.see(ci)
                        return
                self.show_dir(vol, e, None)
            self._expand(tree_item, then=select_child)
        else:
            self.show_dir(vol, e, None)

    def cmd_up(self):
        if not self.current:
            return
        vol, e, tree_item, _ = self.current
        if tree_item:
            parent = self.tree.parent(tree_item)
            if parent and self.nodes.get(parent, ("",))[0] in ("vol", "dir"):
                self.tree.selection_set(parent)
                self.tree.see(parent)
                return
        if e.parent is not None:
            self.show_dir(vol, e.parent, None)

    def goto_path(self, text):
        if not self.current:
            return
        vol = self.current[0]
        path = text.split("]", 1)[1].strip() if text.startswith("[") and "]" in text else text

        def work():
            from .core import resolve
            fs = self.session.filesystem(vol)
            return resolve(fs, path)

        self.run_bg(work, lambda e: self.show_dir(vol, e, None) if e.is_dir else None,
                    fail=lambda err: self.status.set(f"Path not found: {path}"))

    def _list_menu(self, evt):
        item = self.list.identify_row(evt.y)
        if item and item not in self.list.selection():
            self.list.selection_set(item)
        self.ctx.tk_popup(evt.x_root, evt.y_root)

    def _selected_entries(self):
        return [self.list_rows[i] for i in self.list.selection() if i in self.list_rows]

    # -- commands ------------------------------------------------------------
    def _fs_for_current(self):
        vol = self.current[0]
        return vol, self.session.filesystem(vol)

    def cmd_extract(self, from_tree=False):
        if not self.session:
            return
        entries = [] if from_tree else self._selected_entries()
        vol = None
        if not entries:
            sel = self.tree.selection()
            if sel:
                kind, vol, e = self.nodes.get(sel[0], (None, None, None))
                if kind == "dir" and e is not None:
                    entries = [e]
                elif kind == "vol":
                    return self.cmd_extract_volume()
        elif self.current:
            vol = self.current[0]
        if not entries or vol is None:
            messagebox.showinfo(APP_NAME, "Select files or folders to copy first.")
            return
        dest = filedialog.askdirectory(title="Copy to folder", mustexist=False)
        if dest:
            self._run_extract(vol, entries, dest)

    def cmd_extract_volume(self):
        vol = self._selected_volume()
        if vol is None:
            messagebox.showinfo(APP_NAME, "Select a volume in the left pane first.")
            return
        dest = filedialog.askdirectory(title=f"Copy all files of {vol.label} to", mustexist=False)
        if not dest:
            return
        try:
            fs = self.session.filesystem(vol)
        except Exception as e:  # noqa: BLE001
            messagebox.showerror(APP_NAME, str(e))
            return
        entries = self._visible(fs.list_dir(fs.root()))
        self._run_extract(vol, entries, os.path.join(dest, safe_name(vol.label)))

    def _selected_volume(self):
        sel = self.tree.selection()
        if sel:
            item = sel[0]
            while item:
                kind, vol, _e = self.nodes.get(item, (None, None, None))
                if kind == "vol":
                    return vol
                item = self.tree.parent(item)
        return self.current[0] if self.current else None

    def _run_extract(self, vol, entries, dest):
        fs = self.session.filesystem(vol)
        prog = ProgressDialog(self, "Copying files", cancellable=True)
        errs_before = self.session.errors.count
        stats = ExtractStats()
        last = [0.0]

        def progress(st):
            import time
            now = time.monotonic()
            if now - last[0] > 0.1:
                last[0] = now
                self.call_ui(prog.update, None, None,
                             f"{st.summary()}\n{st.current}")

        def work():
            return extract(fs, entries, dest, self.session.errors, stats=stats, progress=progress,
                           cancel=prog.cancel_event, include_deleted=self.show_deleted.get(),
                           include_system=self.show_system.get())

        def done(st):
            prog.close()
            new_errs = self.session.errors.count - errs_before
            msg = f"Copied to {dest}\n\n{st.summary()}"
            if prog.cancel_event.is_set():
                msg = "Cancelled.\n\n" + msg
            if new_errs:
                msg += (f"\n\n{new_errs} problem(s) were encountered; damaged parts were replaced with "
                        "zeros. See Tools > Problems log.")
            self.status.set(f"Copied {st.summary()} to {dest}")
            (messagebox.showwarning if new_errs else messagebox.showinfo)(APP_NAME, msg)

        def fail(e):
            prog.close()
            messagebox.showerror(APP_NAME, f"Copy failed: {e}")

        self.run_bg(work, done, fail, busy_text="Copying...")

    def cmd_preview(self):
        ents = [e for e in self._selected_entries() if not e.is_dir]
        if not ents or not self.current:
            sel = self._selected_entries()
            if sel and sel[0].is_dir:
                self.open_child_dir(sel[0])
            return
        e = ents[0]
        vol, fs = self._fs_for_current()

        def work():
            n = min(e.size, PREVIEW_LIMIT)
            if e.kind == "link":
                target = fs.readlink(e) or ""
                return f"Symbolic link -> {target}".encode()
            return fs.read(e, 0, n)

        self.run_bg(work, lambda data: PreviewWindow(self, e, data, fs), busy_text=f"Reading {e.name}...")

    def cmd_open_external(self):
        ents = [e for e in self._selected_entries() if e.kind == "file"]
        if not ents:
            return
        e = ents[0]
        vol, fs = self._fs_for_current()
        tmpdir = tempfile.mkdtemp(prefix="vdbrowser_")

        def work():
            extract(fs, [e], tmpdir, self.session.errors)
            return os.path.join(tmpdir, safe_name(e.name))

        self.run_bg(work, open_with_default_app, busy_text=f"Extracting {e.name}...")

    def cmd_properties(self):
        ents = self._selected_entries()
        if not ents:
            return
        e = ents[0]
        rows = [("Name", e.name), ("Path", entry_path(e)), ("Type", e.kind),
                ("Size", f"{fmt_size(e.size)} ({e.size:,} bytes)"),
                ("Modified", fmt_time(e.mtime)), ("Accessed", fmt_time(e.atime)),
                ("Changed", fmt_time(e.ctime)), ("Created", fmt_time(e.crtime)),
                ("Inode / MFT entry", str(e.addr)), ("Deleted", "yes" if e.deleted else "no")]
        if e.kind == "link":
            try:
                rows.append(("Link target", self._fs_for_current()[1].readlink(e) or "?"))
            except Exception:  # noqa: BLE001
                pass
        TextWindow(self, f"Properties - {e.name}", "\n".join(f"{k:<20} {v}" for k, v in rows))

    def cmd_info(self):
        s = self.session
        if not s:
            return
        lines = ["DISK IMAGE", "=" * 60]
        lines += [f"{k:<20} {v}" for k, v in s.disk.info()]
        lines += ["", f"Partitioning: {s.scheme}", "", "VOLUMES", "=" * 60]
        for i, v in enumerate(s.all_volumes(), 1):
            lines.append(f"[{i}] {v.label}")
            lines.append(f"     type: {v.kind}   file system: {v.fs_hint or 'unknown'}   "
                         f"size: {fmt_size(v.size)}   offset: {v.start:,}")
            if v.note:
                lines.append(f"     note: {v.note}")
            try:
                fs = s.filesystem(v) if v.fs_hint and v.fs_hint != "LVM2 PV" else None
                if fs:
                    for k, val in fs.info():
                        lines.append(f"     {k}: {val}")
            except Exception as e:  # noqa: BLE001
                lines.append(f"     cannot open: {e}")
        TextWindow(self, "Image information", "\n".join(lines))
        self._update_problems()

    def cmd_problems(self):
        if not self.session or not self.session.errors.count:
            messagebox.showinfo(APP_NAME, "No problems have been detected.")
            return
        errs = self.session.errors
        text = (f"{errs.count} problem(s) recorded. Unreadable data is returned as zeros so "
                f"intact files can still be recovered.\n\n" + "\n".join(errs.items))
        if errs.count > len(errs.items):
            text += f"\n... and {errs.count - len(errs.items)} more"
        TextWindow(self, "Problems log", text)

    def cmd_deep_scan(self):
        if not self.session:
            return
        path = self.session.path
        self.open_image(path, deep=True)

    def cmd_export_raw(self):
        if not self.session:
            return
        sel = self.tree.selection()
        kind = self.nodes.get(sel[0], ("disk",))[0] if sel else "disk"
        img = self.session.disk
        label = os.path.splitext(self.session.disk.name)[0]
        if kind != "disk":
            vol = self._selected_volume()
            if vol is not None:
                img = vol.image
                label = label + "_" + safe_name(vol.label).replace(" ", "_")
        dest = filedialog.asksaveasfilename(title="Export raw image", defaultextension=".img",
                                            initialfile=label + ".img",
                                            filetypes=[("Raw image", "*.img"), ("All files", "*")])
        if not dest:
            return
        prog = ProgressDialog(self, "Exporting raw image", cancellable=True)

        def work():
            return export_raw(img, dest,
                              progress=lambda d, t: self.call_ui(prog.update, d, t,
                                                                 f"{fmt_size(d)} of {fmt_size(t)}"),
                              cancel=prog.cancel_event)

        def done(n):
            prog.close()
            messagebox.showinfo(APP_NAME, f"Wrote {fmt_size(n)} to {dest}")

        def fail(e):
            prog.close()
            messagebox.showerror(APP_NAME, str(e))

        self.run_bg(work, done, fail)

    def cmd_about(self):
        messagebox.showinfo(APP_NAME, f"{APP_NAME} {__version__}\n\n"
                            "Browse and copy files from VMware, VirtualBox, Hyper-V and QEMU/KVM "
                            "virtual disks.\n\n"
                            "VMDK: monolithic/split sparse & flat, streamOptimized, ESX COWD, "
                            "snapshots.\n"
                            "VDI: fixed, dynamic, differencing (VirtualBox snapshots).\n"
                            "VHD / VHDX: fixed, dynamic, differencing.\n"
                            "QCOW2 (v2/v3, zlib/zstd, backing chains, internal snapshots), "
                            "QCOW v1, raw images.\n"
                            "File systems: NTFS, FAT, exFAT, ext2/3/4, XFS, HFS+, APFS, UFS, ISO9660, "
                            "LVM2.\n\nDamaged images are read on a best-effort basis: unreadable "
                            "regions are filled with zeros and listed in the Problems log.\n\n"
                            "File system support by The Sleuth Kit (pytsk3).")


# ---------------------------------------------------------------------------
# Dialogs
# ---------------------------------------------------------------------------

class ProgressDialog(tk.Toplevel):
    def __init__(self, master, title, cancellable=False):
        super().__init__(master)
        self.title(title)
        self.transient(master)
        self.resizable(False, False)
        self.cancel_event = threading.Event()
        frm = ttk.Frame(self, padding=12)
        frm.pack(fill=tk.BOTH, expand=True)
        self.msg = tk.StringVar(value="Working...")
        ttk.Label(frm, textvariable=self.msg, width=70, wraplength=int(480 * master.scale)).pack(anchor=tk.W)
        self.bar = ttk.Progressbar(frm, mode="indeterminate", length=int(480 * master.scale))
        self.bar.pack(fill=tk.X, pady=8)
        self.bar.start(12)
        if cancellable:
            ttk.Button(frm, text="Cancel", command=self._cancel).pack(anchor=tk.E)
        self.protocol("WM_DELETE_WINDOW", self._cancel if cancellable else lambda: None)
        self.geometry(f"+{master.winfo_rootx() + 120}+{master.winfo_rooty() + 120}")
        self._closed = False

    def update(self, i, n, msg):  # noqa: D401 - matches Tk naming
        if self._closed:
            return
        if msg:
            self.msg.set(msg)
        if n:
            if str(self.bar.cget("mode")) != "determinate":
                self.bar.stop()
                self.bar.configure(mode="determinate", maximum=1000)
            self.bar["value"] = int(1000 * i / max(n, 1))

    def _cancel(self):
        self.cancel_event.set()
        self.msg.set("Cancelling...")

    def close(self):
        self._closed = True
        try:
            self.destroy()
        except tk.TclError:
            pass


class TextWindow(tk.Toplevel):
    def __init__(self, master, title, text, mono=True):
        super().__init__(master)
        self.title(title)
        self.geometry(f"{int(820 * master.scale)}x{int(520 * master.scale)}")
        frm = ttk.Frame(self)
        frm.pack(fill=tk.BOTH, expand=True)
        font = ("Consolas", 10) if sys.platform == "win32" else ("DejaVu Sans Mono", 10)
        self.text = tk.Text(frm, wrap=tk.NONE if mono else tk.WORD, font=font if mono else None,
                            undo=False)
        ys = ttk.Scrollbar(frm, orient=tk.VERTICAL, command=self.text.yview)
        xs = ttk.Scrollbar(frm, orient=tk.HORIZONTAL, command=self.text.xview)
        self.text.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        self.text.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        frm.rowconfigure(0, weight=1)
        frm.columnconfigure(0, weight=1)
        self.text.insert("1.0", text)
        self.text.configure(state=tk.DISABLED)
        bar = ttk.Frame(self, padding=4)
        bar.pack(fill=tk.X)
        ttk.Button(bar, text="Copy text", command=lambda: self._copy(text)).pack(side=tk.LEFT)
        ttk.Button(bar, text="Close", command=self.destroy).pack(side=tk.RIGHT)

    def _copy(self, text):
        self.clipboard_clear()
        self.clipboard_append(text)


def _looks_text(data):
    if not data:
        return True, ""
    if data[:2] in (b"\xff\xfe", b"\xfe\xff"):
        try:
            return True, data.decode("utf-16")
        except UnicodeDecodeError:
            pass
    sample = data[:65536]
    if b"\0" in sample:
        return False, None
    try:
        return True, data.decode("utf-8")
    except UnicodeDecodeError as e:
        if e.start > len(data) - 4:
            return True, data[:e.start].decode("utf-8")
    ctrl = sum(1 for b in sample if b < 9 or 13 < b < 32)
    if ctrl / max(1, len(sample)) < 0.02:
        return True, data.decode("latin-1")
    return False, None


def hexdump(data, limit=256 * 1024):
    lines = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off:off + 16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{off:08x}  {hx:<48}  {asc}")
    if len(data) > limit:
        lines.append(f"... (hex view limited to first {fmt_size(limit)})")
    return "\n".join(lines)


class PreviewWindow(tk.Toplevel):
    def __init__(self, master, entry, data, fs):
        super().__init__(master)
        self.master_app = master
        self.entry = entry
        self.fs = fs
        self.title(f"{entry.name} - {fmt_size(entry.size)}")
        self.geometry(f"{int(900 * master.scale)}x{int(620 * master.scale)}")
        bar = ttk.Frame(self, padding=4)
        bar.pack(side=tk.TOP, fill=tk.X)
        ttk.Button(bar, text="Save as...", command=self._save).pack(side=tk.LEFT, padx=2)
        ttk.Button(bar, text="Open with default app", command=master.cmd_open_external).pack(side=tk.LEFT, padx=2)
        self.mode = tk.StringVar()
        body = ttk.Frame(self)
        body.pack(fill=tk.BOTH, expand=True)

        ext = os.path.splitext(entry.name)[1].lower()
        if ext in (".png", ".gif") and entry.size <= PREVIEW_LIMIT:
            try:
                import base64
                self._img = tk.PhotoImage(master=self, data=base64.b64encode(data))
                cv = tk.Canvas(body, background="#808080")
                cv.pack(fill=tk.BOTH, expand=True)
                cv.create_image(4, 4, image=self._img, anchor=tk.NW)
                return
            except tk.TclError:
                pass

        is_text, text = _looks_text(data)
        font = ("Consolas", 10) if sys.platform == "win32" else ("DejaVu Sans Mono", 10)
        txt = tk.Text(body, wrap=tk.NONE, font=font)
        ys = ttk.Scrollbar(body, orient=tk.VERTICAL, command=txt.yview)
        xs = ttk.Scrollbar(body, orient=tk.HORIZONTAL, command=txt.xview)
        txt.configure(yscrollcommand=ys.set, xscrollcommand=xs.set)
        txt.grid(row=0, column=0, sticky="nsew")
        ys.grid(row=0, column=1, sticky="ns")
        xs.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)
        self.txt = txt
        self.data = data
        self.text = text
        ttk.Radiobutton(bar, text="Text", value="text", variable=self.mode,
                        command=self._render).pack(side=tk.RIGHT)
        ttk.Radiobutton(bar, text="Hex", value="hex", variable=self.mode,
                        command=self._render).pack(side=tk.RIGHT)
        if entry.size > len(data):
            ttk.Label(bar, text=f"showing first {fmt_size(len(data))}").pack(side=tk.RIGHT, padx=8)
        self.mode.set("text" if is_text else "hex")
        self._render()

    def _render(self):
        self.txt.configure(state=tk.NORMAL)
        self.txt.delete("1.0", tk.END)
        if self.mode.get() == "text":
            if self.text is None:
                self.text = self.data.decode("latin-1")
            self.txt.insert("1.0", self.text)
        else:
            self.txt.insert("1.0", hexdump(self.data))
        self.txt.configure(state=tk.DISABLED)

    def _save(self):
        dest = filedialog.askdirectory(title="Save to folder", mustexist=False)
        if dest:
            vol = self.master_app.current[0]
            self.master_app._run_extract(vol, [self.entry], dest)


def open_with_default_app(path):
    try:
        if sys.platform == "win32":
            os.startfile(path)  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            opener = shutil.which("xdg-open") or shutil.which("gio")
            if opener is None:
                raise OSError("xdg-open not found")
            args = [opener, "open", path] if opener.endswith("gio") else [opener, path]
            subprocess.Popen(args)
    except OSError as e:
        messagebox.showerror(APP_NAME, f"Could not open {path}: {e}")


def enable_dpi_awareness():
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            pass


def main(path=None):
    enable_dpi_awareness()
    app = App(path)
    app.mainloop()
