"""Command line interface (useful on headless Linux servers and for scripting)."""

import argparse
import os
import sys

from . import APP_NAME, __version__
from .core import Session, extract, export_raw, resolve, entry_path, fmt_time
from .disk import fmt_size

COMMANDS = ("info", "ls", "extract", "cat", "export")


def _volume(sess, number):
    vols = sess.all_volumes()
    if not vols:
        sys.exit("no volumes found (try --deep)")
    if number is None:
        browsable = [v for v in vols if v.fs_hint and v.fs_hint not in ("LVM2 PV", "Linux swap")]
        if len(browsable) == 1:
            return browsable[0]
        sys.exit("several volumes found - choose one with -p N (see 'info')")
    if not 1 <= number <= len(vols):
        sys.exit(f"volume number must be 1..{len(vols)}")
    return vols[number - 1]


def cmd_info(sess, args):
    for k, v in sess.disk.info():
        print(f"{k:<20} {v}")
    print(f"{'Partitioning':<20} {sess.scheme}")
    print()
    for i, v in enumerate(sess.all_volumes(), 1):
        print(f"[{i}] {v.label:<34} {v.fs_hint or '?':<12} {fmt_size(v.size):>10}   {v.kind}"
              + (f"  ({v.note})" if v.note else ""))


def _print_listing(fs, entry, recursive, deleted, prefix=""):
    for c in sorted(fs.list_dir(entry), key=lambda x: (not x.is_dir, x.name.lower())):
        if c.deleted and not deleted:
            continue
        c.parent = entry
        flag = "D" if c.deleted else " "
        kind = {"dir": "<DIR>", "link": "<LNK>"}.get(c.kind, fmt_size(c.size))
        print(f"{flag} {fmt_time(c.mtime):19} {kind:>10}  {prefix}{c.name}{'/' if c.is_dir else ''}")
        if recursive and c.is_dir and not c.deleted:
            _print_listing(fs, c, recursive, deleted, prefix + c.name + "/")


def cmd_ls(sess, args):
    fs = sess.filesystem(_volume(sess, args.partition))
    entry = resolve(fs, args.path or "/")
    if not entry.is_dir:
        print(f"{fmt_size(entry.size):>10}  {entry_path(entry)}")
        return
    _print_listing(fs, entry, args.recursive, args.deleted)


def cmd_extract(sess, args):
    fs = sess.filesystem(_volume(sess, args.partition))
    entries = [resolve(fs, p) for p in (args.paths or ["/"])]
    if len(entries) == 1 and entries[0].name == "":
        entries = [e for e in fs.list_dir(entries[0])
                   if (args.system or not e.system) and (args.deleted or not e.deleted)]
    last = [0]

    def progress(st):
        if args.quiet:
            return
        if st.files != last[0]:
            last[0] = st.files
            sys.stderr.write(f"\r{st.summary()[:100]:<100}")
            sys.stderr.flush()

    before = sess.errors.count
    st = extract(fs, entries, args.output, sess.errors, progress=progress,
                 include_deleted=args.deleted, include_system=args.system)
    if not args.quiet:
        sys.stderr.write("\n")
    print(f"Extracted {st.summary()} to {args.output}")
    if sess.errors.count > before:
        print(f"{sess.errors.count - before} problem(s) - run with -v to list them", file=sys.stderr)


def cmd_cat(sess, args):
    fs = sess.filesystem(_volume(sess, args.partition))
    e = resolve(fs, args.path)
    out = sys.stdout.buffer
    for chunk in fs.iter_content(e):
        out.write(chunk)
    out.flush()


def cmd_export(sess, args):
    img = sess.disk if args.partition is None else _volume(sess, args.partition).image

    def progress(d, t):
        if not args.quiet:
            sys.stderr.write(f"\r{fmt_size(d)} / {fmt_size(t)}   ")
    n = export_raw(img, args.output, progress=progress)
    if not args.quiet:
        sys.stderr.write("\n")
    print(f"Wrote {fmt_size(n)} to {args.output}")


def build_parser():
    p = argparse.ArgumentParser(prog="vdbrowser", description=f"{APP_NAME} {__version__} - command line mode. "
                                "Run without arguments to start the graphical interface.")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("image", help="VMDK, VDI, VHD/VHDX, QCOW2/QCOW or raw disk image")
        sp.add_argument("--deep", action="store_true", help="deep scan for lost partitions")
        sp.add_argument("--rebuild-index", action="store_true",
                        help="rebuild streamOptimized grain index by scanning")
        sp.add_argument("-v", "--verbose", action="store_true", help="print the problems log")

    sp = sub.add_parser("info", help="show image, partition and volume information")
    common(sp)
    sp = sub.add_parser("ls", help="list a directory")
    common(sp)
    sp.add_argument("path", nargs="?", default="/")
    sp.add_argument("-p", "--partition", type=int, help="volume number from 'info'")
    sp.add_argument("-r", "--recursive", action="store_true")
    sp.add_argument("-d", "--deleted", action="store_true", help="include deleted entries")
    sp = sub.add_parser("extract", help="copy files/folders out of the image")
    common(sp)
    sp.add_argument("paths", nargs="*", help="paths inside the volume (default: everything)")
    sp.add_argument("-p", "--partition", type=int)
    sp.add_argument("-o", "--output", required=True, help="destination folder")
    sp.add_argument("-d", "--deleted", action="store_true", help="also try to recover deleted entries")
    sp.add_argument("-s", "--system", action="store_true",
                    help="include file system metadata files (NTFS $MFT etc.)")
    sp.add_argument("-q", "--quiet", action="store_true")
    sp = sub.add_parser("cat", help="write a file's content to stdout")
    common(sp)
    sp.add_argument("path")
    sp.add_argument("-p", "--partition", type=int)
    sp = sub.add_parser("export", help="save the disk or one volume as a raw .img")
    common(sp)
    sp.add_argument("-p", "--partition", type=int, help="volume number (default: whole disk)")
    sp.add_argument("-o", "--output", required=True)
    sp.add_argument("-q", "--quiet", action="store_true")
    return p


def main(argv=None):
    args = build_parser().parse_args(argv)
    if not os.path.isfile(args.image):
        sys.exit(f"file not found: {args.image}")
    sess = Session(args.image, deep=args.deep, rebuild_stream_index=args.rebuild_index)
    try:
        {"info": cmd_info, "ls": cmd_ls, "extract": cmd_extract, "cat": cmd_cat,
         "export": cmd_export}[args.cmd](sess, args)
    except FileNotFoundError as e:
        sys.exit(f"not found: {e}")
    except RuntimeError as e:
        sys.exit(str(e))
    finally:
        if args.verbose and sess.errors.count:
            print(f"\n{sess.errors.count} problem(s):", file=sys.stderr)
            for m in sess.errors.items:
                print("  " + m, file=sys.stderr)
        sess.close()
