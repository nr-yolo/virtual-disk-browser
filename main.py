"""Virtual Disk Browser entry point.

    vdbrowser                     -> graphical interface
    vdbrowser disk.vmdk           -> graphical interface, opening disk.vmdk
    vdbrowser info|ls|extract|cat|export ...   -> command line mode
"""

import sys


def main():
    argv = sys.argv[1:]
    from vdbrowser.cli import COMMANDS
    if argv and (argv[0] in COMMANDS or argv[0] in ("-h", "--help", "--version")):
        from vdbrowser.cli import main as cli_main
        if sys.stdout is None:  # windowed build launched with CLI arguments
            import io
            sys.stdout = io.StringIO()
            sys.stderr = sys.stdout
        cli_main(argv)
        return
    from vdbrowser.gui import main as gui_main
    gui_main(argv[0] if argv else None)


if __name__ == "__main__":
    main()
