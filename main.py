"""
main.py — Single entry point.

  python main.py              → launches GUI
  python main.py cli ...      → CLI
  python main.py doctor       → environment check
  python main.py list-agents  → list discovered agents
"""

from __future__ import annotations

import io
import sys


def _force_utf8():
    """On Windows the default stdout/stderr encoding can be cp1252.
    Force UTF-8 so Unicode characters in log messages don't cause crashes."""
    if sys.platform == "win32":
        try:
            if hasattr(sys.stdout, "buffer"):
                sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace", line_buffering=True)
            if hasattr(sys.stderr, "buffer"):
                sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace", line_buffering=True)
        except Exception:
            pass


def main():
    _force_utf8()
    args = sys.argv[1:]

    # CLI / utility commands
    if args and args[0] in ("cli", "doctor", "list-agents"):
        import click
        from cli import cli_group
        # Remove "main.py" from argv so Click sees the right subcommand
        sys.argv = [sys.argv[0]] + args
        cli_group()
        return

    # Default: launch GUI
    try:
        from gui.app import launch_gui
        sys.exit(launch_gui())
    except ImportError as e:
        print(f"GUI not available: {e}")
        print("Install PySide6:  pip install PySide6 PySide6-Addons")
        print("Or use the CLI:   python main.py cli --help")
        sys.exit(1)


if __name__ == "__main__":
    main()
