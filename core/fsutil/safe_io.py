"""
Safe filesystem helpers for forensic-image mounts.

Why this exists:
  Forensic image mounts (Arsenal Image Mounter, FTK Imager, OSFMount, etc.) can
  return Win32 errors that Python turns into OSError exceptions — most notably:

    [WinError 1117] The request could not be performed because of an I/O device error
    [WinError 21]   The device is not ready
    [WinError 5]    Access is denied
    [WinError 1392] The file or directory is corrupted and unreadable

  Vanilla `Path.exists()` and `Path.iterdir()` *raise* on these instead of
  returning False / empty. The agents need to keep going (or fail with a clear
  message) rather than crashing deep in a worker thread. These helpers swallow
  the I/O errors and return safe defaults, plus surface a single pre-flight
  check that detects a dead mount up-front.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Iterable, Iterator, List

log = logging.getLogger("dfir.fsutil")

# Win32 error numbers we treat as "device or path unavailable, keep going"
_TOLERATED_WINERRORS = {
    1117,  # I/O device error
    21,    # device not ready
    5,     # access denied
    1392,  # file/directory corrupted and unreadable
    433,   # device not connected
    31,    # device fault
    1359,  # internal error
}


class MountUnavailableError(RuntimeError):
    """Raised when the mounted forensic image is wholly unreadable."""


def _is_tolerated(exc: BaseException) -> bool:
    """Return True if the exception is one of the I/O errors we swallow."""
    if isinstance(exc, FileNotFoundError):
        return True
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, OSError):
        winerr = getattr(exc, "winerror", None)
        if winerr in _TOLERATED_WINERRORS:
            return True
        # Generic ENOENT / EACCES fall through here too
        if exc.errno in (2, 13):
            return True
    return False


def safe_exists(path: Path) -> bool:
    """Path.exists() that returns False on any I/O / device error."""
    try:
        return path.exists()
    except OSError as e:
        if _is_tolerated(e):
            log.debug("safe_exists(%s) -> False (%s)", path, e)
            return False
        raise


def safe_is_dir(path: Path) -> bool:
    try:
        return path.is_dir()
    except OSError as e:
        if _is_tolerated(e):
            return False
        raise


def safe_is_file(path: Path) -> bool:
    try:
        return path.is_file()
    except OSError as e:
        if _is_tolerated(e):
            return False
        raise


def safe_iterdir(path: Path) -> Iterator[Path]:
    """iterdir() that yields nothing on I/O error instead of raising."""
    try:
        # Materialise so the iteration error happens here (not later)
        entries = list(path.iterdir())
    except OSError as e:
        if _is_tolerated(e):
            log.debug("safe_iterdir(%s) -> [] (%s)", path, e)
            return
        raise
    for entry in entries:
        yield entry


def safe_glob(path: Path, pattern: str) -> List[Path]:
    """glob() that returns [] on I/O error instead of raising."""
    try:
        return list(path.glob(pattern))
    except OSError as e:
        if _is_tolerated(e):
            log.debug("safe_glob(%s, %s) -> [] (%s)", path, pattern, e)
            return []
        raise


def check_mount_health(mount_point: Path) -> None:
    """
    Pre-flight check: verify the forensic-image mount is actually readable.
    Raises MountUnavailableError with a clear, actionable message if not.

    Why we test multiple paths:
      A mount can be "exists()" True at the root but throw on every read.
      We try a sequence of common paths to detect this state.
    """
    mount_point = Path(mount_point)
    test_paths = [
        mount_point,
        mount_point / "Windows",
        mount_point / "Windows" / "System32",
    ]
    last_err: Exception | None = None

    # First — does the root even resolve?
    try:
        if not mount_point.exists():
            raise MountUnavailableError(
                f"Mount path {mount_point} does not exist. "
                f"Mount the forensic image and verify the drive letter."
            )
    except OSError as e:
        raise MountUnavailableError(
            f"Cannot stat mount root {mount_point}: {e}\n\n"
            f"This usually means the mount is dead. Re-mount the image."
        ) from e

    # Second — can we actually read it?
    for p in test_paths:
        try:
            if p.exists():
                # Try to read a directory entry
                if p.is_dir():
                    try:
                        next(iter(p.iterdir()), None)
                    except OSError as e:
                        last_err = e
                        continue
                return  # at least one path is healthy
        except OSError as e:
            last_err = e
            continue

    # All paths failed — report the clearest error
    winerr = getattr(last_err, "winerror", None) if last_err else None
    extra = ""
    if winerr == 1117:
        extra = (
            "\n\n[WinError 1117 = I/O device error]\n"
            "The forensic image mount has gone offline or is returning read errors.\n"
            "Common causes:\n"
            "  • Image file (E01/VHD/VHDX/RAW) is corrupted\n"
            "  • Mount tool (Arsenal Image Mounter / FTK Imager / OSFMount) crashed\n"
            "  • Underlying disk holding the image has bad sectors\n"
            "  • USB drive holding the image was disconnected mid-read\n\n"
            "Fix:\n"
            "  1. Dismount the image (in your mount tool)\n"
            "  2. Verify the source image file isn't corrupted (check hash)\n"
            "  3. Re-mount the image\n"
            "  4. Confirm read access by opening Windows Explorer and listing files\n"
            "  5. Re-run this pipeline"
        )
    elif winerr == 21:
        extra = ("\n\n[WinError 21 = device not ready]\n"
                 "The mount is recognised but not yet ready. Wait a moment and retry.")
    elif winerr == 5:
        extra = ("\n\n[WinError 5 = access denied]\n"
                 "Run the tool as Administrator, or check NTFS permissions on the image.")

    raise MountUnavailableError(
        f"Cannot read forensic image at {mount_point}.\n"
        f"Last error: {last_err}"
        f"{extra}"
    )
