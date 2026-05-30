"""Filesystem helpers that tolerate forensic-image mount errors."""
from .safe_io import (
    safe_exists,
    safe_iterdir,
    safe_glob,
    safe_is_dir,
    safe_is_file,
    check_mount_health,
    MountUnavailableError,
)

__all__ = [
    "safe_exists",
    "safe_iterdir",
    "safe_glob",
    "safe_is_dir",
    "safe_is_file",
    "check_mount_health",
    "MountUnavailableError",
]
