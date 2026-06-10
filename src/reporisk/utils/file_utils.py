"""File traversal helpers for local repository scanning."""

from __future__ import annotations

from pathlib import Path
from typing import Iterable

IGNORED_DIRECTORIES = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
}

SUPPORTED_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".json",
    ".env",
    ".yml",
    ".yaml",
    ".toml",
    ".ini",
    ".md",
    ".txt",
}
SUPPORTED_FILENAMES = {".env"}


def is_supported_text_file(path: Path) -> bool:
    """Return True if a path is a supported text/code file."""
    return path.is_file() and (path.suffix.lower() in SUPPORTED_EXTENSIONS or path.name in SUPPORTED_FILENAMES)


def iter_supported_files(root: Path, ignored_directories: Iterable[str] | None = None) -> Iterable[Path]:
    """Yield supported local files under root while pruning common generated directories."""
    ignored = set(ignored_directories or IGNORED_DIRECTORIES)
    for path in root.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        if is_supported_text_file(path):
            yield path


def read_text_lines(path: Path) -> list[str] | None:
    """Read a text file safely; return None for binary/unreadable files."""
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if b"\x00" in data:
        return None
    try:
        return data.decode("utf-8").splitlines()
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace").splitlines()
        except UnicodeDecodeError:
            return None
