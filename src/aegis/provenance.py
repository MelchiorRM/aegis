"""Record which code produced a run. Standard library only, so the notebook builder can use it."""

from __future__ import annotations

import hashlib
import subprocess
from pathlib import Path

PACKAGE_DIR = Path(__file__).resolve().parent


def source_files(root: str | Path = PACKAGE_DIR.parent) -> dict[str, str]:
    """Return the package's Python files by path relative to ``root``, the package's parent."""
    root = Path(root)
    return {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in sorted((root / PACKAGE_DIR.name).rglob("*.py"))
    }


def source_hash(root: str | Path = PACKAGE_DIR.parent) -> str:
    """Fingerprint the package source. Works with or without git, including in the notebook."""
    digest = hashlib.sha256()
    for name, text in source_files(root).items():
        digest.update(name.encode())
        digest.update(text.encode())
    return digest.hexdigest()[:16]


def file_sha256(path: str | Path, chunk_size: int = 1 << 20) -> str:
    """Hash a file in chunks, so a large CSV is never held in memory."""
    digest = hashlib.sha256()
    with Path(path).open("rb") as handle:
        while chunk := handle.read(chunk_size):
            digest.update(chunk)
    return digest.hexdigest()


def git_state(directory: str | Path = PACKAGE_DIR) -> str:
    """Describe the commit holding ``directory``, or ``unknown`` outside a repository.

    ``-dirty`` means files under ``directory`` differ from that commit. ``git describe
    --dirty`` alone ignores untracked files, so it would call uncommitted code clean.
    """

    def git(*args: str) -> str:
        return subprocess.run(
            ["git", "-C", str(directory), *args], capture_output=True, text=True, check=True
        ).stdout.strip()

    try:
        commit = git("describe", "--always")
        return f"{commit}-dirty" if git("status", "--porcelain", "--", ".") else commit
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
