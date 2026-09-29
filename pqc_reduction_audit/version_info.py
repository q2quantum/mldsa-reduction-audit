"""
version_info.py -- Issue #193 п.3 / #194 п.4: привязка прогона к версии цели.

cli.py раньше не проверял, какую версию файла ему дали, а номера строк в
известных отчётах жёстко привязаны к конкретному тегу (см. #192 -- сверка
велась вручную по названию файла отчёта). Это записывает SHA-256 целевого
файла и, если --include-root -- git-репозиторий, точный тег/коммит в сам
отчёт (M5), чтобы прогон нельзя было спутать с прогоном по другой версии.

Не трогает логику определения мест (M1/M1b/M2/M3) -- только метаданные
отчёта.
"""
from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class TargetVersionInfo:
    sha256: str
    git_tag: str | None
    git_commit: str | None
    git_dirty: bool | None

    def to_dict(self) -> dict:
        return {
            "sha256": self.sha256,
            "git_tag": self.git_tag,
            "git_commit": self.git_commit,
            "git_dirty": self.git_dirty,
        }


def _sha256_of_file(path: Path) -> str:
    """CRLF-normalized (Issue #194 п.1): a git checkout with core.autocrlf=true
    on Windows rewrites line endings on checkout, giving a different sha256
    for byte-identical source than a Linux/macOS checkout of the same tag.
    Normalizing to LF before hashing makes the value the same on every
    platform, independent of local git line-ending settings."""
    h = hashlib.sha256()
    h.update(path.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def _run_git(include_root: str, *args: str) -> str | None:
    """Returns stripped stdout, or None if the command failed to run at all
    (not a git repo, git missing, timeout). An empty-but-successful result
    (e.g. `git status --porcelain` on a clean tree) is collapsed to None too
    -- callers that need to distinguish "clean" from "not a repo" should use
    _run_git_ok() instead."""
    ok, out = _run_git_ok(include_root, *args)
    return (out or None) if ok else None


def _run_git_ok(include_root: str, *args: str) -> tuple[bool, str]:
    """Returns (command_succeeded, stripped_stdout) -- unlike _run_git(),
    keeps empty-but-successful output distinguishable from a failed command."""
    try:
        result = subprocess.run(
            ["git", "-C", include_root, *args],
            capture_output=True, text=True, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, ""
    return result.returncode == 0, result.stdout.strip()


def compute_target_version_info(target_file: str, include_root: str) -> TargetVersionInfo:
    """Best-effort: git info is None if include_root isn't a git checkout
    (e.g. a plain extracted tarball) -- sha256 always succeeds if the file
    is readable, which cli.py already requires to get this far."""
    sha256 = _sha256_of_file(Path(target_file))

    git_tag = _run_git(include_root, "describe", "--tags", "--always", "--dirty")
    git_commit = _run_git(include_root, "rev-parse", "HEAD")
    status_ok, status_out = _run_git_ok(include_root, "status", "--porcelain")
    git_dirty = bool(status_out) if status_ok else None

    return TargetVersionInfo(
        sha256=sha256,
        git_tag=git_tag,
        git_commit=git_commit,
        git_dirty=git_dirty,
    )
