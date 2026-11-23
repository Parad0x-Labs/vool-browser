#!/usr/bin/env python3
"""Refuse a commit that carries a secret or a path from someone's own computer.

    python tools/scan_repo.py

Scans every tracked file. Prints the file and line of each finding, never the
matched text itself.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("token", re.compile(r"\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("token", re.compile(r"\bsk-[A-Za-z0-9_-]{24,}\b|\bAKIA[0-9A-Z]{16}\b|\bxox[abprs]-[A-Za-z0-9-]{20,}\b")),
    ("secret assignment", re.compile(r"(?i)\b(api[_-]?key|secret|password|passwd|token)\b\s*[:=]\s*['\"][^'\"\s]{12,}['\"]")),
    ("home folder path", re.compile(r"(/Users/|/home/)(?!runner/|user/)[A-Za-z0-9._-]+/|[A-Za-z]:\\Users\\[^\\\s]+\\")),
    ("mounted drive path", re.compile(r"/Volumes/[A-Za-z0-9._-]+/")),
    ("private network address", re.compile(r"\b(10\.\d{1,3}|192\.168|172\.(1[6-9]|2\d|3[01]))\.\d{1,3}\.\d{1,3}\b")),
    ("email address", re.compile(r"\b[A-Za-z0-9._%+-]+@(?!users\.noreply\.github\.com)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
)


#: The only files that are not text: pictures for the README, in one folder, of a known
#: kind and a modest size. Anything else that cannot be read as text is a finding.
PICTURE_FOLDER = "docs/assets"
PICTURE_KINDS = {".png": b"\x89PNG\r\n\x1a\n"}
PICTURE_MOST_BYTES = 512 * 1024


def is_allowed_picture(path: Path, root: Path) -> bool:
    relative = path.relative_to(root).as_posix()
    start = PICTURE_KINDS.get(path.suffix.lower())
    if start is None or not relative.startswith(PICTURE_FOLDER + "/") or relative.count("/") != PICTURE_FOLDER.count("/") + 1:
        return False
    try:
        raw = path.read_bytes()
    except OSError:
        return False
    return raw.startswith(start) and len(raw) <= PICTURE_MOST_BYTES


def tracked_files(root: Path) -> list[Path]:
    out = subprocess.run(["git", "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                         cwd=root, capture_output=True, check=True).stdout
    return [root / name for name in out.decode("utf-8").split("\0") if name]


def scan(paths: list[Path], root: Path) -> list[str]:
    findings: list[str] = []
    for path in paths:
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            if is_allowed_picture(path, root):
                continue
            findings.append(f"{path.relative_to(root).as_posix()}: not readable as text")
            continue
        for number, line in enumerate(text.splitlines(), 1):
            for name, pattern in RULES:
                if pattern.search(line):
                    findings.append(f"{path.relative_to(root).as_posix()}:{number}: {name}")
    return findings


def main() -> int:
    paths = tracked_files(ROOT)
    if not paths:
        print("FAILED: no files were scanned")
        return 1
    findings = scan(paths, ROOT)
    for line in findings:
        print("FOUND", line)
    print(f"FAILED: {len(findings)} finding(s)" if findings else f"OK: {len(paths)} file(s) scanned")
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
