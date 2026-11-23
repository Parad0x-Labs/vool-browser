#!/usr/bin/env python3
"""Every link from one page of this repository to another must lead somewhere.

    python tools/check_docs.py

Checks the relative links and pictures in every Markdown file: the target must be a file
or folder in the repository, and a `#heading` on it must exist. Links to the web are not
followed; nothing here goes online.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_LINK = re.compile(r"(?:\[[^\]]*\]\(([^)\s]+)[^)]*\))|(?:\b(?:src|href)=\"([^\"]+)\")")
_HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*$")
_FENCE = re.compile(r"^(```|~~~)")


def anchors(path: Path) -> set[str]:
    """The heading anchors of a Markdown page, made the way GitHub makes them."""
    found: set[str] = set()
    fenced = False
    for line in path.read_text(encoding="utf-8").splitlines():
        if _FENCE.match(line.strip()):
            fenced = not fenced
            continue
        match = None if fenced else _HEADING.match(line)
        if match:
            text = re.sub(r"[`*_]|\[([^\]]*)\]\([^)]*\)", r"\1", match.group(1)).strip().lower()
            found.add(re.sub(r"\s", "-", re.sub(r"[^\w\s-]", "", text)))
    return found


def problems(root: Path) -> list[str]:
    found: list[str] = []
    pages = sorted(path for path in root.rglob("*.md") if ".git" not in path.relative_to(root).parts)
    for page in pages:
        fenced = False
        for number, line in enumerate(page.read_text(encoding="utf-8").splitlines(), 1):
            if _FENCE.match(line.strip()):
                fenced = not fenced
                continue
            if fenced:
                continue
            for match in _LINK.finditer(line):
                target = match.group(1) or match.group(2)
                if re.match(r"[a-zA-Z][a-zA-Z0-9+.-]*:", target):
                    continue  # the web, mail and the like: not followed
                where = f"{page.relative_to(root).as_posix()}:{number}"
                name, _, anchor = target.partition("#")
                goal = page if not name else (page.parent / name).resolve()
                if not goal.is_relative_to(root.resolve()) or not goal.exists():
                    found.append(f"{where}: {target} leads nowhere")
                elif anchor and goal.suffix == ".md" and anchor.lower() not in anchors(goal):
                    found.append(f"{where}: {target} names a heading that is not there")
    return found


def main() -> int:
    found = problems(ROOT)
    for line in found:
        print("FOUND", line)
    print(f"FAILED: {len(found)} broken link(s)" if found else "OK: every link between pages leads somewhere")
    return 1 if found else 0


if __name__ == "__main__":
    raise SystemExit(main())
