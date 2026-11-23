#!/usr/bin/env python3
"""Write manifest/manifest.json from the files on disk, or check that it matches them.

    python tools/build_manifest.py            # rewrite; the serial goes up by one when anything changed
    python tools/build_manifest.py --check    # exit 1 when the committed manifest does not match

The serial only ever goes up. VOOL refuses a manifest whose serial is lower than the
one it already holds, so an old signed manifest cannot be replayed to bring back an
old list.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402


def load(path: Path) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def problems(manifest: dict | None, files: list[dict]) -> list[str]:
    if manifest is None:
        return ["manifest.json is missing or is not JSON"]
    found: list[str] = []
    if manifest.get("schema") != common.MANIFEST_SCHEMA:
        found.append(f"schema must be {common.MANIFEST_SCHEMA}")
    serial = manifest.get("serial")
    if type(serial) is not int or serial < 1:
        found.append("serial must be a whole number from 1")
    if set(manifest) != {"schema", "serial", "generated", "files"}:
        found.append("must hold exactly schema, serial, generated, files")
    if manifest.get("files") != files:
        found.append("the files section does not match the files on disk; run tools/build_manifest.py")
    return found


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    files = common.manifest_files()
    current = load(common.MANIFEST)
    if args.check:
        found = problems(current, files)
        for line in found:
            print("PROBLEM", line)
        print("FAILED" if found else f"OK: manifest serial {current['serial']} matches {len(files)} file(s)")
        return 1 if found else 0
    if current is not None and not problems(current, files):
        print(f"unchanged: serial {current['serial']}")
        return 0
    previous = current.get("serial") if current else 0
    serial = (previous if type(previous) is int and previous > 0 else 0) + 1
    manifest = {
        "schema": common.MANIFEST_SCHEMA,
        "serial": serial,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "files": files,
    }
    common.MANIFEST.parent.mkdir(parents=True, exist_ok=True)
    common.MANIFEST.write_bytes(common.canonical(manifest))
    print(f"written: serial {serial}. The signature is now out of date; sign it (docs/SIGNING.md).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
