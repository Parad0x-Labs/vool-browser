#!/usr/bin/env python3
"""Verify the manifest the way VOOL does before it accepts an update.

    python tools/verify_manifest.py                       # report; unsigned is reported, not failed
    python tools/verify_manifest.py --require-signature   # exit 1 unless validly signed (the published branch)

Checks, in this order, and stops at the first failure:
1. the signature over the exact manifest bytes, against keys/release.pub
2. the manifest's shape and serial
3. every listed file: present, exact size, exact SHA-256
4. no list file on disk that the manifest does not list
"""
from __future__ import annotations

import argparse
import base64
import binascii
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common  # noqa: E402

SIGNED, UNSIGNED, BAD = "SIGNED", "UNSIGNED", "BAD"


def _b64(path: Path, size: int) -> bytes | None:
    try:
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
    except (OSError, ValueError, binascii.Error):
        return None
    return raw if len(raw) == size else None


def signature_state(manifest_bytes: bytes, public_key: Path, signature: Path) -> tuple[str, str]:
    """(state, plain reason). BAD covers everything that is present but not valid."""
    if not public_key.exists():
        if signature.exists():
            return BAD, "a signature is present but there is no public key to check it against"
        return UNSIGNED, "no release key has been published yet"
    key = _b64(public_key, 32)
    if key is None:
        return BAD, "keys/release.pub is not a 32-byte Ed25519 public key in base64"
    if not signature.exists():
        return UNSIGNED, "the manifest has no signature"
    sig = _b64(signature, 64)
    if sig is None:
        return BAD, "manifest.json.sig is not a 64-byte signature in base64"
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        Ed25519PublicKey.from_public_bytes(key).verify(sig, manifest_bytes)
    except InvalidSignature:
        return BAD, "the signature does not match this manifest"
    return SIGNED, "the signature is valid"


def file_problems(manifest: dict, root: Path) -> list[str]:
    found: list[str] = []
    if manifest.get("schema") != common.MANIFEST_SCHEMA:
        return [f"schema must be {common.MANIFEST_SCHEMA}"]
    if type(manifest.get("serial")) is not int or manifest["serial"] < 1:
        return ["serial must be a whole number from 1"]
    files = manifest.get("files")
    if not isinstance(files, list) or not files:
        return ["the manifest lists no files"]
    listed: set[str] = set()
    for item in files:
        if not isinstance(item, dict) or not isinstance(item.get("path"), str):
            return ["a file entry has no path"]
        path = item["path"]
        target = (root / path).resolve()
        if path in listed or ".." in Path(path).parts or Path(path).is_absolute() or not target.is_relative_to(root.resolve()):
            found.append(f"{path}: not a plain path inside the repository, or listed twice")
            continue
        listed.add(path)
        if not target.is_file():
            found.append(f"{path}: missing")
            continue
        raw = target.read_bytes()
        if len(raw) != item.get("bytes"):
            found.append(f"{path}: size differs from the manifest")
        import hashlib

        if hashlib.sha256(raw).hexdigest() != item.get("sha256"):
            found.append(f"{path}: SHA-256 differs from the manifest")
    for path in sorted((root / "lists").glob("*.txt")):
        if path.relative_to(root).as_posix() not in listed:
            found.append(f"{path.relative_to(root).as_posix()}: on disk but not in the manifest")
    return found


def verify(root: Path, *, require_signature: bool) -> tuple[int, list[str]]:
    manifest_path = root / "manifest" / "manifest.json"
    try:
        raw = manifest_path.read_bytes()
        manifest = json.loads(raw.decode("ascii"))
    except (OSError, ValueError):
        return 1, ["FAILED: manifest.json is missing or is not JSON"]
    if not isinstance(manifest, dict):
        return 1, ["FAILED: manifest.json is not an object"]
    state, reason = signature_state(raw, root / "keys" / "release.pub", root / "manifest" / "manifest.json.sig")
    lines = [f"{state}: {reason}"]
    if state == BAD or (require_signature and state != SIGNED):
        return 1, [*lines, "FAILED: an update like this is refused"]
    found = file_problems(manifest, root)
    if found:
        return 1, [*lines, *("PROBLEM " + line for line in found), "FAILED: an update like this is refused"]
    return 0, [*lines, f"OK: serial {manifest['serial']}, {len(manifest['files'])} file(s) match"]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--require-signature", action="store_true")
    args = parser.parse_args(argv)
    code, lines = verify(common.ROOT, require_signature=args.require_signature)
    print("\n".join(lines))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
