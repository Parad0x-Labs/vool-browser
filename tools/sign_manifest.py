#!/usr/bin/env python3
"""Sign manifest/manifest.json. Run by the maintainer only, on their own computer.

    python tools/sign_manifest.py --new-key /path/outside/this/repository/release.key
    python tools/sign_manifest.py --key /path/outside/this/repository/release.key

The private key file must live outside this repository. This script refuses a key
path inside it, and never prints the private key.
"""
from __future__ import annotations

import argparse
import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common


def _outside_repository(path: Path) -> bool:
    return not path.resolve().is_relative_to(common.ROOT.resolve())


def new_key(path: Path) -> int:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not _outside_repository(path):
        print("REFUSED: keep the private key outside this repository")
        return 1
    if path.exists():
        print("REFUSED: that file already exists; a key is never overwritten")
        return 1
    key = Ed25519PrivateKey.generate()
    raw = key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="ascii") as handle:
        handle.write(base64.b64encode(raw).decode("ascii") + "\n")
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    common.PUBLIC_KEY.parent.mkdir(parents=True, exist_ok=True)
    common.PUBLIC_KEY.write_text(base64.b64encode(public).decode("ascii") + "\n", encoding="ascii")
    print(f"Private key written to {path} (readable by you only). Back it up somewhere safe.")
    print("Public key written to keys/release.pub. Commit that file.")
    return 0


def sign(path: Path) -> int:
    import verify_manifest
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if not _outside_repository(path):
        print("REFUSED: keep the private key outside this repository")
        return 1
    try:
        raw = base64.b64decode(path.read_text(encoding="ascii").strip(), validate=True)
        key = Ed25519PrivateKey.from_private_bytes(raw)
    except (OSError, ValueError):
        print("REFUSED: that file is not a private key made by --new-key")
        return 1
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if not common.PUBLIC_KEY.exists() or common.PUBLIC_KEY.read_text(encoding="ascii").strip() != base64.b64encode(public).decode("ascii"):
        print("REFUSED: this key does not match keys/release.pub")
        return 1
    # Never sign something VOOL would refuse for its contents.
    import json

    manifest_bytes = common.MANIFEST.read_bytes()
    found = verify_manifest.file_problems(json.loads(manifest_bytes.decode("ascii")), common.ROOT)
    if found:
        print("REFUSED: the manifest does not match the files:")
        for line in found:
            print("  " + line)
        return 1
    common.SIGNATURE.write_text(base64.b64encode(key.sign(manifest_bytes)).decode("ascii") + "\n", encoding="ascii")
    code, lines = verify_manifest.verify(common.ROOT, require_signature=True)
    print("\n".join(lines))
    return code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--new-key", type=Path)
    group.add_argument("--key", type=Path)
    args = parser.parse_args(argv)
    return new_key(args.new_key) if args.new_key else sign(args.key)


if __name__ == "__main__":
    raise SystemExit(main())
