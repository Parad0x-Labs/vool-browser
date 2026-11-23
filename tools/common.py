"""Shared rules for the list tools. Standard library only."""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LISTS = ROOT / "lists"
MANIFEST = ROOT / "manifest" / "manifest.json"
SIGNATURE = ROOT / "manifest" / "manifest.json.sig"
PUBLIC_KEY = ROOT / "keys" / "release.pub"

MANIFEST_SCHEMA = "vool.browser.manifest.v1"

_LABEL = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")

#: Names that are not public sites. A list entry for one of these is a mistake.
RESERVED_SUFFIXES = (
    "localhost", "local", "localdomain", "internal", "intranet", "lan", "home", "corp",
    "test", "example", "invalid", "onion", "arpa",
)

#: Two-part endings under which anyone can register. Listing one would block
#: every site beneath it, so an entry must have a name in front of it.
SHARED_ENDINGS = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp",
    "co.kr", "com.br", "com.cn", "com.tr", "com.mx", "co.in", "co.za", "com.ar", "com.ua",
    "github.io", "gitlab.io", "pages.dev", "web.app", "netlify.app", "vercel.app",
    "herokuapp.com", "blogspot.com", "wordpress.com", "cloudfront.net", "amazonaws.com",
    "azurewebsites.net", "appspot.com", "firebaseapp.com", "workers.dev", "r2.dev",
})

#: Hosts a list may never block: blocking them would cut off VOOL's own updates
#: of these lists, or take down a whole shared platform for one bad page.
PROTECTED = frozenset({
    "github.com", "githubusercontent.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
    "google.com", "youtube.com", "gmail.com", "apple.com", "icloud.com", "microsoft.com",
    "live.com", "outlook.com", "office.com", "wikipedia.org", "wikimedia.org", "mozilla.org",
    "duckduckgo.com", "amazon.com", "cloudflare.com", "dropbox.com", "gitlab.com",
    "torproject.org", "archive.org", "stackoverflow.com", "python.org", "pypi.org",
})


def host_problem(host: str) -> str | None:
    """Why *host* may not be a list entry, or None when it may."""
    if host != host.strip() or not host:
        return "has spaces around it or is empty"
    if host != host.lower():
        return "must be lower case"
    if len(host) > 253:
        return "is longer than a host name can be"
    if any(ch in host for ch in "/:@?#*\\ \t"):
        return "must be a bare host: no scheme, port, path or wildcard"
    try:
        ipaddress.ip_address(host)
        return "is a number address; lists hold names only"
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2:
        return "needs at least a name and an ending"
    if any(not _LABEL.match(label) for label in labels):
        return "has a part that is not a valid host label (non-ASCII names go in punycode)"
    if labels[-1].isdigit():
        return "ends in a number"
    if labels[-1] in RESERVED_SUFFIXES:
        return "is not a public site name"
    if host in SHARED_ENDINGS:
        return "is an ending anyone can register under, not one site"
    if host in PROTECTED or any(host.endswith("." + p) for p in PROTECTED):
        return "is on the never-block list"
    if any(p.endswith("." + host) for p in PROTECTED):
        return "would also block a host on the never-block list"
    return None


def read_hosts(path: Path) -> tuple[list[str], list[str]]:
    """(hosts, problems) for one list file. Every problem names its line."""
    hosts: list[str] = []
    problems: list[str] = []
    raw = path.read_bytes()
    if b"\r" in raw:
        problems.append(f"{path.name}: uses Windows line endings")
    if raw and not raw.endswith(b"\n"):
        problems.append(f"{path.name}: must end with a line break")
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError:
        return [], [f"{path.name}: holds characters outside plain ASCII"]
    for number, line in enumerate(text.splitlines(), 1):
        if line.startswith("#"):
            continue
        if not line:
            problems.append(f"{path.name}:{number}: empty line")
            continue
        why = host_problem(line)
        if why:
            problems.append(f"{path.name}:{number}: {line!r} {why}")
        else:
            hosts.append(line)
    if hosts != sorted(hosts):
        problems.append(f"{path.name}: entries are not sorted")
    seen: set[str] = set()
    for host in hosts:
        if host in seen:
            problems.append(f"{path.name}: {host} is listed twice")
        seen.add(host)
    return hosts, problems


def list_files() -> list[Path]:
    return sorted(LISTS.glob("*.txt"))


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def manifest_files() -> list[dict]:
    """What the manifest must say about the files as they are on disk now."""
    entries = []
    for path in [*list_files(), LISTS / "sources.json", ROOT / "plugins" / "index.json"]:
        item = {"path": path.relative_to(ROOT).as_posix(), "sha256": sha256_file(path), "bytes": path.stat().st_size}
        if path.suffix == ".txt":
            item["entries"] = len(read_hosts(path)[0])
        entries.append(item)
    return entries


def canonical(data: dict) -> bytes:
    return (json.dumps(data, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode("ascii")
