#!/usr/bin/env python3
"""Check every list, the sources file and the plugin index. Exit 1 on any problem.

    python tools/validate_lists.py
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import common

_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")
_VERSION = re.compile(r"^\d+(\.\d+){1,3}$")

SOURCE_FORMATS = ("hosts", "domains")
#: Extension permissions a listed plugin may never ask for. The same names VOOL itself refuses
#: when a browser plugin is reviewed: programs outside the browser, the engine's control channel,
#: the browser's connection, other plugins, privacy and per-site settings, saved sign-ins and
#: certificates, the screen outside the browser, and saving files by itself.
FORBIDDEN_PERMISSIONS = frozenset({
    "nativeMessaging", "debugger", "proxy", "vpnProvider", "management", "privacy", "passwordsPrivate",
    "contentSettings", "desktopCapture",
    "webAuthenticationProxy", "certificateProvider", "platformKeys", "enterprise.platformKeys",
    "enterprise.deviceAttributes", "enterprise.hardwarePlatform", "enterprise.networkingAttributes",
    "downloads", "downloads.open", "downloads.shelf", "downloads.ui",
})


def _https(value: object) -> bool:
    return isinstance(value, str) and value.startswith("https://") and " " not in value and len(value) < 500


def _load(path: Path, schema: str, problems: list[str]) -> dict | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        problems.append(f"{path.name}: cannot be read as JSON ({exc.__class__.__name__})")
        return None
    if not isinstance(data, dict) or data.get("schema") != schema:
        problems.append(f"{path.name}: schema must be {schema}")
        return None
    return data


def check_sources(path: Path) -> list[str]:
    problems: list[str] = []
    data = _load(path, "vool.browser.sources.v1", problems)
    if data is None:
        return problems
    sources = data.get("sources")
    if not isinstance(sources, list) or set(data) != {"schema", "sources"}:
        return [f"{path.name}: must hold exactly 'schema' and a 'sources' list"]
    seen: set[str] = set()
    for index, source in enumerate(sources):
        where = f"{path.name}: source {index + 1}"
        if not isinstance(source, dict):
            problems.append(f"{where}: must be an object")
            continue
        if set(source) != {"id", "name", "url", "format", "licence", "licence_url", "licence_checked_on"}:
            problems.append(f"{where}: must hold exactly id, name, url, format, licence, licence_url, licence_checked_on")
            continue
        if not isinstance(source["id"], str) or not _ID.match(source["id"]) or source["id"] in seen:
            problems.append(f"{where}: id must be unique, lower case letters, digits and dashes")
        seen.add(str(source["id"]))
        if not isinstance(source["name"], str) or not source["name"].strip():
            problems.append(f"{where}: needs a name")
        if not _https(source["url"]) or not _https(source["licence_url"]):
            problems.append(f"{where}: url and licence_url must be https addresses")
        if source["format"] not in SOURCE_FORMATS:
            problems.append(f"{where}: format must be one of {', '.join(SOURCE_FORMATS)}")
        if not isinstance(source["licence"], str) or not source["licence"].strip():
            problems.append(f"{where}: the licence must be named")
        if not isinstance(source["licence_checked_on"], str) or not _DATE.match(source["licence_checked_on"]):
            problems.append(f"{where}: licence_checked_on must be a date like 2026-01-31")
    return problems


def check_plugins(path: Path) -> list[str]:
    problems: list[str] = []
    data = _load(path, "vool.browser.plugins.v1", problems)
    if data is None:
        return problems
    plugins = data.get("plugins")
    if data.get("category") != "web-browser" or not isinstance(plugins, list) or set(data) != {"schema", "category", "plugins"}:
        return [f"{path.name}: must hold exactly schema, category 'web-browser' and a 'plugins' list"]
    wanted = {"id", "name", "summary", "homepage", "licence", "version", "package_url", "package_sha256", "permissions", "reviewed_on"}
    seen: set[str] = set()
    for index, plugin in enumerate(plugins):
        where = f"{path.name}: plugin {index + 1}"
        if not isinstance(plugin, dict) or set(plugin) != wanted:
            problems.append(f"{where}: must hold exactly {', '.join(sorted(wanted))}")
            continue
        if not isinstance(plugin["id"], str) or not _ID.match(plugin["id"]) or plugin["id"] in seen:
            problems.append(f"{where}: id must be unique, lower case letters, digits and dashes")
        seen.add(str(plugin["id"]))
        for key in ("name", "summary", "licence"):
            if not isinstance(plugin[key], str) or not plugin[key].strip() or len(plugin[key]) > 200:
                problems.append(f"{where}: {key} must be a short text")
        if not _https(plugin["homepage"]) or not _https(plugin["package_url"]):
            problems.append(f"{where}: homepage and package_url must be https addresses")
        if not isinstance(plugin["version"], str) or not _VERSION.match(plugin["version"]):
            problems.append(f"{where}: version must be numbers and dots")
        if not isinstance(plugin["package_sha256"], str) or not _SHA.match(plugin["package_sha256"]):
            problems.append(f"{where}: package_sha256 must be 64 lower case hex characters")
        permissions = plugin["permissions"]
        if not isinstance(permissions, list) or not all(isinstance(p, str) and p for p in permissions):
            problems.append(f"{where}: permissions must be a list of names")
        else:
            refused = sorted(set(permissions) & FORBIDDEN_PERMISSIONS)
            if refused:
                problems.append(f"{where}: asks for a permission no listed plugin may have ({', '.join(refused)})")
        if not isinstance(plugin["reviewed_on"], str) or not _DATE.match(plugin["reviewed_on"]):
            problems.append(f"{where}: reviewed_on must be a date like 2026-01-31")
    return problems


def check_all(root: Path | None = None) -> list[str]:
    root = root or common.ROOT
    problems: list[str] = []
    files = sorted((root / "lists").glob("*.txt"))
    if not files:
        problems.append("lists/: no list file found")
    across: dict[str, str] = {}
    for path in files:
        hosts, found = common.read_hosts(path)
        problems.extend(found)
        for host in hosts:
            if host in across:
                problems.append(f"{path.name}: {host} is already in {across[host]}")
            across.setdefault(host, path.name)
    problems.extend(check_sources(root / "lists" / "sources.json"))
    problems.extend(check_plugins(root / "plugins" / "index.json"))
    return problems


def main() -> int:
    problems = check_all()
    for line in problems:
        print("PROBLEM", line)
    if problems:
        print(f"FAILED: {len(problems)} problem(s)")
        return 1
    total = sum(len(common.read_hosts(p)[0]) for p in common.list_files())
    print(f"OK: {len(common.list_files())} list file(s), {total} host(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
