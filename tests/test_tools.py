"""The tools must refuse what VOOL must never accept, and pass the repository as committed."""
from __future__ import annotations

import base64
import hashlib
import json
import shutil
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))

import build_manifest  # noqa: E402
import common  # noqa: E402
import scan_repo  # noqa: E402
import validate_lists  # noqa: E402
import verify_manifest  # noqa: E402


@pytest.fixture
def repo(tmp_path):
    """A small, valid copy of the repository layout with two blocked hosts."""
    root = tmp_path / "repo"
    (root / "lists").mkdir(parents=True)
    (root / "plugins").mkdir()
    (root / "manifest").mkdir()
    (root / "keys").mkdir()
    (root / "lists" / "vool-block.txt").write_text("# note\nbad-shop.example-malware.com\nfake-bank-login.net\n")
    (root / "lists" / "sources.json").write_text(json.dumps({"schema": "vool.browser.sources.v1", "sources": []}))
    (root / "plugins" / "index.json").write_text(json.dumps({"schema": "vool.browser.plugins.v1", "category": "web-browser", "plugins": []}))
    return root


def write_manifest(root: Path, serial: int = 1) -> bytes:
    files = []
    for path in [*sorted((root / "lists").glob("*.txt")), root / "lists" / "sources.json", root / "plugins" / "index.json"]:
        raw = path.read_bytes()
        files.append({"path": path.relative_to(root).as_posix(), "sha256": hashlib.sha256(raw).hexdigest(), "bytes": len(raw)})
    data = common.canonical({"schema": common.MANIFEST_SCHEMA, "serial": serial, "generated": "2026-01-01T00:00:00Z", "files": files})
    (root / "manifest" / "manifest.json").write_bytes(data)
    return data


def sign(root: Path, data: bytes, key=None):
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = key or Ed25519PrivateKey.generate()
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    (root / "keys" / "release.pub").write_text(base64.b64encode(public).decode() + "\n")
    (root / "manifest" / "manifest.json.sig").write_text(base64.b64encode(key.sign(data)).decode() + "\n")
    return key


# -- what a list may hold ---------------------------------------------------------


@pytest.mark.parametrize("host", ["fake-bank-login.net", "a.b.c.example-malware.com", "xn--80ak6aa92e.com", "evil.co.uk"])
def test_a_plain_public_host_is_accepted(host):
    assert common.host_problem(host) is None


@pytest.mark.parametrize("host", [
    "", " padded.com", "Upper.com", "http://site.com", "site.com/path", "site.com:8080", "*.site.com",
    "user@" + "site.com", "10.0." + "0.1", "2001:db8::1", "com", "localhost", "printer.local", "router.lan",
    "thing.internal", "hidden.onion", "site.test", "co.uk", "github.io", "amazonaws.com",
    "github.com", "raw.githubusercontent.com", "evil.github.com", "mail.google.com", "googleusercontent..com",
    "-dash.com", "dash-.com", "under_score.com", "caf\u00e9.com", "a" * 64 + ".com", "site.123",
])
def test_anything_else_is_refused_with_a_reason(host):
    assert common.host_problem(host)


def test_a_list_cannot_cut_off_the_updates_of_the_lists_themselves():
    for host in ("github.com", "githubusercontent.com", "raw.githubusercontent.com", "objects.githubusercontent.com"):
        assert "never-block" in common.host_problem(host)


@pytest.mark.parametrize("body, word", [
    ("b.com\na.com\n", "sorted"),
    ("a.com\na.com\n", "twice"),
    ("a.com\n\nb.com\n", "empty line"),
    ("a.com", "line break"),
    ("a.com\r\nb.com\r\n", "Windows"),
    ("a.com\nhttp://b.com\n", "bare host"),
    ("a.com\n<script>alert(1)</script>\n", "bare host"),
    ("caf\u00e9.com\n", "ASCII"),
])
def test_a_malformed_list_file_is_refused(repo, body, word):
    (repo / "lists" / "vool-block.txt").write_bytes(body.encode("utf-8"))
    problems = validate_lists.check_all(repo)
    assert any(word in line for line in problems), problems


def test_the_same_host_in_two_lists_is_refused(repo):
    (repo / "lists" / "second.txt").write_text("fake-bank-login.net\n")
    assert any("already in" in line for line in validate_lists.check_all(repo))


def test_a_valid_layout_passes(repo):
    assert validate_lists.check_all(repo) == []


# -- sources and plugins ----------------------------------------------------------


GOOD_SOURCE = {"id": "public-feed", "name": "Public feed", "url": "https://feed.example.org/hosts.txt", "format": "hosts",
               "licence": "CC0-1.0", "licence_url": "https://feed.example.org/licence", "licence_checked_on": "2026-01-31"}
GOOD_PLUGIN = {"id": "example-blocker", "name": "Example Blocker", "summary": "Blocks adverts.", "homepage": "https://example.org/b",
               "licence": "GPL-3.0", "version": "1.2.3", "package_url": "https://example.org/b-1.2.3.zip",
               "package_sha256": "a" * 64, "permissions": ["declarativeNetRequest"], "reviewed_on": "2026-01-31"}


def _sources(repo, *items):
    (repo / "lists" / "sources.json").write_text(json.dumps({"schema": "vool.browser.sources.v1", "sources": list(items)}))
    return validate_lists.check_all(repo)


def _plugins(repo, *items):
    (repo / "plugins" / "index.json").write_text(json.dumps({"schema": "vool.browser.plugins.v1", "category": "web-browser", "plugins": list(items)}))
    return validate_lists.check_all(repo)


def test_a_source_with_its_licence_recorded_passes(repo):
    assert _sources(repo, GOOD_SOURCE) == []


@pytest.mark.parametrize("change", [
    {"licence": ""}, {"licence_checked_on": "last week"}, {"url": "http://feed.example.org/hosts.txt"},
    {"format": "script"}, {"id": "Has Spaces"}, {"extra": "field"},
])
def test_a_source_without_a_checked_licence_or_with_a_plain_address_is_refused(repo, change):
    assert _sources(repo, {**GOOD_SOURCE, **change})


def test_two_sources_cannot_share_an_id(repo):
    assert _sources(repo, GOOD_SOURCE, GOOD_SOURCE)


def test_a_reviewed_pinned_plugin_passes(repo):
    assert _plugins(repo, GOOD_PLUGIN) == []


@pytest.mark.parametrize("change", [
    {"package_sha256": "abc"}, {"package_sha256": "A" * 64}, {"package_url": "http://example.org/b.zip"},
    {"permissions": ["nativeMessaging"]}, {"permissions": ["declarativeNetRequest", "debugger"]},
    {"permissions": "all"}, {"version": "latest"}, {"reviewed_on": ""}, {"licence": ""}, {"install_script": "curl | sh"},
])
def test_a_plugin_that_is_unpinned_overreaching_or_unreviewed_is_refused(repo, change):
    assert _plugins(repo, {**GOOD_PLUGIN, **change})


@pytest.mark.parametrize("body", ["not json", "[]", json.dumps({"schema": "other"})])
def test_a_broken_sources_or_plugin_file_is_refused(repo, body):
    (repo / "lists" / "sources.json").write_text(body)
    (repo / "plugins" / "index.json").write_text(body)
    assert len(validate_lists.check_all(repo)) == 2


# -- the manifest and its signature -----------------------------------------------


def test_an_unsigned_manifest_is_reported_and_refused_where_a_signature_is_required(repo):
    write_manifest(repo)
    code, lines = verify_manifest.verify(repo, require_signature=False)
    assert code == 0 and lines[0].startswith("UNSIGNED")
    code, lines = verify_manifest.verify(repo, require_signature=True)
    assert code == 1 and "refused" in lines[-1]


def test_a_signed_manifest_that_matches_every_file_is_accepted(repo):
    sign(repo, write_manifest(repo))
    code, lines = verify_manifest.verify(repo, require_signature=True)
    assert code == 0 and lines[0].startswith("SIGNED"), lines


def test_one_changed_byte_in_a_list_is_refused_even_with_a_valid_signature(repo):
    sign(repo, write_manifest(repo))
    path = repo / "lists" / "vool-block.txt"
    path.write_text(path.read_text().replace("fake-bank-login.net", "fake-bank-login.org"))
    code, lines = verify_manifest.verify(repo, require_signature=True)
    assert code == 1 and any("SHA-256 differs" in line for line in lines)


def test_a_manifest_edited_after_signing_is_refused(repo):
    data = write_manifest(repo)
    sign(repo, data)
    (repo / "manifest" / "manifest.json").write_bytes(data.replace(b'"serial": 1', b'"serial": 9'))
    code, lines = verify_manifest.verify(repo, require_signature=False)
    assert code == 1 and lines[0].startswith("BAD")


def test_a_signature_from_another_key_is_refused(repo):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    data = write_manifest(repo)
    sign(repo, data)
    other = Ed25519PrivateKey.generate()
    (repo / "manifest" / "manifest.json.sig").write_text(base64.b64encode(other.sign(data)).decode() + "\n")
    assert verify_manifest.verify(repo, require_signature=False)[0] == 1


@pytest.mark.parametrize("sig", ["", "not base64 !!", base64.b64encode(b"short").decode()])
def test_a_damaged_signature_file_is_refused_not_treated_as_unsigned(repo, sig):
    sign(repo, write_manifest(repo))
    (repo / "manifest" / "manifest.json.sig").write_text(sig)
    code, lines = verify_manifest.verify(repo, require_signature=False)
    assert code == 1 and lines[0].startswith("BAD")


def test_a_signature_with_no_published_key_is_refused(repo):
    sign(repo, write_manifest(repo))
    (repo / "keys" / "release.pub").unlink()
    assert verify_manifest.verify(repo, require_signature=False)[0] == 1


def test_a_list_file_the_manifest_does_not_name_is_refused(repo):
    sign(repo, write_manifest(repo))
    (repo / "lists" / "slipped-in.txt").write_text("extra-site.com\n")
    code, lines = verify_manifest.verify(repo, require_signature=True)
    assert code == 1 and any("not in the manifest" in line for line in lines)


def test_a_missing_or_truncated_file_is_refused(repo):
    sign(repo, write_manifest(repo))
    (repo / "lists" / "vool-block.txt").write_text("# note\n")
    assert verify_manifest.verify(repo, require_signature=True)[0] == 1
    (repo / "lists" / "vool-block.txt").unlink()
    code, lines = verify_manifest.verify(repo, require_signature=True)
    assert code == 1 and any("missing" in line for line in lines)


@pytest.mark.parametrize("path", ["../outside.txt", "/etc/hosts", "lists/../../outside.txt"])
def test_a_manifest_cannot_point_outside_the_repository(repo, path):
    (repo.parent / "outside.txt").write_text("x")
    data = common.canonical({"schema": common.MANIFEST_SCHEMA, "serial": 1, "generated": "2026-01-01T00:00:00Z",
                             "files": [{"path": path, "sha256": hashlib.sha256(b"x").hexdigest(), "bytes": 1}]})
    (repo / "manifest" / "manifest.json").write_bytes(data)
    sign(repo, data)
    assert verify_manifest.verify(repo, require_signature=True)[0] == 1


@pytest.mark.parametrize("body", [b"", b"not json", b"[]", b'{"schema": "vool.browser.manifest.v1", "serial": 0, "files": []}'])
def test_a_broken_manifest_is_refused(repo, body):
    (repo / "manifest" / "manifest.json").write_bytes(body)
    assert verify_manifest.verify(repo, require_signature=False)[0] == 1


def test_the_builder_raises_the_serial_only_when_a_file_changed(repo, monkeypatch):
    for name, value in (("ROOT", repo), ("LISTS", repo / "lists"), ("MANIFEST", repo / "manifest" / "manifest.json")):
        monkeypatch.setattr(common, name, value)
    assert build_manifest.main([]) == 0 and json.loads(common.MANIFEST.read_text())["serial"] == 1
    assert build_manifest.main([]) == 0 and json.loads(common.MANIFEST.read_text())["serial"] == 1
    assert build_manifest.main(["--check"]) == 0
    (repo / "lists" / "vool-block.txt").write_text("# note\nbad-shop.example-malware.com\n")
    assert build_manifest.main(["--check"]) == 1
    assert build_manifest.main([]) == 0 and json.loads(common.MANIFEST.read_text())["serial"] == 2
    assert verify_manifest.verify(repo, require_signature=False)[0] == 0


# -- the repository scanner -------------------------------------------------------


@pytest.mark.parametrize("line, name", [
    ("-----BEGIN OPENSSH " + "PRIVATE KEY-----", "private key block"),
    ("token = ghp_" + "a" * 36, "token"),
    ('api_key = "' + "k" * 20 + '"', "secret assignment"),
    ("see /Users/" + "somebody/notes.txt", "home folder path"),
    ("C:\\Users\\" + "somebody\\file", "home folder path"),
    ("/Volumes/" + "DRIVE/work", "mounted drive path"),
    ("server at 192.168." + "1.20", "private network address"),
    ("write to someone@" + "example.org", "email address"),
])
def test_the_scanner_finds_secrets_and_personal_paths_without_printing_them(tmp_path, line, name):
    path = tmp_path / "file.md"
    path.write_text("fine\n" + line + "\n")
    findings = scan_repo.scan([path], tmp_path)
    assert findings == [f"file.md:2: {name}"]


def test_the_scanner_passes_ordinary_text(tmp_path):
    path = tmp_path / "file.md"
    path.write_text("Blocked hosts are listed one per line.\nSee https://github.com/Parad0x-Labs/vool-browser\n")
    assert scan_repo.scan([path], tmp_path) == []


# -- the repository as committed --------------------------------------------------


def test_the_committed_repository_passes_its_own_checks():
    assert validate_lists.check_all(ROOT) == []
    assert build_manifest.problems(build_manifest.load(common.MANIFEST), common.manifest_files()) == []
    code, lines = verify_manifest.verify(ROOT, require_signature=False)
    assert code == 0, lines
    assert scan_repo.scan(scan_repo.tracked_files(ROOT), ROOT) == []
