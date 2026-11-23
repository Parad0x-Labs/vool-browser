<p align="center">
  <img src="docs/assets/vool-browser-banner.png" alt="VOOL Browser: signed block lists and plugins" width="100%" />
</p>

<h1 align="center">VOOL Browser</h1>

<p align="center"><strong>The block lists and plugins behind the browser built into <a href="https://github.com/Parad0x-Labs/vool">VOOL</a>.</strong><br />Checked on your computer. Signed before it ships. Nothing about your browsing leaves your machine.</p>

<p align="center">
  <a href="docs/UPDATES.md"><img src="https://img.shields.io/badge/lists-signed_Ed25519-eee8d5?style=for-the-badge&labelColor=1a1a1a" alt="Lists are signed with Ed25519" /></a>
  <a href="#what-the-lists-can-and-cannot-do"><img src="https://img.shields.io/badge/lists-block_only-eee8d5?style=for-the-badge&labelColor=1a1a1a" alt="Lists can only block" /></a>
  <a href="plugins/README.md"><img src="https://img.shields.io/badge/plugins-reviewed_and_pinned-eee8d5?style=for-the-badge&labelColor=1a1a1a" alt="Plugins are reviewed and pinned" /></a><br />
  <a href="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/checks.yml"><img src="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/checks.yml/badge.svg" alt="Checks" /></a> <a href="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/codeql.yml"><img src="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/codeql.yml/badge.svg" alt="CodeQL" /></a> <a href="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/security-audit.yml"><img src="https://github.com/Parad0x-Labs/vool-browser/actions/workflows/security-audit.yml/badge.svg" alt="Security audit" /></a> <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-eee8d5" alt="MIT license" /></a> <a href="https://github.com/Parad0x-Labs/vool"><img src="https://img.shields.io/badge/app-VOOL-eee8d5" alt="The VOOL app" /></a>
</p>

<p align="center"><a href="#how-an-update-reaches-a-computer"><strong>How it works</strong></a> · <a href="#report-a-site"><strong>Report a site</strong></a> · <a href="#browser-plugins"><strong>Plugins</strong></a> · <a href="#check-it-yourself"><strong>Check it yourself</strong></a> · <a href="SECURITY.md"><strong>Security</strong></a></p>

**VOOL's browser checks every address against block lists that live on your computer.** Your browsing is never sent to a server to be checked. This repository is where those lists are kept, reviewed and signed, and where browser plugins for VOOL are listed.

> **Status:** this is for the browser arriving with VOOL 0.8. The first signed release of the lists is not published yet; until it is, VOOL takes no list from here and blocks nothing with it.

## What is here

| Folder | What it holds |
| --- | --- |
| [`lists/`](lists) | The block lists: sites known to spread malware or steal sign-ins, one host per line. `sources.json` records every public list drawn on, with its licence. |
| [`manifest/`](manifest) | `manifest.json` records the exact size and SHA-256 of every file, and a serial that only goes up. `manifest.json.sig` is its signature. |
| [`keys/`](keys) | The public key that signatures are checked against. The private key is never in this repository. |
| [`plugins/`](plugins) | The "Web browser" plugin category: the index of browser plugins VOOL can offer, and the rules a plugin must meet. |
| [`tools/`](tools) | The scripts that validate lists, build the manifest and verify it. CI runs the same scripts. |
| [`docs/`](docs) | How an update is checked, and how a change is reviewed. |

## How an update reaches a computer

1. A change to a list is proposed here and reviewed.
2. CI validates every line and checks that the manifest matches the files.
3. The maintainer signs the manifest with a key that never leaves their hands.
4. Once a day, and only after the person has switched the browser on, VOOL downloads the manifest and the lists.
5. VOOL takes them only if the signature matches the key built into VOOL, the release is not older than the one it holds, and every file matches its size and SHA-256. Anything else is discarded and the lists already on the computer stay in force.

The download is the same whole file for everyone. It shows that a copy of VOOL asked for an update, and nothing about which sites anyone visits. With a private route switched on in VOOL, the update uses that route too. The full rules are in [docs/UPDATES.md](docs/UPDATES.md).

## What the lists can and cannot do

- A list can only **block**. Nothing in this repository can unblock a site, turn a protection off, or change any other VOOL setting.
- A blocked site shows a warning. The person can still choose to open it, one site at a time, until they close the browser.
- VOOL's own agent never opens a listed site, whatever the person chose for themselves.
- Some hosts can never be blocked, whoever signed the list: the place the lists come from, and large shared platforms that one bad page must not take down.

## Report a site

- A harmful site that is not blocked: open a [**Report a harmful site**](https://github.com/Parad0x-Labs/vool-browser/issues/new?template=harmful-site.yml) issue.
- A safe site that is blocked by mistake: open a [**Wrongly blocked site**](https://github.com/Parad0x-Labs/vool-browser/issues/new?template=wrongly-blocked.yml) issue. A wrongly blocked host is removed first and discussed after.
- A weakness in the lists, the signing or the tools: see [SECURITY.md](SECURITY.md). Please do not open a public issue for those.

What gets a site listed, and what never does, is in [docs/REVIEW.md](docs/REVIEW.md) and [CONTRIBUTING.md](CONTRIBUTING.md).

## Browser plugins

A browser plugin for VOOL is an ordinary browser extension in a VOOL plugin package. It is reviewed, installed, switched on and removed like every other VOOL plugin, and VOOL refuses one that asks for saved sign-ins, the browser's connection or programs outside the browser. You can make your own inside VOOL (**Add-ons → Plugins → Make a browser plugin**). What a listed plugin must meet: [plugins/README.md](plugins/README.md).

## Check it yourself

```
python -m pip install -r requirements.txt
python tools/validate_lists.py
python tools/build_manifest.py --check
python tools/verify_manifest.py
python -m pytest tests -q
```

`python tools/verify_manifest.py --require-signature` checks a release the way VOOL does: the signature first, then every file.

## Explore

| Topic | Start here |
| --- | --- |
| **Understand it** | [How updates are checked](docs/UPDATES.md) · [The public key](keys/README.md) |
| **Take part** | [Contributing](CONTRIBUTING.md) · [How changes are reviewed](docs/REVIEW.md) · [Plugin rules](plugins/README.md) |
| **Trust** | [Security policy](SECURITY.md) · [Checks](https://github.com/Parad0x-Labs/vool-browser/actions/workflows/checks.yml) · [CodeQL](https://github.com/Parad0x-Labs/vool-browser/actions/workflows/codeql.yml) · [MIT license](LICENSE) |
| **The app** | [VOOL](https://github.com/Parad0x-Labs/vool) |

Lists taken from other projects keep their own licences, which `lists/sources.json` records.

---

<p align="center">Built by <a href="https://github.com/Parad0x-Labs"><strong>Parad0x Labs</strong></a> · Part of <a href="https://github.com/Parad0x-Labs/vool"><strong>VOOL</strong></a></p>
