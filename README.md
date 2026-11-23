# VOOL Browser

Protection data and plugins for the browser built into [VOOL](https://github.com/Parad0x-Labs/vool).

VOOL's browser checks every address against block lists that live **on your computer**. Your browsing is never sent to a server to be checked. This repository is where those lists are kept, reviewed and signed, and where browser plugins for VOOL are listed.

## What is here

| Folder | What it holds |
| --- | --- |
| `lists/` | The block lists: sites known to spread malware or steal sign-ins, one host per line. `sources.json` names the public lists VOOL also draws on, each with its licence. |
| `manifest/` | `manifest.json` records the exact SHA-256 and size of every list. `manifest.json.sig` is its signature. |
| `keys/` | The public key that signatures are checked against. The private key is never in this repository. |
| `plugins/` | The "Web browser" plugin category: an index of browser plugins VOOL can offer, and the rules a plugin must meet. |
| `tools/` | The scripts that validate lists, build the manifest, and verify it. CI runs the same scripts. |
| `docs/` | How updates, signing and reviews work. |

## How an update reaches a computer

1. A change to a list is proposed here and reviewed.
2. CI validates every line and rebuilds the manifest.
3. The maintainer signs the manifest with a key that never leaves their hands.
4. Once a day, and only after the person has switched the browser on, VOOL downloads the manifest and the lists.
5. VOOL accepts them only if the signature is valid and every file matches its SHA-256. Anything else is discarded and the lists already on the computer stay in force.

The download is the same whole file for everyone. It shows that a copy of VOOL asked for an update, and nothing about which sites anyone visits.

## What the lists can and cannot do

- A list can only **block**. Nothing in this repository can unblock a site, turn a protection off, or change any other VOOL setting.
- A blocked site shows a warning. The person can still choose to continue, one site at a time.
- A list is never the only protection. The browser's own checks for unsafe connections and lookalike addresses stay on.

## Report a site

- A harmful site that is not blocked: open a **Report a harmful site** issue.
- A safe site that is blocked by mistake: open a **Wrongly blocked site** issue.
- A weakness in the lists, the signing or the tools: see [SECURITY.md](SECURITY.md). Please do not open a public issue for those.

## Check it yourself

```
python -m pip install -r requirements.txt
python tools/validate_lists.py
python tools/build_manifest.py --check
python tools/verify_manifest.py
python -m pytest tests -q
```

## Licence

MIT. See [LICENSE](LICENSE). Lists taken from other projects keep their own licences, which `lists/sources.json` records.
