# Security Policy

## Reporting a weakness

If you find a way to get a bad list accepted, to forge or bypass the manifest signature, to make a list unblock something, or any other weakness in this repository, **do not open a public issue.**

Use GitHub Security Advisories:
https://github.com/Parad0x-Labs/vool-browser/security/advisories/new

We aim to acknowledge a report within 72 hours and to give a fix or a plan within 14 days.

Weaknesses in the VOOL app itself go to https://github.com/Parad0x-Labs/vool/security/advisories/new

## What counts

In scope:

- The list format and `tools/validate_lists.py` accepting something they should refuse
- `tools/build_manifest.py` or `tools/verify_manifest.py` accepting a changed, truncated or unsigned file as good
- Anything that lets content in this repository do more than block a site
- The CI workflows in `.github/workflows`

Out of scope:

- A harmful site that is simply not on a list yet. Open a **Report a harmful site** issue.
- A safe site blocked by mistake. Open a **Wrongly blocked site** issue.
- Weaknesses in third-party lists that are not caused by how they are used here.

## Promises this repository keeps

- The signing key's private half is never committed, never placed in CI, and never typed into an issue or a pull request.
- Every list change is reviewed by the maintainer before it is signed.
- A release is the manifest plus its signature. Without a valid signature VOOL keeps what it already has.
