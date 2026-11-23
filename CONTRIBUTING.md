# Contributing

Thank you for helping keep people safe.

## Adding a harmful site

The quickest way is a **Report a harmful site** issue. To propose the change yourself:

1. Add the host to `lists/vool-block.txt`: lower case, one per line, no `http://`, no path. Keep the file sorted.
2. Add one line to the pull request saying what the site does and how you know (a public report, a screenshot, a scan result). Do not paste stolen data or working malware links.
3. Run `python tools/validate_lists.py` and `python -m pytest tests -q`.

Do not edit `manifest/manifest.json` by hand. CI rebuilds it and the maintainer signs it.

## What will not be merged

- A host that is a whole shared platform (a code host, a mail provider, a cloud storage service) because one page on it is bad. Report the page to that platform instead.
- A site listed for its opinions, its politics or its competition with anyone. The lists cover malware, sign-in theft and fraud.
- Anything that is not a block entry: no allow rules, no settings, no scripts in list files.
- A new public source without its licence recorded in `lists/sources.json`.

## Browser plugins

See `plugins/README.md` for what a plugin entry needs.

## Commits

Keep commits small and say what changed and why. Never commit a key, a token, a password, or a path from your own computer.
