# Web browser plugins

This is the "Web browser" category of VOOL's plugin list. A plugin here adds something to the browser built into VOOL, for example an ad blocker.

`index.json` is the list VOOL reads. It starts empty: a plugin is added only after review.

## What an entry holds

```json
{
  "id": "example-blocker",
  "name": "Example Blocker",
  "summary": "Blocks adverts and trackers.",
  "homepage": "https://example.org/blocker",
  "licence": "GPL-3.0",
  "version": "1.2.3",
  "package_url": "https://example.org/blocker-1.2.3.zip",
  "package_sha256": "<64 hex characters>",
  "permissions": ["declarativeNetRequest"],
  "reviewed_on": "2026-01-31"
}
```

## Rules

- The package is pinned by version and SHA-256. VOOL installs exactly those bytes or nothing.
- Every permission the plugin asks for is listed, and VOOL shows the list to the person before they add it.
- A plugin is off until the person adds it. Nothing here is installed by default.
- A plugin may not read saved sign-ins, may not change the browser's connection or safety settings, may not start programs outside the browser, may not save files by itself, and may not load code or updates from the network after install.
- A plugin never runs in a private window.
- Open source only, with the licence named.

`tools/validate_lists.py` checks every entry against these rules.

## What a plugin package is

A browser plugin is an ordinary VOOL plugin that carries a standard browser extension, version 3 of the format the major browsers share:

```
example-blocker/
  .codex-plugin/plugin.json   name, version, kind ["browser"], "browser": {"extension": "extension"}
  extension/manifest.json     which pages it works on and what it asks the browser for
  extension/...               the extension's own files
  LICENSE
```

VOOL reviews, installs, enables and removes it in the Plugins section like any other plugin, in the "Web browser" group.

## Making your own

You do not need this list to use your own plugin. In VOOL, open Plugins and use "Make a browser plugin": it writes a small working plugin into a folder on your computer. Change it, then review and install the folder under "Install from a folder".
