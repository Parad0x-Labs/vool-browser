# Reviewing a list change

Before a host is added:

1. **It is one site, not a platform.** `tools/validate_lists.py` refuses known shared endings and the never-block hosts, but a reviewer still checks that the host is not a service many unrelated people use.
2. **The harm is shown.** A public report, a scan result or a screenshot. An accusation alone is not enough.
3. **It is in scope.** Malware, sign-in theft, fraud. Not opinions, not competitors, not adult or political content.
4. **Nothing but block entries changed.** A pull request that touches `tools/`, `.github/` or `keys/` alongside a list change is split in two.

Before a public source is added to `lists/sources.json`:

1. Its licence allows redistribution inside an MIT-licensed product, and the licence text is linked.
2. It is maintained: recent updates and a way to report false blocks.
3. `licence_checked_on` is the day the reviewer read the licence.

Before a plugin is added to `plugins/index.json`: see `plugins/README.md`.

Removing a wrongly blocked host is always allowed and is done first, discussed after.
