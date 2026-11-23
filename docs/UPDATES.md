# How list updates work

## Two branches

- `main` is where changes are proposed and reviewed. Its manifest always matches its files; CI refuses anything else. It may be unsigned for a short time after a change.
- `published` is what VOOL downloads. Only the maintainer moves it, and only to a commit whose manifest carries a valid signature. CI on `published` fails without one.

## What VOOL does with an update

1. Once a day, and only after the person has switched the browser on, VOOL downloads `manifest/manifest.json` and `manifest/manifest.json.sig` from `published`.
2. It checks the signature over the exact manifest bytes against the public key that shipped inside VOOL. The key in this repository is for people checking by hand; VOOL does not take its key from the network.
3. It refuses a manifest whose `serial` is lower than the one it already holds. An old signed manifest cannot be replayed to bring back an old list.
4. It downloads each listed file and checks its size and SHA-256.
5. Only when every check passes does it swap the new lists in, all at once. On any failure it keeps the lists it has and tries again the next day.

`tools/verify_manifest.py --require-signature` runs steps 2 and 4 the same way, so anyone can check a release by hand.

## What an update can contain

Block entries, the record of public sources, and the plugin index. Nothing else is read. An update cannot unblock a site, change a setting, or run code.

## Privacy

Everyone downloads the same whole files. The request shows that a copy of VOOL asked for an update. It carries no identifier and nothing about the sites anyone visits. When the person has switched on a private route in VOOL, the update uses that route too.
