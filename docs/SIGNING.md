# Signing a release

Only the maintainer does this, on their own computer. The private key never enters this repository, CI, an issue or a chat.

## Once: make the key

```
python -m pip install -r requirements.txt
python tools/sign_manifest.py --new-key <a path outside this repository>
```

This writes the private key to the path you gave, readable by you only, and writes the public key to `keys/release.pub`. Commit `keys/release.pub`. Back the private key up somewhere safe and offline: without it, no further update can be signed, and VOOL will keep the last lists it accepted.

The same public key must be built into VOOL. A list signed with any other key is refused.

## Each release

```
git checkout main && git pull
python tools/validate_lists.py
python tools/build_manifest.py
python tools/sign_manifest.py --key <the path of your private key>
python tools/verify_manifest.py --require-signature
git add manifest/manifest.json manifest/manifest.json.sig
git commit -m "Release serial <number>"
git push origin main
git push origin main:published
```

`sign_manifest.py` refuses to sign when the key does not match `keys/release.pub`, when the key path is inside the repository, or when the manifest does not match the files.

## If the key is lost or exposed

Tell users through a VOOL release: the new public key ships inside the next VOOL version, and lists signed with the old key stop being accepted from that version on. Do not publish a "new key" through this repository alone; nothing here can replace the key VOOL trusts.
