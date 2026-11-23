# Keys

`release.pub` holds the public key that list signatures are checked against: one line, an Ed25519 public key in base64. It appears here when the first signed release is published. The same key is built into VOOL, and VOOL never takes its key from the network: the copy here is for anyone who wants to check a release by hand.

```
python -m pip install -r requirements.txt
python tools/verify_manifest.py --require-signature
```

The private key is never in this repository, in CI, in an issue or in a chat. If it is ever lost or exposed, the new public key ships inside the next VOOL version; nothing published here can replace the key VOOL trusts.
