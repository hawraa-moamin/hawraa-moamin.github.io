#!/usr/bin/env python3
"""
verify.py: independently check the signed CV without trusting the web page.

  pip install cryptography
  python verify.py                 # checks cv.pdf, manifest.json, manifest.sig, public_key.json in this folder
  python verify.py --pubkey-b64 <key you obtained from a separate channel>

Equivalent with OpenSSL 3.x and coreutils:
  openssl pkeyutl -verify -pubin -inkey public_key.pem -rawin -in manifest.json -sigfile manifest.sig
  sha256sum cv.pdf        # must equal the "sha256" field in manifest.json
"""
import argparse, base64, hashlib, json, pathlib, sys
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

HERE = pathlib.Path(__file__).resolve().parent
ap = argparse.ArgumentParser()
ap.add_argument("--pubkey-b64", help="override the published key with one obtained out of band")
args = ap.parse_args()

pub_b64 = args.pubkey_b64 or json.loads((HERE / "public_key.json").read_text())["public_key_base64"]
pk = Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64))
mbytes = (HERE / "manifest.json").read_bytes()
try:
    pk.verify((HERE / "manifest.sig").read_bytes(), mbytes)
    print("[ok]   signature on manifest.json is valid")
except InvalidSignature:
    sys.exit("[FAIL] signature does not match this public key")

m = json.loads(mbytes)
digest = hashlib.sha256((HERE / m["document"]).read_bytes()).hexdigest()
if digest != m["sha256"]:
    sys.exit(f"[FAIL] {m['document']} has been modified\n       expected {m['sha256']}\n       got      {digest}")
print(f"[ok]   {m['document']} matches the signed digest {digest}")
print(f"       signed by {m['subject']} at {m['signed_at']}")
