#!/usr/bin/env python3
"""
sign.py: sign cv.pdf with an Ed25519 key (hash-then-sign, via a signed manifest).

What it does
  1. Computes SHA-256(cv.pdf).
  2. Writes manifest.json, a small statement that names the file, its digest,
     its size, the signer and the time.
  3. Signs the exact bytes of manifest.json with Ed25519 -> manifest.sig (64 raw bytes).
  4. Publishes the public key -> public_key.json and public_key.pem.

The private key never goes in the website folder. By default it lives in
../PRIVATE_KEEP_OFFLINE/signing_key.pem (outside the repo, and .gitignore blocks *.pem keys).

Usage
  pip install cryptography
  python sign.py              # re-sign cv.pdf with your existing key
  python sign.py --new-key    # create a brand-new key pair first (do this once, on your own computer)
"""
import argparse, base64, datetime, hashlib, json, pathlib, sys
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

HERE = pathlib.Path(__file__).resolve().parent
DEFAULT_KEY = HERE.parent / "PRIVATE_KEEP_OFFLINE" / "signing_key.pem"

SUBJECT = "Hawraa Moamin"
CONTACT = "hawraa.a.moamin@gmail.com"


def fingerprint(raw_pub: bytes) -> str:
    """First 128 bits of SHA-256(raw public key), in groups of 4 hex digits."""
    h = hashlib.sha256(raw_pub).hexdigest()[:32]
    return ":".join(h[i:i + 4] for i in range(0, 32, 4))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--key", type=pathlib.Path, default=DEFAULT_KEY, help="path to the PRIVATE key (keep it out of the repo)")
    ap.add_argument("--new-key", action="store_true", help="generate a new Ed25519 key pair first")
    ap.add_argument("--doc", default="cv.pdf")
    args = ap.parse_args()

    if args.new_key:
        if args.key.exists():
            sys.exit(f"{args.key} already exists; move it away first if you really want a new key.")
        args.key.parent.mkdir(parents=True, exist_ok=True)
        sk = Ed25519PrivateKey.generate()
        args.key.write_bytes(sk.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
        args.key.chmod(0o600)
        print(f"new private key -> {args.key}  (never upload this)")
    sk = serialization.load_pem_private_key(args.key.read_bytes(), password=None)
    pk = sk.public_key()
    raw_pub = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)

    doc = (HERE / args.doc).read_bytes()
    manifest = {
        "type": "signed-cv/v1",
        "subject": SUBJECT,
        "contact": CONTACT,
        "document": args.doc,
        "sha256": hashlib.sha256(doc).hexdigest(),
        "bytes": len(doc),
        "signed_at": datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        "signature_algorithm": "Ed25519",
        "key_fingerprint": fingerprint(raw_pub),
        "statement": f"I, {SUBJECT}, attest that the file named above, identified by its SHA-256 digest, is my current CV.",
    }
    mbytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode()
    (HERE / "manifest.json").write_bytes(mbytes)
    (HERE / "manifest.sig").write_bytes(sk.sign(mbytes))  # 64 raw bytes

    (HERE / "public_key.json").write_text(json.dumps({
        "algorithm": "Ed25519",
        "public_key_base64": base64.b64encode(raw_pub).decode(),
        "fingerprint": fingerprint(raw_pub),
        "fingerprint_definition": "first 128 bits of SHA-256(raw 32-byte public key)",
    }, indent=2) + "\n")
    (HERE / "public_key.pem").write_bytes(pk.public_bytes(serialization.Encoding.PEM,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo))
    print("sha256(cv.pdf) =", manifest["sha256"])
    print("key fingerprint =", manifest["key_fingerprint"])
    print("wrote manifest.json, manifest.sig, public_key.json, public_key.pem")


if __name__ == "__main__":
    main()
