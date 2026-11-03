# Hawraa Moamin · signed CV

Live page: https://hawraa-moamin.github.io/

`cv.pdf` is signed with Ed25519. The page checks the signature and the PDF's SHA-256 digest in your browser using the Web Crypto API.

| File | Purpose |
|---|---|
| `cv.pdf` | the CV |
| `manifest.json` | signed statement: signer, file name, size, SHA-256 digest, time |
| `manifest.sig` | 64-byte Ed25519 signature over the exact bytes of `manifest.json` |
| `public_key.json`, `public_key.pem` | verification key (fingerprint `5b02:de76:4518:28e2:4547:dee6:f13b:ba19`) |
| `verify.py` | independent verifier (Python) |
| `sign.py` | how the files were produced; the private key is never in this repo |

Verify without the web page:

```bash
openssl pkeyutl -verify -pubin -inkey public_key.pem -rawin -in manifest.json -sigfile manifest.sig
sha256sum cv.pdf   # must equal "sha256" in manifest.json
```
