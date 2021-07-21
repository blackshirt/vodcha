## vodcha

# (X)ChaCha20 and Poly1305 in V Language (RFC 8439)

This module implements three algorithms specified in rfc:

1. ChaCha20 stream cipher encryption algorithm, based on https://datatracker.ietf.org/doc/html/rfc8439
2. eXtended Chacha20 (XChaCha20) construction as specified in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
3. Poly1305 cryptographic message authentication code, and,
4. Authenticated Encryption with Associated Data (AEAD) construction using (x)chacha20 and poly1305 library provided

Its references based on RFC 8439 at https://datatracker.ietf.org/doc/html/rfc8439 and inspired mostly by python version at https://github.com/tex2e/chacha20-poly1305

## Clone

```bash
git clone https://github.com/blackshirt/vodcha.git
```
## Install from vpm

```bash
v install blackshirt.vodcha
```
and then import in your module 
`import blackshirt.vodcha`

## Run the tests

```bash
v -stats test .
```

