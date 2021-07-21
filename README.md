# vodcha

# ChaCha20 and Poly1305 in V Language (RFC 8439)

This module implements three algorithms specified in rfc:

1. ChaCha20 stream cipher encryption algoritm, and Extended Chacha20 (XChaCha20) as specified in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
2. Poly1305 cryptographic message authentication code, and,
3. Authenticated Encryption with Associated Data (AEAD) construction using chacha20 and poly1305 library provided

Its references based on RFC 8439 at https://datatracker.ietf.org/doc/html/rfc8439 and inspired mostly by python version at https://github.com/tex2e/chacha20-poly1305

## Clone

```bash
git clone https://github.com/blackshirt/vodcha.git
```

## Unit Tests

```bash
v -stats test .
```

# module vodcha

## Contents

- [ietf_chacha20_block](#ietf_chacha20_block)
- [chacha20_encrypt](#chacha20_encrypt)
- [chacha20_decrypt](#chacha20_decrypt)
- [poly1305_key_generator](#poly1305_key_generator)
- [poly1305_mac](#poly1305_mac)
- [encrypt_and_tag](#encrypt_and_tag)
- [decrypt_and_verify](#decrypt_and_verify)

## ietf_chacha20_block

```v
fn ietf_chacha20_block(key []byte, counter u32, nonce []byte) ?[]byte
```

`ietf_chacha20_block` generate block/key stream

## chacha20_encrypt

```v
fn chacha20_encrypt(key []byte, counter u32, nonce []byte, plaintext []byte) ?[]byte
```

`chacha20_encrypt` generate encrypted message from plaintext using chacha 20 round algorithm specified in rfc8439

## chacha20_decrypt

```v
fn chacha20_decrypt(key []byte, counter u32, nonce []byte, ciphertext []byte) ?[]byte
```

`chacha20_decrypt` do opposite of encrypt

## poly1305_key_generator

```v
fn poly1305_key_generator(key []byte, nonce []byte) ?[]byte
```

`poly1305_key_generator` generate poly1305 one time key using `ietf_chacha20_block` function https://datatracker.ietf.org/doc/html/rfc8439#section-2.6 Generating the Poly1305 Key Using ChaCha20

## poly1305_mac

```v
fn poly1305_mac(msg []byte, key []byte) []byte
```

`poly1305_mac` was poly1305 mac algorithms specified in https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.1

## encrypt_and_tag

```v
fn encrypt_and_tag(aad []byte, key []byte, nonce []byte, plaintext []byte) ?([]byte, []byte)
```

`encrypt_and_tag` encrypt the plaintext using chacha20-poly1305 and return ciphertext and the tag

## decrypt_and_verify

```v
fn decrypt_and_verify(key []byte, nonce []byte, ciphertext []byte, mac []byte, aad []byte) ?[]byte
```

`decrypt_and_verify` doing decryption of ciphertext and verify the tag's validity
