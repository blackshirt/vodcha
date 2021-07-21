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

## Run the tests

```bash
cd vodcha
v -stats test .
```

## Install from vpm

```bash
v install blackshirt.vodcha
```
and then import in your module 
`import blackshirt.vodcha`


## Example

```
import blackshirt.vodcha

fn main() {
	//provides random key, or generates one
	key := vodcha.gen_random_key() or {return}

	//provides nonce with specific size, or generates one
	nonce := vodcha.gen_random_nonce(24) or {return}

	//provide additional data
	aad := 'test data'.bytes()
	//input plaintext to encrypt and authenticated
	input := 'vodcha was an aead-xchacha20-poly1305 library in vlang'
	//convert input to bytes
	plaintext := input.bytes()

	//encrypt and gets encrypted text and tag
	ciphertext, tag := vodcha.encrypt_and_buildtag(aad, key, nonce, plaintext) or {return}
	println("Ciphertext: $ciphertext.bytestr()")
	println("Tag: $tag.bytestr()")
	
	//decryption 
	original_msg := vodcha.decrypt_and_verify(key, nonce, ciphertext, tag, aad) or { return }
	println("Original msg: $input")
	println("Decrypted from ciphertext: $original_msg.bytestr()")
}
```

output
```bash
$ v run main.v 
Ciphertext: �I�}t;v��?U�O�gE�M�bq��\��H�        ��a--W��(-%�lh���,v1
Tag: U�hd��G�߭>)܇_
Original msg: vodcha was an aead-xchacha20-poly1305 library in vlang
Decrypted from ciphertext: vodcha was an aead-xchacha20-poly1305 library in vlang
```