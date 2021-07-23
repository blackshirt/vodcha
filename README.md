# vodcha

## (X)ChaCha20 and Poly1305 in V Language (RFC 8439)

This module implements algorithms specified in rfc:

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


This module only exports a few high level function/methods for AEAD construction 
using chacha20 (xchacha20) stream cipher and Poly1305 MAC primitives, 
and several convenient function/methods to make life easier.


## Example
```
import blackshirt.vodcha

fn main() {
	// provides with 32 bytes random key, or generates one
	key := vodcha.random_key() or {return}

	// provides nonce with specific size, 
	// allowed nonce size was 12 for chacha20 and 24 for xchacha20
	// or generates one using `random_nonce(size)
	nonce := vodcha.random_nonce(24) or {return}
	
	// create chacha20/xchacha20 stream cipher 
	mut cipher := vodcha.new_cipher(key, nonce) or {return}
	
	//provides arbitrary-length additional authenticated data
	aad := 'test data'.bytes()

	// input message to encrypt and authenticated
	input := 'vodcha was an aead-xchacha20-poly1305 library in vlang'.bytes()
	
	// do encrypt and gets encrypted text and authenticated tag
	ciphertext, tag := cipher.aead_encrypt_and_build_tag(aad, input) or {return}
	// or using normal function operation
	//ciphertext, tag := vodcha.encrypt_and_build_tag(aad, key, nonce, input) or {return}
	
	println("Ciphertext: $ciphertext.bytestr()")
	println("Tag: $tag.bytestr()")
	
	//decryption 
	original_msg := cipher.aead_decrypt_and_verify_tag(aad, ciphertext, tag) or { return }
	
	//or using normal function based operation
	//original_msg := vodcha.decrypt_and_verify_tag(aad, key, nonce, ciphertext, tag) or { return }
	
	println("Original msg: $input.bytestr()")
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