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


This module only export a few high level function/method for AEAD construction 
based on chacha20 (xchacha20) stream cipher and Poly1305 MAC, and several convenient function/methods


## Example
```
import blackshirt.vodcha

fn main() {
	//provides random key, or generates one
	key := vodcha.random_key() or {return}

	//provides nonce with specific size, or generates one
	nonce := vodcha.random_nonce(24) or {return}
	
	// create chacha/xchacha stream cipher 
	cipher := vodcha.new_cipher(key, nonce)
	
	//provide additional data
	aad := 'test data'.bytes()

	//input plaintext to encrypt and authenticated
	input := 'vodcha was an aead-xchacha20-poly1305 library in vlang'.bytes()
	
	//encrypt and gets encrypted text and tag
	ciphertext, tag := cipher.aead_encrypt_and_build_tag(aad, input)
	//or using normal function operation
	//ciphertext, tag := vodcha.encrypt_and_build_tag(aad, key, nonce, input) or {return}
	
	println("Ciphertext: $ciphertext.bytestr()")
	println("Tag: $tag.bytestr()")
	
	//decryption 
	original_msg := cipher.decrypt_and_verify_tag(aad, ciphertext, tag) or { return }
	
	//or using function based operation
	//original_msg := vodcha.decrypt_and_verify_tag(aad, key, nonce, ciphertext, tag) or { return }
	
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