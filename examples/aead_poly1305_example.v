module main 

import crypto.rand 
import blackshirt.vodcha


fn main() {
	// we use samples from previous chacha example,
	// first, provides 32 bytes random key needed this purposes
	// you can provide yourself, or using `random_key()` srom this module
	// its internally build with key_size size, aka 32 
	key := vodcha.random_key() or {return} 

	// then, we need some random nonce, you can provide one
	// or using `random_nonce(size)` where size either 12 or 24
	nonce := vodcha.random_nonce(12) or {return} 

	// create new cipher,
	mut cipher := vodcha.new_cipher(key, nonce) or {return}

	// provides with additional (authenticated) data hat should be authenticated with the key, 
	// but does not need to be encrypted. you can provide your self, or for example, generates
	// it randomly
	aad := rand.read(64) or {return}
	println("aad : $aad.hex()")
	// provides input message want to encrypted and authenticated 
	msg := 'This is message want to send to you'.bytes()

	ciphertext, tag := cipher.aead_encrypt_and_build_tag(msg, aad) or {return}

	println("Ciphertext result in hex form: $ciphertext.hex()")
	println("tag result in hex form: $tag.hex()")

	// lets doing decryption of ciphertext from previous encrypt operation and verify the tag
	decrypted_message := cipher.aead_decrypt_and_verify_tag(aad, ciphertext, tag) or {return}

	// lets assert decrypted message exactly same with original msg
	// internally, above decryption process doing tag verification
	assert decrypted_message == msg 
	println("Decrypted msg: $decrypted_message.bytestr()")
	println("Original msg: $msg.bytestr()")
}