module main 

import blackshirt.vodcha

fn main() {
	// NOTE: Messages encrypted with this module was not authenticated, if you want to do 
	// encrypted and authenticated data, you should complement it with message authenticated code (MAC)
	// algorithms, and this module provides this need with poly1305 mac.
	// most commons function/methods in this module return optional, so handle it
	println("Test vodcha chacha20/xchacha20 module.....")

	// first, provides 32 bytes random key needed for chacha20 cipher
	// you can provide yourself, or using `random_key()` from this module
	// its internally build with key_size size, aka 32 
	key := vodcha.random_key() or {return} 

	// then, we need some random nonce, you can provide one
	// or using `random_nonce(size)` where size either 12 or 24
	nonce := vodcha.random_nonce(24) or {return} // we build using xchacha20 construct

	// create xchacha20 cipher instance
	cipher := vodcha.new_cipher(key, nonce) or {return}

	// encryption was doing by providing message want to be encrypted to cipher instance
	// lets say, message to be encrypted, in bytes
	msg := 'This is message want to send to you'.bytes()

	// encrypt the message
	encrypted_message := cipher.encrypt(msg) or {return}

	// lets verify encrypted_message by doing decryption, in reverse way of encryption

	decrypted_message := cipher.decrypt(encrypted_message) or {return}

	assert decrypted_message == msg 
	println("Original  msg: $msg.bytestr()")
	println("Encrypted msg: $encrypted_message.bytestr()")
	println("Decrypted msg: $decrypted_message.bytestr()")
}

