// AEAD Construction using chacha20 (or xchacha20) and poly1305

module vodcha

import encoding.binary
import crypto.internal.subtle


// `encrypt_and_buildtag` encrypt the plaintext using chacha20-poly1305 and return ciphertext and the tag
pub fn encrypt_and_buildtag(aad []byte, key []byte, nonce []byte, plaintext []byte) ?([]byte, []byte) {
	ciphertext, tag := aead_chacha20_poly_encrypt(aad, key, nonce, plaintext) ?
	return ciphertext, tag
}

// `decrypt_and_verify` doing decryption of ciphertext and verify the tag's validity
pub fn decrypt_and_verify(key []byte, nonce []byte, ciphertext []byte, mac []byte, aad []byte) ?[]byte {
	plaintext, tag := aead_chacha20_poly_decrypt(aad, key, nonce, ciphertext) ?

	res := subtle.constant_time_compare(tag, mac)
	if res != 1 {
		return error('Bad tag')
	}
	return plaintext
}

// 'aead_chacha20_poly_encrypt' encrypt the `plaintext` with `chacha20_encrypt` using one time key generated 
// by `poly1305_key_gen` and then mac-ed by `poly1305_mac`
fn aead_chacha20_poly_encrypt(aad []byte, key []byte, nonce []byte, plaintext []byte) ?([]byte, []byte) {
	_ = key[key_size-1] //bound early check

	otk := poly1305_key_gen(key, nonce) ?
	//ciphertext := chacha20_encrypt_generic(key, u32(1), nonce, plaintext) ?
	//add support to xchacha20
	ciphertext := chacha20_encrypt(key, u32(1), nonce, plaintext) ?

	mut mac_data := pad16(aad)
	ch := pad16(ciphertext)
	mac_data << ch
	mac_data << num_to_8_le_bytes(u64(aad.len))
	mac_data << num_to_8_le_bytes(u64(ciphertext.len))
	tag := poly1305_mac(mac_data, otk)
	return ciphertext, tag
}

// `aead_chacha20_poly_decrypt` do opposite of encrypt
fn aead_chacha20_poly_decrypt(aad []byte, key []byte, nonce []byte, ciphertext []byte) ?([]byte, []byte) {
	otk := poly1305_key_gen(key, nonce) ?
	
	//plaintext := chacha20_encrypt_generic(key, u32(1), nonce, ciphertext) ?
	plaintext := chacha20_encrypt(key, u32(1), nonce, ciphertext) ?

	mut mac_data := pad16(aad)
	ch := pad16(ciphertext)
	mac_data << ch
	mac_data << num_to_8_le_bytes(u64(aad.len))
	mac_data << num_to_8_le_bytes(u64(ciphertext.len))
	tag := poly1305_mac(mac_data, otk)
	return plaintext, tag
}

fn num_to_8_le_bytes(num u64) []byte {
	mut buf := []byte{len: 8}
	binary.little_endian_put_u64(mut buf, num)
	return buf
}

fn pad16(x []byte) []byte {
	mut buf := x.clone()
	if buf.len % 16 == 0 {
		return buf
	}
	pad_bytes := []byte{len: 16 - buf.len % 16, init: 0}
	buf << pad_bytes
	return buf
}
