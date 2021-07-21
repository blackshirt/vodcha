// Building block for eXtended ChaCha20
// Its based on https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
// so, its maybe outdated...
module vodcha

import encoding.binary

// `hchacha20` was intermediary step to build xchacha20 and initialized the same way as the ChaCha20 cipher, 
// except hchacha20 use a 128-bit (16 byte) nonce and has no counter to derive subkey
fn hchacha20(key []byte, nonce []byte) []byte {
	// early bound check
	_, _ = key[..key_size], nonce[..16]

	mut x0 := chacha_c0
	mut x1 := chacha_c1
	mut x2 := chacha_c2
	mut x3 := chacha_c3

	mut x4 := binary.little_endian_u32(key[0..4])
	mut x5 := binary.little_endian_u32(key[4..8])
	mut x6 := binary.little_endian_u32(key[8..12])
	mut x7 := binary.little_endian_u32(key[12..16])

	mut x8 := binary.little_endian_u32(key[16..20])
	mut x9 := binary.little_endian_u32(key[20..24])
	mut x10 := binary.little_endian_u32(key[24..28])
	mut x11 := binary.little_endian_u32(key[28..32])

	mut x12 := binary.little_endian_u32(nonce[0..4])
	mut x13 := binary.little_endian_u32(nonce[4..8])
	mut x14 := binary.little_endian_u32(nonce[8..12])
	mut x15 := binary.little_endian_u32(nonce[12..16])

	for i := 0; i < 10; i++ {
		// Diagonal round.
		x0, x4, x8, x12 = quarter_round(x0, x4, x8, x12)
		x1, x5, x9, x13 = quarter_round(x1, x5, x9, x13)
		x2, x6, x10, x14 = quarter_round(x2, x6, x10, x14)
		x3, x7, x11, x15 = quarter_round(x3, x7, x11, x15)

		// Column round.
		x0, x5, x10, x15 = quarter_round(x0, x5, x10, x15)
		x1, x6, x11, x12 = quarter_round(x1, x6, x11, x12)
		x2, x7, x8, x13 = quarter_round(x2, x7, x8, x13)
		x3, x4, x9, x14 = quarter_round(x3, x4, x9, x14)
	}

	mut out := []byte{len: 32}

	binary.little_endian_put_u32(mut out[0..4], x0)
	binary.little_endian_put_u32(mut out[4..8], x1)
	binary.little_endian_put_u32(mut out[8..12], x2)
	binary.little_endian_put_u32(mut out[12..16], x3)

	binary.little_endian_put_u32(mut out[16..20], x12)
	binary.little_endian_put_u32(mut out[20..24], x13)
	binary.little_endian_put_u32(mut out[24..28], x14)
	binary.little_endian_put_u32(mut out[28..32], x15)

	return out
}

// `chacha20_encrypt` was a thin wrapper around two supported nonce size, chacha20 with 96 bits 
// and xchacha20 with 192 bits nonce  
pub fn chacha20_encrypt(key []byte, ctr u32, nonce []byte, plaintext []byte) ?[]byte {
	_ = key[..key_size]
	if nonce.len == nonce_size_x {
		ciphertext := chacha20_encrypt_extended(key, ctr, nonce, plaintext) ?
		return ciphertext
	} 
	if nonce.len == nonce_size {
		ciphertext := chacha20_encrypt_generic(key, ctr, nonce, plaintext) ?
		return ciphertext
	}
	return error("Wrong nonce size : $nonce.len")
}

// eXtended nonce size (xchacha20) encrypt function 
// as specified in https://datatracker.ietf.org/doc/html/draft-arciszewski-xchacha-03
fn chacha20_encrypt_extended(key []byte, ctr u32, nonce []byte, plaintext []byte) ?[]byte {
	if nonce.len != nonce_size_x {
		return error("xchacha: wrong x nonce size: $nonce.len")
	}
	subkey := hchacha20(key, nonce[0..16])
	mut cnonce := nonce[16..24].clone()
	cnonce.prepend([byte(0x00), 0x00, 0x00, 0x00])
	ciphertext := chacha20_encrypt_generic(subkey, ctr, cnonce, plaintext) ?

	return ciphertext
}
