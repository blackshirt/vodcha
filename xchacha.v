module vodcha

import encoding.binary

fn hchacha20(key []byte, nonce []byte) []byte {
	// hchacha use first 16 bytes of nonce  and key to derive subkey
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

// nonce was 24 bytes length, as specified
fn xchacha20_encrypt(key []byte, nonce []byte, plaintext []byte, ctr u32) ?[]byte {
	_ = key[..key_size]
	if nonce.len >= nonce_size_x {
		mut cnonce := nonce[16..24].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([byte(0x00), 0x00, 0x00, 0x00])
		ciphertext := chacha20_ietf_encrypt(subkey, ctr, cnonce, plaintext) ?

		return ciphertext
	} 
	if nonce.len >= nonce_size && nonce.len < nonce_size_x {
		ciphertext := chacha20_ietf_encrypt(key, ctr, nonce, plaintext) ?
		return ciphertext
		 
	}
	return error("Wronng nonce size")
}
