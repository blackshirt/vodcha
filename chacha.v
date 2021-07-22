// Chacha20 stream cipher based on RFC 8439

module vodcha

import math
import math.bits
import crypto.cipher
import encoding.binary

// https://datatracker.ietf.org/doc/html/rfc8439#section-2.3
const (
	key_size     = 32 // 256 bits size
	nonce_size   = 12 // 96 bits size

	// 192 bits size, extended nonce size of chacha20, called xchacha20
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
	nonce_size_x = 24

	// block size of chacha20
	block_size = 64
	buf_size   = block_size
)


// first of four words chacha20 state constant
const (
	chacha_c0  = u32(0x61707865)
	chacha_c1  = u32(0x3320646e)
	chacha_c2  = u32(0x79622d32)
	chacha_c3  = u32(0x6b206574)
)


// core chacha20 round function
fn quarter_round(a u32, b u32, c u32, d u32) (u32, u32, u32, u32) {
	mut ax := a
	mut bx := b
	mut cx := c
	mut dx := d

	// a += b
	// d ^= a
	// d = bits.rotate_left_32(d, 16)
	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 16)
	/*
	c += d
	b ^= c
	b = bits.rotate_left_32(b, 12)
	*/
	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 12)

	/*
	a += b
	d ^= a
	d = bits.rotate_left_32(d, 8)
	*/
	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 8)

	/*
	c += d
	b ^= c
	b = bits.rotate_left_32(b, 7)
	*/
	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 7)

	return ax, bx, cx, dx
}

fn quarter_round_on_chacha_state(mut state []u32, idx1 u32, idx2 u32, idx3 u32, idx4 u32) {
	state[idx1], state[idx2], state[idx3], state[idx4] = quarter_round(state[idx1], state[idx2], state[idx3], state[idx4])
}

fn inner_block(mut state []u32) []u32 {
	_ = state[15]
	quarter_round_on_chacha_state(mut state, 0, 4, 8, 12)
	quarter_round_on_chacha_state(mut state, 1, 5, 9, 13)
	quarter_round_on_chacha_state(mut state, 2, 6, 10, 14)
	quarter_round_on_chacha_state(mut state, 3, 7, 11, 15)
	quarter_round_on_chacha_state(mut state, 0, 5, 10, 15)
	quarter_round_on_chacha_state(mut state, 1, 6, 11, 12)
	quarter_round_on_chacha_state(mut state, 2, 7, 8, 13)
	quarter_round_on_chacha_state(mut state, 3, 4, 9, 14)
	return state
}

// `chacha20_block_generic` generate block/key stream from 256 bits key and 96 bits nonce 
fn chacha20_block_generic(key []byte, counter u32, nonce []byte) ?[]byte {
	if key.len != key_size {
		return error('chacha20 wrong key size')
	}
	if nonce.len != nonce_size {
		return error('chacha20 wrong nonce size')
	}
	
	// setup state
	
	s0, s1, s2, s3 := chacha_c0, chacha_c1, chacha_c2, chacha_c3
	s4 := binary.little_endian_u32(key[0..4])
	s5 := binary.little_endian_u32(key[4..8])
	s6 := binary.little_endian_u32(key[8..12])
	s7 := binary.little_endian_u32(key[12..16])

	s8 := binary.little_endian_u32(key[16..20])
	s9 := binary.little_endian_u32(key[20..24])
	s10 := binary.little_endian_u32(key[24..28])
	s11 := binary.little_endian_u32(key[28..32])

	s12 := counter
	s13 := binary.little_endian_u32(nonce[0..4])
	s14 := binary.little_endian_u32(nonce[4..8])
	s15 := binary.little_endian_u32(nonce[8..12])
	
	mut state := [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15]
	mut initial_state := state[..state.len].clone()

	for i := 0; i < 10; i++ {
		state = inner_block(mut state)
	}

	// state += initial_state
	for i := 0; i < state.len; i++ {
		state[i] = state[i] + initial_state[i]
	}

	// return state
	return serialize(state)
}

// `chacha20_encrypt_generic` generate encrypted message from plaintext using chacha 20 round algorithm
// specified in rfc8439
pub fn chacha20_encrypt_generic(key []byte, counter u32, nonce []byte, plaintext []byte) ?[]byte {
	//bound early check
	_, _ = key[key_size-1], nonce[nonce_size-1]
	mut encrypted_message := []byte{}

	for i := 0; i < plaintext.len / block_size; i++ {
		key_stream := chacha20_block_generic(key, counter + u32(i), nonce) or { return none }
		block := plaintext[i * block_size..(i + 1) * block_size]

		// encrypted_message += block ^ key_stream
		mut dst := []byte{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		// encrypted_message = encrypted_message + dst
		encrypted_message << dst
	}
	if plaintext.len % block_size != 0 {
		j := plaintext.len / block_size
		key_stream := chacha20_block_generic(key, counter + u32(j), nonce) or { return none }
		block := plaintext[j * block_size..]

		// encrypted_message += (block^key_stream)[0..len(plaintext)%block_size]
		mut dst := []byte{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		dst = dst[0..plaintext.len % block_size]
		
		// encrypted_message = encrypted_message[0..plaintext.len % block_size]
		encrypted_message << dst
	
	}
	return encrypted_message
}

// `chacha20_decrypt_generic` do opposite of encrypt
pub fn chacha20_decrypt_generic(key []byte, counter u32, nonce []byte, ciphertext []byte) ?[]byte {
	//bound early check
	_, _ = key[key_size-1], nonce[nonce_size-1]
	mut decrypted_message := []byte{}

	for i := 0; i < ciphertext.len / block_size; i++ {
		key_stream := chacha20_block_generic(key, counter + u32(i), nonce) or { return none }
		block := ciphertext[i * block_size..(i + 1) * block_size]

		mut dst := []byte{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)

		decrypted_message << dst
	}
	if ciphertext.len % block_size != 0 {
		j := ciphertext.len / block_size
		key_stream := chacha20_block_generic(key, counter + u32(j), nonce) or { return none }
		block := ciphertext[j * block_size..]

		mut dst := []byte{len: block.len}
		_ := cipher.xor_bytes(mut dst, block, key_stream)
		dst = dst[0..ciphertext.len % block_size]
		
		decrypted_message << dst
	
	}
	return decrypted_message
}