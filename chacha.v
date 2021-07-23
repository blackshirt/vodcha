// Chacha20 stream cipher based on RFC 8439

module vodcha

import math
import math.bits
import crypto.cipher
import crypto.internal.subtle
import encoding.binary

// https://datatracker.ietf.org/doc/html/rfc8439#section-2.3
const (
	key_size     = 32 // 256 bits size
	nonce_size   = 12 // 96 bits size

	// extended nonce size of chacha20, called xchacha20, 192 bits nonce size
	// https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03
	nonce_size_x = 24

	// chacha20 block size
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

struct Cipher {
	// key
	key     []byte
	nonce   []byte
	mut:
	counter u32
}

pub fn new_chiper_from_string(key string, nonce string) ?Cipher {
	bytes_key := key.bytes()
	bytes_nonce := nonce.bytes()

	return new_cipher(bytes_key, bytes_nonce)
}

pub fn new_cipher(key []byte, nonce []byte) ?Cipher{
	if key.len != key_size {
		return error("error wrong key size provided ")
	}
	if nonce.len !in [nonce_size, nonce_size_x] {
		return error("error nonce size provided")
	}
	c := Cipher{
		key: key
		nonce: nonce
	}
	return c
}

// encrypt result in encrypted plaintext with chacha20 stream cipher
fn (c Cipher) encrypt(plaintext []byte) ?[]byte {
	return chacha20_encrypt(c.key, c.counter, c.nonce, plaintext)
}

// decrypt decrypt the ciphertext that was result from chacha20 encryption
fn (c Cipher) decrypt(ciphertext []byte) ?[]byte {
	return chacha20_encrypt(c.key, c.counter, c.nonce, ciphertext)
}

// `chacha20_encrypt` was a thin wrapper around two supported nonce size, chacha20 with 96 bits 
// and xchacha20 with 192 bits nonce  
fn chacha20_encrypt(key []byte, ctr u32, nonce []byte, plaintext []byte) ?[]byte {
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


// core chacha20 round function
fn quarter_round(a u32, b u32, c u32, d u32) (u32, u32, u32, u32) {
	mut ax := a
	mut bx := b
	mut cx := c
	mut dx := d

	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 16)
	
	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 12)

	ax += bx
	dx ^= ax
	dx = bits.rotate_left_32(dx, 8)

	cx += dx
	bx ^= cx
	bx = bits.rotate_left_32(bx, 7)

	return ax, bx, cx, dx
}

// initialize chacha20 state, represented as array of 16 u32
fn initialize_chacha_state(key []byte, counter u32, nonce []byte) ?[]u32 {
	if key.len != key_size {
		return error('chacha20 wrong key size')
	}
	if nonce.len != nonce_size {
		return error('chacha20 wrong nonce size')
	}
	mut state := []u32{len:16}

	state[0] = chacha_c0
	state[1] = chacha_c1
	state[2] = chacha_c2
	state[3] = chacha_c3

	state[4] = binary.little_endian_u32(key[0..4])
	state[5] = binary.little_endian_u32(key[4..8])
	state[6] = binary.little_endian_u32(key[8..12])
	state[7] = binary.little_endian_u32(key[12..16])

	state[8] = binary.little_endian_u32(key[16..20])
	state[9] = binary.little_endian_u32(key[20..24])
	state[10] = binary.little_endian_u32(key[24..28])
	state[11] = binary.little_endian_u32(key[28..32])

	state[12] = counter
	state[13] = binary.little_endian_u32(nonce[0..4])
	state[14] = binary.little_endian_u32(nonce[4..8])
	state[15] = binary.little_endian_u32(nonce[8..12])

	return state
}


// `chacha20_block_generic` generate block/key stream from 256 bits key and 96 bits nonce 
fn chacha20_block_generic(key []byte, counter u32, nonce []byte) ?[]byte {
	// setup chacha state, checking was done on initialization step
	mut state := initialize_chacha_state(key, counter, nonce) ?
	// copy of state 
	initial_state := state[..state.len].clone()

	// perform chacha20 quarter round on chacha20 state
	for i := 0; i < 10; i++ {
		// Diagonal round.
		state[0], state[4], state[8], state[12] = quarter_round(state[0], state[4], state[8], state[12])
		state[1], state[5], state[9], state[13] = quarter_round(state[1], state[5], state[9], state[13])
		state[2], state[6], state[10], state[14] = quarter_round(state[2], state[6], state[10], state[14])
		state[3], state[7], state[11], state[15] = quarter_round(state[3], state[7], state[11], state[15])

		// Column round.
		state[0], state[5], state[10], state[15] = quarter_round(state[0], state[5], state[10], state[15])
		state[1], state[6], state[11], state[12] = quarter_round(state[1], state[6], state[11], state[12])
		state[2], state[7], state[8], state[13] = quarter_round(state[2], state[7], state[8], state[13])
		state[3], state[4], state[9], state[14] = quarter_round(state[3], state[4], state[9], state[14])
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
fn chacha20_encrypt_generic(key []byte, counter u32, nonce []byte, plaintext []byte) ?[]byte {
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

// `chacha20_decrypt_generic` decrypt the ciphertext, opposite of encryption proses
fn chacha20_decrypt_generic(key []byte, counter u32, nonce []byte, ciphertext []byte) ?[]byte {
	//bound early check
	_, _ = key[key_size-1], nonce[nonce_size-1]
	mut decrypted_message := []byte{}

	for i := 0; i < ciphertext.len / block_size; i++ {
		key_stream := chacha20_block_generic(key, counter + u32(i), nonce) or { return none }
		block := ciphertext[i * block_size..(i + 1) * block_size]

		mut dst := []byte{len: block.len}
		if subtle.inexact_overlap(block, key_stream) {
			panic("chacha: subtle inexact overlap")
		}
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