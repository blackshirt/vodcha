/*
Poly1305 Message Authentication Code (MAC)
based on RFC 8439
*/

module vodcha

import math
import math.big
import math.util

const (
	// Poly1305 constant prime, aka (2^130)-5
	cp = big.from_hex_string('3fffffffffffffffffffffffffffffffb')
)

// `poly1305_mac` was poly1305 mac algorithms specified in 
// https://datatracker.ietf.org/doc/html/rfc8439#section-2.5.1
pub fn poly1305_mac(msg []byte, key []byte) []byte {
	_ = key[key_size-1] // bound early check
	mut r := le_bytes_to_bignum(key[0..16])
	r = clamp_bignum(r)
	s := le_bytes_to_bignum(key[16..32])

	mut a := big.from_int(0)

	// this looping fixed comes from @jokermc/div72 at vlang discord channel
	// https://discord.com/channels/592103645835821068/592294828432424960/865885996733562890
	for i in 1 .. ((msg.len + 15) / 16 + 1) {
		mut mm := msg[(i - 1) * 16..util.imin(i * 16, msg.len)].clone()
		mm << byte(0x01)
		n := le_bytes_to_bignum(mm)
		a += n
		a = (r * a) % cp
	}
	a += s
	return bignum_to_16_le_bytes(a)
}

// `poly1305_key_gen` generate poly1305 one time key using `chacha20_block_generic` if nonce was 96 bits, or
// using extended nonce version, xchacha20, when its nonce was 192 bits 
fn poly1305_key_gen(key []byte, nonce []byte) ?[]byte {
	_ = key[key_size-1]
	_ = nonce.len in [nonce_size, nonce_size_x] // ensure nonce size is valid
	counter := u32(0)
	if nonce.len == nonce_size_x {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([byte(0x00), 0x00, 0x00, 0x00])
		block := chacha20_block_generic(subkey, counter, cnonce) ?
		return block[0..32]
	} 
	if nonce.len == nonce_size {
		block := chacha20_block_generic(key, counter, nonce) ?
		return block[0..32]
	} 
	return error("wrong nonce size")
}

// Convert ittle endian byte format to `big.Number`
fn le_bytes_to_bignum(data []byte) big.Number {
	mut ret := big.from_int(0)
	for i := data.len - 1; i >= 0; i-- {
		ret = ret.lshift(8)
		ret += big.from_int(int(data[i]))
	}
	return ret
}

// Convert number to 16 bytes in little endian format
fn ori_bignum_to_16_le_bytes(mut num big.Number) []byte {
	mut ret := []byte{len: 16}
	for i in 0 .. 16 {
		//BUG WARN: its contains some way reducing a bignum to an int, and then to a byte
		//is there viable alternative for this ?
		ret[i] = byte(big.b_and(num, big.from_int(0xff)).int())
		num = num.rshift(8)
	}
	return ret
}

fn bignum_to_16_le_bytes(num big.Number) []byte {
	mut res := num.bytes()
	res.trim(16)
	return res
}

// `clamp_bignum` clamp the number required for poly1305 operation
fn clamp_bignum(r big.Number) big.Number {
	return big.b_and(r, big.from_hex_string('0ffffffc0ffffffc0ffffffc0fffffff'))
}