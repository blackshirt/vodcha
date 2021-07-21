/*
Poly1305 Message Authentication Code (MAC)
based on RFC 843
*/

module vodcha

import math
import math.big
import math.util

const (
	// constant prime (2^130)-5
	cp = big.from_hex_string('3fffffffffffffffffffffffffffffffb')
)

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
fn bignum_to_16_le_bytes(mut num big.Number) []byte {
	mut ret := []byte{len: 16}
	for i in 0 .. 16 {
		ret[i] = byte(big.b_and(num, big.from_int(0xff)).int())
		num = num.rshift(8)
	}
	return ret
}

// `clamp_bignum` clamp the number required for poly1305 operation
fn clamp_bignum(r big.Number) big.Number {
	return big.b_and(r, big.from_hex_string('0ffffffc0ffffffc0ffffffc0fffffff'))
}

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
		a = (r * a) % vodcha.cp
	}
	a += s
	return bignum_to_16_le_bytes(mut a)
}

// `poly1305_key_gen` generate poly1305 one time key using `chacha20_ietf_block` function if nonce was 96 bits, and using
// xchacha20 support with derived key from hchacha function if provided nonce was 192 bits
pub fn poly1305_key_gen(key []byte, nonce []byte) ?[]byte {
	_ = key[key_size-1]
	_ = nonce.len in [nonce_size, nonce_size_x] // ensure nonce size is valid
	counter := u32(0)
	if nonce.len == nonce_size_x {
		mut cnonce := nonce[16..].clone()
		subkey := hchacha20(key, nonce[0..16])
		cnonce.prepend([byte(0x00), 0x00, 0x00, 0x00])
		block := chacha20_ietf_block(subkey, counter, cnonce) ?
		return block[0..32]
	} else if nonce.len == nonce_size {
		block := chacha20_ietf_block(key, counter, nonce) ?
		return block[0..32]
	} else {
		return error("wrong nonce size")
	}
}
