module vodcha

import crypto.rand
import encoding.binary

// generate random key 
pub fn random_key() ?[]byte {
	return rand.read(key_size)
}

//generate random nonce with size
pub fn random_nonce(size int) ?[]byte {
	if size !in [nonce_size, nonce_size_x] {
		return error("get_random_nonce: wrong nonce size $size provided, allowed value was 12 or 24")
	}
	return rand.read(size)
}

//`serialize` serialize chacha20 state (array of 16 u32) to array of bytes
fn serialize(state []u32) []byte {
	_ = state[15]
	mut res := []byte{len: 4 * state.len}
	for idx, val in state {
		binary.little_endian_put_u32(mut res[idx * 4..idx * 4 + 4], val)
	}
	return res
}

//`unserialize` do opposite of `serialize`
fn unserialize(mut res []byte) []u32 {
	_ = res[63]
	mut out := []u32{len:16}
	for i := 0; i < 16; i++ {
		binary.little_endian_put_u32(mut res[i * 4..i * 4 + 4], out[i])
	}
	return out
}

// convert u32 to internal array of byte
fn u32_to_bytes(val u32) []byte {
	mut res := []byte{len: 4}
	for i := u32(0); i < 4; i++ {
		res[i] = byte((val >> (8 * i)) & 0xff)
	}
	return res
}

// convert array of bytes to u32 representation
fn bytes_to_u32(val []byte) u32 {
	mut res := u32(0)
	for i := u32(0); i < 4; i++ {
		res |= u32(val[i]) << (8 * i)
	}
	return res
}

// this is written by @JalonSolov on vlang discord channel
// https://discord.com/channels/592103645835821068/592106336838352923/855283244861095936
fn char2nibble(b byte) ?byte {
	match b {
		`0`...`9` { return b - 0x30 }
		`A`...`F` { return b - 0x41 + 10 }
		`a`...`f` { return b - 0x61 + 10 }
		else { return error('invalid hex char $b.ascii_str()') }
	}
}

// utility function to convert hex string to array of bytes
fn hex2byte(hex string) ?[]byte {
	mut my_hex := hex
	mut ba := []byte{}

	if my_hex.len & 1 != 0 {
		my_hex = '0' + my_hex
	}

	for i := 0; i < my_hex.len; i += 2 {
		mut b := char2nibble(my_hex[i]) ?
		ba << (b << 4) + char2nibble(my_hex[i + 1]) ?
	}

	return ba
}

// []byte to hex
fn bytes_to_hex(src []byte) string {
	return src.hex()
}

//[]u32 to []byte
fn u32array_to_bytes(vs []u32) []byte {
	mut buf := []byte{len: vs.len * 4}
	for i, v in vs {
		binary.little_endian_put_u32(mut buf[i * 4..], v)
	}
	return buf
}

//[]byte to []u32
fn bytes_to_u32array(vs []byte) []u32 {
	mut out := []u32{len: vs.len / 4}
	for i in out {
		out[i] = binary.little_endian_u32(vs[i * 4..])
	}
	return out
}
