module curve

import math.big

fn modulo_exp(b big.Number, e big.Number, m big.Number) big.Number {
	mut exp := e.clone()
	mut bc := b.clone()
	mut result := big.from_int(1)
	if big.cmp(exp, big.from_int(1)) == 0 {
		result = bc
	}
	for big.cmp(exp, big.from_int(0)) > 0 {
		exp = exp.rshift(1)
		bc = (bc * bc) % m
		if big.cmp(exp, big.from_int(1)) == 0 {
			result = (result * bc) % m
		}
	}
	return result
}

fn int_to_bytes(value int, length int) []int {
	mut result := []int{}
	for i in 0 .. length {
		result << (value >> (i * 8) & 0xff)
	}
	return result
}

// copied here for simplicity
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
