//This is thin wrapper around two supported curve function, x25519 for 128-bit security level
//and x448 for 224-bit security level.
//Just look at curve25519.v (or curve448.v) files for the detail
module curve

import gmp

const (
	two = gmp.from_u64(2)
)

fn decode_little_endian(b []byte, bits int) ?gmp.Bigint {
	if bits == 255 {
		return x25519_decode_little_endian(b)
	}
	if bits == 448 {
		return x448_decode_little_endian(b)
	}
	return error('Unsupported bits length')
}

fn encode_x_coordinate(mut v gmp.Bigint, bits int) ?[]byte {
	if bits == 255 {
		return x25519_encode_x_coordinate(mut v)
	}
	if bits == 448 {
		return x448_encode_x_coordinate(mut v)
	}
	return error('Unsupported bits length')
}

fn cswap(swap gmp.Bigint, x_2 gmp.Bigint, x_3 gmp.Bigint) (gmp.Bigint, gmp.Bigint) {
	mask := gmp.from_u64(0) - swap
	mut dummy := gmp.new()
	mut vv := gmp.new()
	gmp.xor(mut vv, x_2, x_3)
	gmp.and(mut dummy, mask, vv)
	mut r1 := gmp.new()
	mut r2 := gmp.new()

	gmp.xor(mut r1, x_2, dummy)
	gmp.xor(mut r2, x_3, dummy)

	return r1, r2
}

fn scalar_multiply(k gmp.Bigint, u gmp.Bigint, bits int) ?gmp.Bigint {
	if bits == 255 {
		return x25519_scalar_multiply(k, u)
	}
	if bits == 448 {
		return x448_scalar_multiply(k, u)
	}
	return error('Unsupported bits length')
}
