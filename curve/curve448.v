module curve

import gmp

const (
	// curve modulo prime for x448 , 2^448 - 2^224 - 1
	cvp_448 = gmp.from_str('726838724295606890549323807888004534353641360687318060281490199180612328166730772686396383698676545930088884461843637361053498018365439') // 2^448 - 2^224 - 1
	// The constant a24 for x448
	a24_448 = gmp.from_u64(39081)
)

fn x448(mut k []byte, u []byte) []byte {
	_ = k[55]
	key := x448_decode_scalar(mut k)
	ucord := x448_decode_x_coordinate(u)

	mut res := x448_scalar_multiply(key, ucord)
	return x448_encode_x_coordinate(mut res)
}

fn x448_decode_little_endian(b []byte) gmp.Bigint {
	_ = b[55]
	mut sum := gmp.from_u64(0)
	for i in 0 .. (448 + 7) / 8 {
		mut val := gmp.new()
		// left shift
		gmp.mul_2exp(mut val, gmp.from_u64(b[i]), u64(8 * i))
		sum = sum + val
	}
	return sum
}

fn x448_decode_scalar(mut k []byte) gmp.Bigint {
	_ = k[55]
	// mut k := key.clone()
	k[0] &= 252
	k[55] |= 128

	return x448_decode_little_endian(k)
}

fn x448_decode_x_coordinate(u []byte) gmp.Bigint {
	// bits was 448, and 448 % 8 == 0, so, its not needed to do below part
	// and params u not needed as mut params
	// mut u := b.clone()
	// if bits % 8 != 0 {
	//	u[u.len - 1] &= (1 << (bits % 8)) - 1
	//}
	return x448_decode_little_endian(u)
}

fn x448_encode_x_coordinate(mut u gmp.Bigint) []byte {
	mut arr := []byte{len: (448 + 7) / 8}
	// mut u := n
	// u = u % p
	// u = u % cv_prime
	//_, r := gmp.divmod(u, cv_prime)
	// u = r
	// mut u := v.clone()
	// u %= cvp_448
	gmp.mod(mut u, u, curve.cvp_448)

	// return ''.join([chr((u >> 8*i) & 0xff) for i in range((bits+7)/8)])
	for i in 0 .. arr.len {
		mut val := gmp.new()
		// this do right shifting
		gmp.tdiv_q_2exp(mut val, u, u64(8 * i))
		mut d := gmp.new()
		gmp.and(mut d, val, gmp.from_u64(0xff))
		arr[i] = byte(d.u64())
	}

	return arr
}

fn x448_scalar_multiply(k gmp.Bigint, u gmp.Bigint) gmp.Bigint {
	x_1 := u.clone()
	mut x_2 := gmp.from_u64(1)
	mut z_2 := gmp.from_u64(0)
	mut x_3 := u.clone()
	mut z_3 := gmp.from_u64(1)
	mut swap := gmp.from_u64(0)

	for t := 447; t >= 0; t-- {
		mut k_t := gmp.new()
		mut val := gmp.new()
		gmp.tdiv_q_2exp(mut val, k, u64(t)) // right shift
		gmp.and(mut k_t, val, gmp.from_u64(1))
		mut cs := gmp.new()
		gmp.xor(mut cs, swap, k_t)
		swap = cs

		x_2, x_3 = cswap(swap, x_2, x_3)
		z_2, z_3 = cswap(swap, z_2, z_3)
		swap = k_t

		a := (x_2 + z_2) % curve.cvp_448
		mut aa := gmp.new()
		gmp.powm(mut aa, a, two, curve.cvp_448)

		b := (x_2 - z_2) % curve.cvp_448
		mut bb := gmp.new()
		gmp.powm(mut bb, b, two, curve.cvp_448)

		e := (aa - bb) % curve.cvp_448
		c := (x_3 + z_3) % curve.cvp_448
		d := (x_3 - z_3) % curve.cvp_448

		da := (d * a) % curve.cvp_448
		cb := (c * b) % curve.cvp_448

		gmp.powm(mut x_3, (da + cb) % curve.cvp_448, two, curve.cvp_448)
		mut xx := gmp.new()
		gmp.powm(mut xx, (da - cb) % curve.cvp_448, two, curve.cvp_448)

		z_3 = (x_1 * xx) % curve.cvp_448
		x_2 = (aa * bb) % curve.cvp_448
		z_2 = e * ((aa + (curve.a24_448 * e) % curve.cvp_448) % curve.cvp_448)
	}
	x_2, x_3 = cswap(swap, x_2, x_3)
	z_2, z_3 = cswap(swap, z_2, z_3)
	mut zz := gmp.new()
	gmp.powm(mut zz, z_2, curve.cvp_448 - two, curve.cvp_448)

	res := (x_2 * zz) % curve.cvp_448
	return res
}
