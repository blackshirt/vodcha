module curve

import gmp

const (
	// Curve25519 modulo prime, 2**255 - 19
	cvp_25519 = gmp.from_str('57896044618658097711785492504343953926634992332820282019728792003956564819949')
	a24_25519 = gmp.from_u64(121665)
)


fn x25519(mut k []byte, mut u []byte) []byte {
	_ = k[31]
	mut key := x25519_decode_scalar(mut k)
	mut ucord := x25519_decode_x_coordinate(mut u)

	mut res := x25519_scalar_multiply(key, ucord)
	//gmp.clear(mut key)
	//gmp.clear(mut ucord)
	return x25519_encode_x_coordinate(mut res)
}

fn x25519_decode_scalar(mut k []byte) gmp.Bigint {
	_ = k[31]
	// mut k := key.clone()
	k[0] &= 248
	k[31] &= 127
	k[31] |= 64

	return x25519_decode_little_endian(k)
}

fn x25519_decode_little_endian(b []byte) gmp.Bigint {
	//_ = b[31]
	mut sum := gmp.from_u64(0)
	mut val := gmp.new()
	for i in 0 .. (255 + 7) / 8 {
		//moves allocation Bigint val to outside for loop and reused
		//many times
		//mut val := gmp.new()
		// left shift
		gmp.mul_2exp(mut val, gmp.from_u64(b[i]), u64(8 * i))
		sum = sum + val
	}
	gmp.clear(mut val)
	
	return sum
}

fn x25519_encode_x_coordinate(mut u gmp.Bigint) []byte {
	mut arr := []byte{len: (255 + 7) / 8}
	//defer {unsafe { arr.free() } }
	// mut u := v.clone()
	// u = u % cvp_25519
	gmp.mod(mut u, u, curve.cvp_25519)

	// return ''.join([chr((u >> 8*i) & 0xff) for i in range((bits+7)/8)])
	//placed this allocation out of for loop and call gmp.clear() to release it
	mut val := gmp.new()
	for i in 0 .. arr.len {
		//mut val := gmp.new()
		// this do right shifting
		gmp.tdiv_q_2exp(mut val, u, u64(8 * i))
		//mut d := gmp.new()
		//gmp.and(mut d, val, gmp.from_u64(0xff))
		//arr[i] = byte(d.u64())

		//changes to single Bigint `val` allocated before
		gmp.and(mut val, val, gmp.from_u64(0xff))
		arr[i] = byte(val.u64())
	}
	gmp.clear(mut val)
	
	return arr
}

fn x25519_decode_x_coordinate(mut u []byte) gmp.Bigint {
	// mut u := b.clone()
	// 255 % 8 != 0, so mask it
	u[u.len - 1] &= (1 << (255 % 8)) - 1

	return x25519_decode_little_endian(u)
}

fn x25519_scalar_multiply(k gmp.Bigint, u gmp.Bigint) gmp.Bigint {
	mut x_1 := u.clone()
	mut x_2 := gmp.from_u64(1)
	mut z_2 := gmp.from_u64(0)
	mut x_3 := u.clone()
	mut z_3 := gmp.from_u64(1)
	mut swap := gmp.from_u64(0)


	//allocate bigint needed value outside the loop
	mut k_t := gmp.new()
	mut val := gmp.new()
	mut aa := gmp.new()
	mut bb := gmp.new()
	mut xx := gmp.new()
	for t := 254; t >= 0; t-- {
		//this part below, allocated outside for loop
		//mut k_t := gmp.new()
		//mut val := gmp.new()
		
		//gmp.tdiv_q_2exp(mut val, k, u64(t)) // right shift
		gmp.tdiv_q_2exp(mut val, k, u64(t)) // right shift
		//gmp.and(mut k_t, val, gmp.from_u64(1))
		gmp.and(mut k_t, val, gmp.from_u64(1))
		//mut cs := gmp.new()
		
		gmp.xor(mut val, swap, k_t)
		//swap = cs
		swap = val 

		x_2, x_3 = cswap(swap, x_2, x_3)
		z_2, z_3 = cswap(swap, z_2, z_3)
		swap = k_t

		mut a := (x_2 + z_2) % curve.cvp_25519
		//mut aa := gmp.new()
		//eliminate a allocation
		gmp.powm(mut aa, a, two, curve.cvp_25519)

		mut b := (x_2 - z_2) % curve.cvp_25519
		//mut bb := gmp.new()
		gmp.powm(mut bb, b, two, curve.cvp_25519)

		mut e := (aa - bb) % curve.cvp_25519
		mut c := (x_3 + z_3) % curve.cvp_25519
		mut d := (x_3 - z_3) % curve.cvp_25519

		mut da := (d * a) % curve.cvp_25519
		mut cb := (c * b) % curve.cvp_25519

		gmp.powm(mut x_3, (da + cb) % curve.cvp_25519, two, curve.cvp_25519)
		//mut xx := gmp.new()
		gmp.powm(mut xx, (da - cb) % curve.cvp_25519, two, curve.cvp_25519)

		//z_3 = (x_1 * xx) % curve.cvp_25519
		z_3 = (x_1 * xx) % curve.cvp_25519 //x_1 not defined through `u.clone(), directly using `u`
		x_2 = (aa * bb) % curve.cvp_25519
		z_2 = e * ((aa + (curve.a24_25519 * e) % curve.cvp_25519) % curve.cvp_25519)
		
		defer {
			gmp.clear(mut a)
			gmp.clear(mut b)
			gmp.clear(mut c)
			gmp.clear(mut d)
			gmp.clear(mut e)
			gmp.clear(mut da)
			gmp.clear(mut cb)
			
		}
		
	}
	x_2, x_3 = cswap(swap, x_2, x_3)
	z_2, z_3 = cswap(swap, z_2, z_3)
	//mut zz := gmp.new()
	//gmp.powm(mut zz, z_2, curve.cvp_25519 - two, curve.cvp_25519)
	gmp.powm(mut val, z_2, curve.cvp_25519 - two, curve.cvp_25519)

	//res := (x_2 * zz) % curve.cvp_25519
	res := (x_2 * val) % curve.cvp_25519
	
	defer {
		gmp.clear(mut k_t)
		gmp.clear(mut val)
		gmp.clear(mut aa)
		gmp.clear(mut bb)
		gmp.clear(mut xx)
		//gmp.clear(mut zz)

		gmp.clear(mut x_1)
		gmp.clear(mut x_2)
		gmp.clear(mut x_3)
		gmp.clear(mut z_2)
		gmp.clear(mut z_3)
		//gmp.clear(mut swap) //this .clear call leads to double free bug, look at swap = k_t
	}
	
	
	return res
}
