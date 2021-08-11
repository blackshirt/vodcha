// Diffie-Helman Key Exchange over Elliptic Curve (ECDH)
// based on curve25519 and curve448
module curve

import crypto.rand

const (
	err_all_zeros   = error('Results in all zeros bytes')
	// x25519 x-coordinate of the base point and is encoded as a byte with value 9, followed by 31 zero bytes.
	x255_xcord_base = '0900000000000000000000000000000000000000000000000000000000000000'
	// x448 x-coordinate of the base point and is encoded as a byte with value 5, followed by 55 zero bytes
	x448_xcord_base = '0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
)

struct KeyPair {
mut:
	public_key  []byte
	private_key []byte
}

fn new_random_x25519_keypair(c Curve) ?KeyPair {
	if c.bits_size != 255 {
		return error("Underlying curve's bits size: $c.bits_size doesn't match")
	}
	mut x_coord := hex2byte(curve.x255_xcord_base) ?
	mut priv := rand.read(32) ?
	public := c.x25519(mut priv, mut x_coord) ?

	return KeyPair{
		public_key: public
		private_key: priv
	}
}

// K = X25519(a, X25519(b, 9)) = X25519(b, X25519(a, 9))
// as a shared secret.  Both MAY check, without leaking extra
// information about the value of K, whether K is the all-zero value and abort if so
// The check may be performed by ORing all the bytes together and checking whether the
// result is zero
fn is_all_zeros(buf []byte) bool {
	assert buf.len >= 0
	for i := 0; i < buf.len; i++ {
		if buf[i] != byte(0) {
			return false
		}
	}
	return true
}

fn new_x25519_keypair_from_privkey(c Curve, mut priv_key []byte) ?KeyPair {
	if c.bits_size != 255 && priv_key.len != 32 {
		return error("Underlying curve's bits size: $c.bits_size doesn't match")
	}
	mut x_coord := hex2byte(curve.x255_xcord_base) ?
	// this results call should be checked for all zeros
	public := c.x25519(mut priv_key, mut x_coord) ?
	if is_all_zeros(public) {
		return curve.err_all_zeros
	}

	return KeyPair{
		public_key: public
		private_key: priv_key
	}
}

fn (k KeyPair) public_key() []byte {
	return k.public_key
}

fn (k KeyPair) private_key() []byte {
	return k.private_key
}

fn (mut k KeyPair) x25519_ecdh(c Curve, mut pub_key []byte) ?[]byte {
	res := c.x25519(mut k.private_key, mut pub_key) ?
	// check for all zeros
	if is_all_zeros(res) {
		return curve.err_all_zeros
	}
	return res
}

fn (mut k KeyPair) x448_ecdh(c Curve, mut pub_key []byte) ?[]byte {
	res := c.x448(mut k.private_key, mut pub_key) ?
	if is_all_zeros(res) {
		return curve.err_all_zeros
	}
	return res
}

fn new_x448_keypair_from_privkey(c Curve, mut priv_key []byte) ?KeyPair {
	if c.bits_size != 448 && priv_key.len != 56 {
		return error("Underlying curve's bits size: $c.bits_size doesn't match")
	}
	mut x_coord := hex2byte(curve.x448_xcord_base) ?
	public := c.x448(mut priv_key, mut x_coord) ?
	if is_all_zeros(public) {
		return curve.err_all_zeros
	}
	return KeyPair{
		public_key: public
		private_key: priv_key
	}
}
