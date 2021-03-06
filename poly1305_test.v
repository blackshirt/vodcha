module vodcha

import math.big

fn test_clamp_bignum() {
	/*
	its from python working poly1305 implementation
	>>> num=0x85d6be7857556d337f4452fe42d506a8
	>>> num
	177902338159352929974838317437408315048
	>>> hex(num)
	'0x85d6be7857556d337f4452fe42d506a8'
	>>> c = po.clamp(num)
	>>> c
	7761154674124897394032725460501464744
	>>> hex(c)
	'0x5d6be7807556d300f4452fc02d506a8'
	>>> d = num & 0x0ffffffc0ffffffc0ffffffc0fffffff
	>>> d
	7761154674124897394032725460501464744
	>>> hex(d)
	'0x5d6be7807556d300f4452fc02d506a8'
	>>>
	*/
	num := big.from_hex_string('85d6be7857556d337f4452fe42d506a8')
	r := clamp_bignum(num)
	hex_r := r.hexstr() // hex form of bignum r 5d6be7807556d300f4452fc02d506a8
	expected_r := '5d6be7807556d300f4452fc02d506a8'
	assert hex_r == expected_r
}

fn test_le_bytes_to_bignum() {
	key := '1f1e1d1c1b1a19181716151413121110'
	bkey := hex2byte(key) or { return }

	assert bkey.len == 16

	num := le_bytes_to_bignum(bkey) // 21356283574076891493948969979685445151 or 0x101112131415161718191a1b1c1d1e1f
	hex_num := num.hexstr()

	expected_num := '101112131415161718191a1b1c1d1e1f'

	assert hex_num == expected_num
}

fn test_bignum_to_16_le_bytes() {
	num := '1f1e1d1c1b1a19181716151413121110'
	mut big_num := big.from_hex_string(num)

	bts := bignum_to_16_le_bytes(big_num)
	hex_bts := bts.hex()

	expected_bts := '101112131415161718191a1b1c1d1e1f'

	assert hex_bts == expected_bts
}

fn test_bignum_to_16_le_bytes_2() {
	num := '1bf54941aff6bf4afdb20dfb8a800301'
	mut big_num := big.from_hex_string(num)

	bts := bignum_to_16_le_bytes(big_num)
	hex_bts := bts.hex()

	exp_bts := '0103808afb0db2fd4abff6af4149f51b'
	assert hex_bts == exp_bts
}

struct PolyCase {
	keys string
	msg  string
	out  string
}

const (
	poly_cases = [
		// core test
		PolyCase{
			keys: '85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b'
			msg: '43727970746f6772617068696320466f72756d2052657365617263682047726f7570'
			out: 'a8061dc1305136c6c22b8baf0c0127a9'
		},
		// https://datatracker.ietf.org/doc/html/rfc8439#appendix-A.3
		// A.3.1 case
		PolyCase{
			keys: '0000000000000000000000000000000000000000000000000000000000000000'
			msg: '00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
			out: '00000000000000000000000000000000'
		},
		// A.3.2 case
		PolyCase{
			keys: '0000000000000000000000000000000036e5f6b5c5e06070f0efca96227a863e'
			msg: '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f'
			out: '36e5f6b5c5e06070f0efca96227a863e'
		},
		// A.3.3 case
		PolyCase{
			keys: '36e5f6b5c5e06070f0efca96227a863e00000000000000000000000000000000 '
			msg: '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f'
			out: 'f3477e7cd95417af89a6b8794c310cf0 '
		},
		// A.3.4 case
		PolyCase{
			keys: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
			msg: '2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e'
			out: '4541669a7eaaee61e708dc7cbcc5eb62'
		},
	]
)

// test the five test cases above
fn test_poly1305_mac_vector_1to4() {
	for c in poly_cases {
		bkeys := hex2byte(c.keys) or { return }
		bmsg := hex2byte(c.msg) or { return }
		expected_tag := hex2byte(c.out) or { return }

		tag := poly1305_mac(bmsg, bkeys)
		assert tag == expected_tag
	}
}

// Test Vector #5: If one uses 130-bit partial reduction, does the code
// handle the case where partially reduced final result is not fully
// reduced?
fn test_poly1305_mac_vector_5() {
	r := '02000000000000000000000000000000'
	s := '00000000000000000000000000000000'
	data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
	res_tag := '03000000000000000000000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #6: What happens if addition of s overflows modulo 2^128?
fn test_poly1305_mac_vector_6() {
	r := '02000000000000000000000000000000'
	s := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'
	data := '02000000000000000000000000000000'
	res_tag := '03000000000000000000000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #7: What happens if data limb is all ones and there is
// carry from lower limb?
fn test_poly1305_mac_vector_7() {
	r := '01000000000000000000000000000000'
	s := '00000000000000000000000000000000'
	data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF11000000000000000000000000000000'

	res_tag := '05000000000000000000000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #8: What happens if final result from polynomial part is
//   exactly 2^130-5?
fn test_poly1305_mac_vector_8() {
	r := '01000000000000000000000000000000'
	s := '00000000000000000000000000000000'
	data := 'FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFBFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE01010101010101010101010101010101'

	res_tag := '00000000000000000000000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #9: What happens if final result from polynomial part is
//  exactly 2^130-6?
fn test_poly1305_mac_vector_9() {
	r := '02000000000000000000000000000000'
	s := '00000000000000000000000000000000'
	data := 'FDFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'

	res_tag := 'FAFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #10: What happens if 5*H+L-type reduction produces
//  131-bit intermediate result?
fn test_poly1305_mac_vector_10() {
	r := '01000000000000000400000000000000'
	s := '00000000000000000000000000000000'
	data := 'E33594D7505E43B900000000000000003394D7505E4379CD01000000000000000000000000000000000000000000000001000000000000000000000000000000'

	res_tag := '14000000000000005500000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// Test Vector #11: What happens if 5*H+L-type reduction produces
//   131-bit final result?
fn test_poly1305_mac_vector_11() {
	r := '01000000000000000400000000000000'
	s := '00000000000000000000000000000000'
	data := 'E33594D7505E43B900000000000000003394D7505E4379CD010000000000000000000000000000000000000000000000'

	res_tag := '13000000000000000000000000000000'

	key := r + s
	bkeys := hex2byte(key) or { return }
	msg := hex2byte(data) or { return }
	xtag := hex2byte(res_tag) or { return }

	tag := poly1305_mac(msg, bkeys)

	assert tag == xtag
}

// https://datatracker.ietf.org/doc/html/rfc8439#section-2.6.2
// Poly1305 Key Generation Test Vector

fn test_poly1305_key_generator() {
	key := '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
	counter := u32(0)
	nonce := '000000000001020304050607'

	bkey := hex2byte(key) or { return }
	bnonce := hex2byte(nonce) or { return }

	expect := '8ad5a08b905f81cc815040274ab29471a833b637e3fd0da508dbb8e2fdd1a646'
	expected_bytes := hex2byte(expect) or { return }

	out := poly1305_key_gen(bkey, bnonce) or { return }

	assert out == expected_bytes
}

// A.4.  Poly1305 Key Generation Using ChaCha20

// Test Vector #1:
//  ==============
struct PolyKGen {
	ckey   string // chacha key
	nonce  string
	expect string
}

const (
	poly_keys_gen = [
		PolyKGen{
			ckey: '0000000000000000000000000000000000000000000000000000000000000000'
			nonce: '000000000000000000000000'
			expect: '76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7'
		},
		PolyKGen{
			ckey: '0000000000000000000000000000000000000000000000000000000000000001'
			nonce: '000000000000000000000002'
			expect: 'ecfa254f845f647473d3cb140da9e87606cb33066c447b87bc2666dde3fbb739'
		},
		PolyKGen{
			ckey: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
			nonce: '000000000000000000000002'
			expect: '965e3bc6f9ec7ed9560808f4d229f94b137ff275ca9b3fcbdd59deaad23310ae'
		},
	]
)

fn test_poly1305_key_generator_rfc_vector() {
	for c in poly_keys_gen {
		ckey_bytes := hex2byte(c.ckey) or { return }
		nonce_bytes := hex2byte(c.nonce) or { return }
		expected_bytes := hex2byte(c.expect) or { return }

		output := poly1305_key_gen(ckey_bytes, nonce_bytes) or { return }
		assert output == expected_bytes
	}
}
