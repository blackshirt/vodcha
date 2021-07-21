module vodcha

fn test_aead_chacha20_poly_encrypt() {
	plaintext := "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
	bplaintext := plaintext.bytes()

	ptext := '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e'

	bptext := hex2byte(ptext) or { return }

	assert bptext == bplaintext

	aad := '50515253c0c1c2c3c4c5c6c7'
	aad_bytes := hex2byte(aad) or { return }

	key := '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
	key_bytes := hex2byte(key) or { return }

	iv := '4041424344454647'
	fixed := '07000000'

	nonce := fixed + iv
	bnonce := hex2byte(nonce) or { return }

	poly_key := '7bac2b252db447af09b67a55a4e955840ae1d6731075d9eb2a9375783ed553ff'
	pkey_bytes := hex2byte(poly_key) or { return }

	pkey := poly1305_key_gen(key_bytes, bnonce) or { return }
	assert pkey == pkey_bytes

	expected_ciphertext := 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116'

	expected_ciphertext_bytes := hex2byte(expected_ciphertext) or { return }

	expected_tag := '1ae10b594f09e26a7e902ecbd0600691'
	expected_tag_bytes := hex2byte(expected_tag) or { return }

	ciphertext, tag := aead_chacha20_poly_encrypt(aad_bytes, key_bytes, bnonce, bplaintext) or {
		return
	}

	assert ciphertext == expected_ciphertext_bytes
	assert tag == expected_tag_bytes
}

// A.5.  ChaCha20-Poly1305 AEAD Decryption test
fn test_aead_chacha20_poly_decrypt_vector51() {
	aad := 'f33388860000000000004e91'
	aad_bytes := hex2byte(aad) or { return }

	key := '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
	key_bytes := hex2byte(key) or { return }

	nonce := '000000000102030405060708'
	nonce_bytes := hex2byte(nonce) or { return }

	ciphertext := '64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b'
	ciphertext_bytes := hex2byte(ciphertext) or { return }

	expected_plaintext := '496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d'
	expected_plaintext_bytes := hex2byte(expected_plaintext) or { return }

	expected_tag := 'eead9d67890cbb22392336fea1851f38'
	expected_tag_bytes := hex2byte(expected_tag) or { return }

	plaintext, tag := aead_chacha20_poly_decrypt(aad_bytes, key_bytes, nonce_bytes, ciphertext_bytes) or {
		return
	}

	assert plaintext == expected_plaintext_bytes
	assert tag == expected_tag_bytes
}

fn test_chacha20_poly_encrypt_decrypt() {
	key := 'A'.repeat(32).bytes()
	nonce := 'B'.repeat(12).bytes()
	aad := 'C'.repeat(12).bytes()

	plaintext := 'ChaCha20 and Poly1305'.bytes()

	ciphertext, tag := encrypt_and_buildtag(aad, key, nonce, plaintext) or { return }

	pltext2 := decrypt_and_verify(key, nonce, ciphertext, tag, aad) or { return }

	assert plaintext == pltext2
}

fn test_aead_encrypt_decrypt_with_random_generator() {
	key := gen_random_key() or { return }
	nonce := gen_random_nonce(24) or { return }
	aad := 'i miss you'.bytes()

	plaintext := 'vodcha was xchacha poly1305 aead in v-lang'.bytes()

	cipher, tag := encrypt_and_buildtag(aad, key, nonce, plaintext) or { return }

	msg := decrypt_and_verify(key, nonce, cipher, tag, aad) or { return }

	assert plaintext == msg
}

//see provided vector test data below
fn test_aead_chacha20_poly_encrypt_from_libressl_vector_test() {
	for c in aead_cases {
		key_bytes := hex2byte(c.key) or { return }
		ad_bytes := hex2byte(c.ad) or { return }
		nonce_bytes := hex2byte(c.nonce) or { return }
		inp_bytes := hex2byte(c.inp) or { return }
		out_bytes := hex2byte(c.out) or { return }
		tag_bytes := hex2byte(c.tag) or { return }

		cipher, tag := encrypt_and_buildtag(ad_bytes, key_bytes, nonce_bytes, inp_bytes) or {
			return
		}
		assert cipher == out_bytes
		assert tag == tag_bytes
	}
}

struct AeadCase {
	key   string
	ad    string
	nonce string
	inp   string
	out   string
	tag   string
}

// from libressl vector test at https://fossies.org/linux/libressl/tests/aeadtests.txt
const (
	aead_cases = [
		AeadCase{
			key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
			ad: '50515253c0c1c2c3c4c5c6c7'
			nonce: '404142434445464748494a4b4c4d4e4f5051525354555657'
			inp: '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e'
			out: 'bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e'
			tag: 'c0875924c1c7987947deafd8780acf49'
		},
		AeadCase{
			key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
			ad: 'c0c1c2c3c4c5c6c7d0d1d2d3d4d5d6d72e202500000000090000004529000029'
			nonce: 'a0a1a2a31011121314151617'
			inp: '0000000c000040010000000a00'
			out: '610394701f8d017f7c12924889'
			tag: '6b71bfe25236efd7cdc67066906315b2'
		},
		AeadCase{
			// Test vector from RFC7539 2.8.2
			// AEAD: chacha20-poly1305
			key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
			nonce: '070000004041424344454647'
			inp: '4c616469657320616e642047656e746c656d656e206f662074686520636c617373206f66202739393a204966204920636f756c64206f6666657220796f75206f6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73637265656e20776f756c642062652069742e'
			ad: '50515253c0c1c2c3c4c5c6c7'
			out: 'd31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116'
			tag: '1ae10b594f09e26a7e902ecbd0600691'
		},
		AeadCase{
			//# Test vector from RFC7539 Appendix A.5
			// AEAD: chacha20-poly1305
			key: '1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0'
			nonce: '000000000102030405060708'
			inp: '496e7465726e65742d4472616674732061726520647261667420646f63756d656e74732076616c696420666f722061206d6178696d756d206f6620736978206d6f6e74687320616e64206d617920626520757064617465642c207265706c616365642c206f72206f62736f6c65746564206279206f7468657220646f63756d656e747320617420616e792074696d652e20497420697320696e617070726f70726961746520746f2075736520496e7465726e65742d447261667473206173207265666572656e6365206d6174657269616c206f7220746f2063697465207468656d206f74686572207468616e206173202fe2809c776f726b20696e2070726f67726573732e2fe2809d'
			ad: 'f33388860000000000004e91'
			out: '64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb24c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c8559797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523eaf4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a1049e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29a6ad5cb4022b02709b'
			tag: 'eead9d67890cbb22392336fea1851f38'
		},
		AeadCase{
			//# Test vector from RFC7634 Appendix A
			// AEAD: chacha20-poly1305
			key: '808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f'
			nonce: ' a0a1a2a31011121314151617'
			inp: '45000054a6f200004001e778c6336405c000020508005b7a3a080000553bec100007362708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363701020204'
			ad: '0102030400000005'
			out: '24039428b97f417e3c13753a4f05087b67c352e6a7fab1b982d466ef407ae5c614ee8099d52844eb61aa95dfab4c02f72aa71e7c4c4f64c9befe2facc638e8f3cbec163fac469b502773f6fb94e664da9165b82829f641e0'
			tag: '76aaa8266b7fb0f7b11b369907e1ad43'
		},
	]
)
