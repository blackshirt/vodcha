module vodcha

fn test_gen_random_key() {
	key := gen_random_key() or {return}
	assert key.len == key_size
}

fn test_get_random_nonce() {
	ch20_nonce := gen_random_nonce(12) or {return}
	assert ch20_nonce.len == nonce_size
	x20_nonce := gen_random_nonce(24) or {return}
	assert x20_nonce.len == nonce_size_x	
}

fn test_hex2byte() {
	hexnum := '1f1e1d1c1b1a19181716151413121110'
	bytes := hex2byte(hexnum) or { return }

	exp_bytes := [byte(0x1f), byte(0x1e), byte(0x1d), byte(0x1c), byte(0x1b), byte(0x1a), byte(0x19),
		byte(0x18), byte(0x17), byte(0x16), byte(0x15), byte(0x14), byte(0x13), byte(0x12),
		byte(0x11), byte(0x10)]

	assert bytes == exp_bytes
}

fn test_bytes_from_hex_and_string() {
	// s and h was the same thing
	s := 'Any submission to the IETF intended by the Contributor for publication as all or part of an IETF Internet-Draft or RFC and any statement made within the context of an IETF activity is considered an "IETF Contribution". Such statements include oral statements in IETF sessions, as well as written and electronic communications made at any time or place, which are addressed to'
	h := '416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f'

	bs := s.bytes()
	bh := hex2byte(h) or { return }
	assert bs == bh
}
