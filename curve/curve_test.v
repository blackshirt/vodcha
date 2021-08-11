module curve

import gmp

fn test_curve_cswap() {
	num1 := gmp.from_str('34426434033919594451155107781188821651316167215306631574996226621102155684838')
	num2 := gmp.from_str('8883857351183929894090759386610649319417338800022198945255395922347792736741')

	r1, r2 := cswap(gmp.from_u64(1), num1, num2)

	assert gmp.cmp(r1, num2) == 0
	assert gmp.cmp(r2, num1) == 0
}

struct TestDecodeScalar {
	scalar   string
	expected string
}

fn test_curve_decode_scalar() {
	data := [
		TestDecodeScalar{
			scalar: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
			expected: '31029842492115040904895560451863089656472772604678260265531221036453811406496'
		},
		TestDecodeScalar{
			scalar: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'
			expected: '35156891815674817266734212754503633747128614016119564763269015315466259359304'
		},
		TestDecodeScalar{
			scalar: 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
			expected: '436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884'
		},
		TestDecodeScalar{
			scalar: '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bf66'
			expected: '655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940'
		},
	]
	for t in data {
		mut scalar_bytes := hex2byte(t.scalar) or { return }
		expected_num := gmp.from_str(t.expected)
		if scalar_bytes.len == 32 {
			cv := new_curve(255) or { return }
			result := cv.decode_scalar(mut scalar_bytes) or { return }
			assert gmp.cmp(result, expected_num) == 0
		}
		if scalar_bytes.len == 56 {
			cv := new_curve(448) or { return }
			result := cv.decode_scalar(mut scalar_bytes) or { return }
			assert gmp.cmp(result, expected_num) == 0
		}
	}
}

struct XCord {
	xcord    string
	expected string
}

fn test_curve_decode_x_coordinate() {
	data := [
		// decode_x_coordinate
		XCord{
			xcord: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
			expected: '34426434033919594451155107781188821651316167215306631574996226621102155684838'
		},
		XCord{
			xcord: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'
			expected: '8883857351183929894090759386610649319417338800022198945255395922347792736741'
		},
		XCord{
			xcord: 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
			expected: '436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884'
		},
		XCord{
			xcord: '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bf66'
			expected: '291723155518334111074418999028921056388039114643338197781527351546843362695077429836238197597262191753952342817769766385834172977772612'
		},
	]
	for t in data {
		mut xcord_bytes := hex2byte(t.xcord) or { return }
		expected_num := gmp.from_str(t.expected)
		if xcord_bytes.len == 32 {
			cv := new_curve(255) or { return }
			result_x_coord := cv.decode_x_coordinate(mut xcord_bytes) or { return }
			assert gmp.cmp(result_x_coord, expected_num) == 0
		}
		if xcord_bytes.len == 56 {
			cv := new_curve(448) or { return }
			result_x_coord := cv.decode_x_coordinate(mut xcord_bytes) or { return }
			assert gmp.cmp(result_x_coord, expected_num) == 0
		}
	}
}

fn test_curve_encode_x_coordinate() {
	data := [
		XCord{
			xcord: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
			expected: '34426434033919594451155107781188821651316167215306631574996226621102155684838'
		},
		XCord{
			xcord: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413'
			expected: '8883857351183929894090759386610649319417338800022198945255395922347792736741'
		},
		XCord{
			xcord: 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
			expected: '436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884'
		},
		XCord{
			xcord: '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bfe6'
			expected: '655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940'
		},
	]

	for t in data {
		mut num := gmp.from_str(t.expected)
		output := hex2byte(t.xcord) or { return }

		if output.len == 32 {
			cv := new_curve(255) or { return }
			result := cv.encode_x_coordinate(mut num)
			assert result == output
		}
		if output.len == 56 {
			cv := new_curve(448) or { return }
			result := cv.encode_x_coordinate(mut num)
			assert result == output
		}
	}
}

struct ScalMul {
	num1   string
	num2   string
	result string
}

fn test_curve_255_scalar_multiply() {
	data := [
		ScalMul{
			num1: '34426434033919594451155107781188821651316167215306631574996226621102155684838'
			num2: '8883857351183929894090759386610649319417338800022198945255395922347792736741'
			result: '30288769775299154322453471711435182976155832952747871841100586939672915661451'
		},
		// from working python implementation
		ScalMul{
			num1: '31029842492115040904895560451863089656472772604678260265531221036453811406496'
			num2: '35156891815674817266734212754503633747128614016119564763269015315466259359304'
			result: '9687847192437982599224399286282328413310936304537917893524998943417340894289'
		},
	]
	for t in data {
		n1 := gmp.from_str(t.num1)
		n2 := gmp.from_str(t.num2)
		exp := gmp.from_str(t.result)
		cv := new_curve(255) or { return }
		res := cv.scalar_multiply(n1, n2) or { return }
		assert gmp.cmp(res, exp) == 0
	}
}

fn test_curve_448_scalar_multiply() {
	data := [
		ScalMul{
			num1: '436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884'
			num2: '655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940'
			result: '609560854787851861354203378668764097850269855135730507165613337764560406563982280285343525276769211508810615138239953893279036620485699'
		},
	]
	for t in data {
		n1 := gmp.from_str(t.num1)
		n2 := gmp.from_str(t.num2)
		exp := gmp.from_str(t.result)
		cv := new_curve(448) or { return }
		res := cv.scalar_multiply(n1, n2) or { return }
		assert gmp.cmp(res, exp) == 0
	}
}

struct Xdata {
	k string 
	u string 
	out string 
}

fn test_curve_x25519_rfc_vector() {
	data := [
		Xdata{
			k: 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
			u: 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
			out: 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
		},
		Xdata{
			k: '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'
			u: 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'
			out: '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'
		},
	]
	
	for t in data {
		mut scalar := hex2byte(t.k) or {return}
		mut cord := hex2byte(t.u) or {return}

		expected := hex2byte(t.out) or {return}
		
		cv := new_curve(255) or {return}
		result := cv.x25519(mut scalar, mut cord) or {return}
		assert result == expected
	}
}

fn test_curve_x448_rfc_vector() {
	data := [
		Xdata{
			k: '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3'
			u: '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086'
			out: 'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f'
		},
		Xdata{
			k: '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f'
			u: '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db'
			out: '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d'
		},
	]
	for t in data {
		mut scalar := hex2byte(t.k) or {return}
		mut cord := hex2byte(t.u) or {return}

		expected := hex2byte(t.out) or {return}
		
		cv := new_curve(448) or {return}
		result := cv.x448(mut scalar, mut cord) or {return}
		assert result == expected
	}
}


// WARNING: This test still leads to memory leak, and maybe blown up your system, hanging up your OS
// with unresponsible state even with gc boehm flag `v -gc boehm -stats curve_test.v`, 
// its still being killed by os oom killer

// Update: its being fixed with `v_gmp` being updated with memory management updated, see
// https://github.com/VincentLaisney/v_gmp/commit/f348524bb68a052abcfd74ac8102e7ab9f0d8b0a
// You can run test with `-gc boehm` flag being activated, but `-autofree` still suffers error
// Just uncomment this test to be included in test run
/*
fn test_curve_x25519_iteration() {
	iteration1 := hex2byte('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079') or {return}
	iteration1000 := hex2byte('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51') or {return}
	iteration1000000 := hex2byte('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424') or {return}

	key := '0900000000000000000000000000000000000000000000000000000000000000'
	mut k := hex2byte(key) or {return}
	mut u := k.clone()
	cv := new_curve(255) or {return}
	
	for i in 0..1000000 {
		println("start i: $i")
		tmp_k := k.clone()
		r := cv.x25519(mut k, mut u)
		unsafe {u = tmp_k}
		unsafe {k = r}
		if i == 0 {
			assert k == iteration1
		} else if i == 999 {
			assert k == iteration1000
		} else if i == 999999 {
			assert k == iteration1000000
		}
		
	}
}
*/

/*
fn test_curve_x448_iteration() {
	iteration1 := hex2byte('3f482c8a9f19b01e6c46ee9711d9dc14fd4bf67af30765c2ae2b846a4d23a8cd0db897086239492caf350b51f833868b9bc2b3bca9cf4113') or {return}
	iteration1000 := hex2byte('aa3b4749d55b9daf1e5b00288826c467274ce3ebbdd5c17b975e09d4af6c67cf10d087202db88286e2b79fceea3ec353ef54faa26e219f38') or {return}
	iteration1000000 := hex2byte('077f453681caca3693198420bbe515cae0002472519b3e67661a7e89cab94695c8f4bcd66e61b9b9c946da8d524de3d69bd9d9d66b997e37') or {return}

	mut k := hex2byte('0500000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000') or {return}
	mut u := k.clone()
	//mut r := []byte{}
	cv := new_curve(448) or {return}
	for i in 0..1000000 {
		println("start i: $i")
		tmp_k := k.clone()
		r := cv.x448(mut k, mut u)
		unsafe {u = tmp_k}
		unsafe {k = r}
		if i == 0 {
			assert k == iteration1
		} else if i == 999 {
			assert k == iteration1000
		} else if i == 999999 {
			assert k == iteration1000000
		}
		
	}
}
*/