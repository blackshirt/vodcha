module curve

import gmp

fn test_x25519_decode_scalar() {
	// curve := new()
	scalar1 := 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
	scalar2 := '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'

	mut scalar1_bytes := hex2byte(scalar1) or { return }
	mut scalar2_bytes := hex2byte(scalar2) or { return }
	
	expected_num1 := gmp.from_str('31029842492115040904895560451863089656472772604678260265531221036453811406496')
	expected_num2 := gmp.from_str('35156891815674817266734212754503633747128614016119564763269015315466259359304')

	result_num1 := x25519_decode_scalar(mut scalar1_bytes)
	result_num2 := x25519_decode_scalar(mut scalar2_bytes)
	// assert two was equal
	assert gmp.cmp(result_num1, expected_num1) == 0
	assert gmp.cmp(result_num2, expected_num2) == 0

	// assert result_num.hexstr() == expected_num.hexstr()
}

fn test_x25519_decode_x_coordinate() {
	coord1 := 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
	coord2 := 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'
	mut coord1_bytes := hex2byte(coord1) or { return }
	mut coord2_bytes := hex2byte(coord2) or { return }

	expected_coord1 := gmp.from_str('34426434033919594451155107781188821651316167215306631574996226621102155684838')
	expected_coord2 := gmp.from_str('8883857351183929894090759386610649319417338800022198945255395922347792736741')

	result_u_coord1 := x25519_decode_x_coordinate(mut coord1_bytes)
	result_u_coord2 := x25519_decode_x_coordinate(mut coord2_bytes)

	assert gmp.cmp(result_u_coord1, expected_coord1) == 0
	assert gmp.cmp(result_u_coord2, expected_coord2) == 0
}

fn test_x25519_encode_x_coordinate() {
	mut num1 := gmp.from_str('34426434033919594451155107781188821651316167215306631574996226621102155684838')
	mut num2 := gmp.from_str('8883857351183929894090759386610649319417338800022198945255395922347792736741')

	expected_output1 := 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
	expected_output2 := 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a413'
	expected_output1_bytes := hex2byte(expected_output1) or { return }
	expected_output2_bytes := hex2byte(expected_output2) or { return }

	result1 := x25519_encode_x_coordinate(mut num1)
	result2 := x25519_encode_x_coordinate(mut num2)

	assert result1 == expected_output1_bytes
	assert result2 == expected_output2_bytes
}

fn test_x25519_scalar_multiply() {
	num1 := gmp.from_str('34426434033919594451155107781188821651316167215306631574996226621102155684838')
	num2 := gmp.from_str('8883857351183929894090759386610649319417338800022198945255395922347792736741')

	expected_result := gmp.from_str('30288769775299154322453471711435182976155832952747871841100586939672915661451')

	result := x25519_scalar_multiply(num1, num2)

	assert gmp.cmp(expected_result, result) == 0

	// calculation from working python implementation
	n1 := gmp.from_str('31029842492115040904895560451863089656472772604678260265531221036453811406496')
	n2 := gmp.from_str('35156891815674817266734212754503633747128614016119564763269015315466259359304')

	exp := gmp.from_str('9687847192437982599224399286282328413310936304537917893524998943417340894289')
	res := x25519_scalar_multiply(n1, n2)
	assert gmp.cmp(res, exp) == 0
}

fn test_x25519() {
	scalar1 := 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
	scalar2 := '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'

	coord1 := 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
	coord2 := 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'

	output1 := 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'
	output2 := '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'

	output1_bytes := hex2byte(output1) or { return }
	output2_bytes := hex2byte(output2) or { return }

	mut scalar1_bytes := hex2byte(scalar1) or { return }
	mut coord1_bytes := hex2byte(coord1) or { return }

	mut scalar2_bytes := hex2byte(scalar2) or { return }
	mut coord2_bytes := hex2byte(coord2) or { return }

	result1 := x25519(mut scalar1_bytes, mut coord1_bytes)
	result2 := x25519(mut scalar2_bytes, mut coord2_bytes)
	assert result1 == output1_bytes
	assert result2 == output2_bytes
}

fn test_x25519_from_rfc_test_vector_1() {
	scalar := 'a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4'
	ucoord := 'e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c'
	output := 'c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552'

	mut scalar_bytes := hex2byte(scalar) or { return }
	mut ucoord_bytes := hex2byte(ucoord) or { return }
	output_bytes := hex2byte(output) or { return }

	result := x25519(mut scalar_bytes, mut ucoord_bytes)

	assert result == output_bytes
}

fn test_x25519_from_rfc_test_vector_2() {
	scalar := '4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d'
	ucoord := 'e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493'
	output := '95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957'

	mut scalar_bytes := hex2byte(scalar) or { return }
	mut ucoord_bytes := hex2byte(ucoord) or { return }
	output_bytes := hex2byte(output) or { return }

	result := x25519(mut scalar_bytes, mut ucoord_bytes)

	assert result == output_bytes
}


// test from rust rfc7748
// WARNING: This test still leads to memory leak, and maybe blown up your system, hanging up your OS
// with unresponsible state even with gc boehm flag `v -gc boehm -stats curve_test.v`, 
// its still being killed by os oom killer
// For this time, skip this test until the code fixed
/*
fn test_x25519_iteration() {
	iteration1 := hex2byte('422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079') or {return}
	iteration1000 := hex2byte('684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51') or {return}
	iteration1000000 := hex2byte('7c3911e0ab2586fd864497297e575e6f3bc601c0883c30df5f4dd2d24f665424') or {return}

	key := '0900000000000000000000000000000000000000000000000000000000000000'
	mut k := hex2byte(key) or {return}
	mut u := k.clone()
	//mut r := []byte{}

	for i in 0..1000000 {
		println("start i: $i")
		tmp_k := k.clone()
		r := x25519(mut k, mut u)
		unsafe {u = tmp_k}
		unsafe {k = r}
		if i == 0 {
			assert k == iteration1
		} else if i == 999 {
			assert k == iteration1000
		} else if i == 999999 {
			assert k == iteration1000000
		}
		unsafe {tmp_k.free()}
		//unsafe {r.free()}
	}
	unsafe {k.free()}
	unsafe {u.free()}
	unsafe {r.free()}
}
*/
