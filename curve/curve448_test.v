module curve

import gmp

fn test_x448_from_rfc_test_vector() {
	scalar1 := '3d262fddf9ec8e88495266fea19a34d28882acef045104d0d1aae121700a779c984c24f8cdd78fbff44943eba368f54b29259a4f1c600ad3'
	scalar2 := '203d494428b8399352665ddca42f9de8fef600908e0d461cb021f8c538345dd77c3e4806e25f46d3315c44e0a5b4371282dd2c8d5be3095f'

	coord1 := '06fce640fa3487bfda5f6cf2d5263f8aad88334cbd07437f020f08f9814dc031ddbdc38c19c6da2583fa5429db94ada18aa7a7fb4ef8a086'
	coord2 := '0fbcc2f993cd56d3305b0b7d9e55d4c1a8fb5dbb52f8e9a1e9b6201b165d015894e56c4d3570bee52fe205e28a78b91cdfbde71ce8d157db'

	output1 := 'ce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f'
	output2 := '884a02576239ff7a2f2f63b2db6a9ff37047ac13568e1e30fe63c4a7ad1b3ee3a5700df34321d62077e63633c575c1c954514e99da7c179d'

	output1_bytes := hex2byte(output1) or { return }
	output2_bytes := hex2byte(output2) or { return }

	mut scalar1_bytes := hex2byte(scalar1) or { return }
	coord1_bytes := hex2byte(coord1) or { return }

	mut scalar2_bytes := hex2byte(scalar2) or { return }
	coord2_bytes := hex2byte(coord2) or { return }

	result1 := x448(mut scalar1_bytes, coord1_bytes)
	result2 := x448(mut scalar2_bytes, coord2_bytes)
	assert result1 == output1_bytes
	assert result2 == output2_bytes
}

fn test_x448_decode_scalar() {
	// curve := new()
	scalar1 := 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
	scalar2 := '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bf66'

	mut scalar1_bytes := hex2byte(scalar1) or { return }
	mut scalar2_bytes := hex2byte(scalar2) or { return }
	assert scalar1_bytes.len == 56
	assert scalar2_bytes.len == 56

	expected_num1 := gmp.from_str('436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884')
	expected_num2 := gmp.from_str('655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940')

	result_num1 := x448_decode_scalar(mut scalar1_bytes)
	result_num2 := x448_decode_scalar(mut scalar2_bytes)
	// assert two gmp.Number was equal
	assert gmp.cmp(result_num1, expected_num1) == 0
	assert gmp.cmp(result_num2, expected_num2) == 0

	// assert result_num.hexstr() == expected_num.hexstr()
}

fn test_x448_decode_x_coordinate() {
	coord1 := 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
	coord2 := '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bf66'
	coord1_bytes := hex2byte(coord1) or { return }
	coord2_bytes := hex2byte(coord2) or { return }

	expected_coord1 := gmp.from_str('436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884')
	expected_coord2 := gmp.from_str('291723155518334111074418999028921056388039114643338197781527351546843362695077429836238197597262191753952342817769766385834172977772612')

	result_u_coord1 := x448_decode_x_coordinate(coord1_bytes)
	result_u_coord2 := x448_decode_x_coordinate(coord2_bytes)

	assert gmp.cmp(result_u_coord1, expected_coord1) == 0
	assert gmp.cmp(result_u_coord2, expected_coord2) == 0
}

fn test_x448_encode_x_coordinate() {
	mut num1 := gmp.from_str('436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884')
	mut num2 := gmp.from_str('655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940')

	expected_output1 := 'ac3e6f34aac308c281260ea7f02bbf204cb219ef39112c5220104ff913149411711dfe2a0c5474505dd9973a668c15ed250c7fd3e396d499'
	expected_output2 := '44f863334852df04cd8f7aaf53c4e3d4c147c7fa8a8c2d4b024f54ec1827f1d0f133ca073e8be9596a9b2f052b2961e7ac18e79d2474bfe6'
	expected_output1_bytes := hex2byte(expected_output1) or { return }
	expected_output2_bytes := hex2byte(expected_output2) or { return }

	result1 := x448_encode_x_coordinate(mut num1)
	result2 := x448_encode_x_coordinate(mut num2)

	assert result1 == expected_output1_bytes
	assert result2 == expected_output2_bytes
}

fn test_x448_scalar_multiply() {
	num1 := gmp.from_str('436757467217601688366132871896080895239115033775737064806367793722968428509414077064245797888947294985659980974372068256067233566899884')
	num2 := gmp.from_str('655142517666137556349080902972923323564859794986997227922272451137163006751776391499333722954143974534333603620902855352601473792079940')

	expected_result := gmp.from_str('609560854787851861354203378668764097850269855135730507165613337764560406563982280285343525276769211508810615138239953893279036620485699')

	result := x448_scalar_multiply(num1, num2)

	assert gmp.cmp(expected_result, result) == 0
}
