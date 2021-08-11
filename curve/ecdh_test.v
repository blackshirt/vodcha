module curve

fn test_check_all_zeros() {
	nol := []byte{}
	assert is_all_zeros(nol) == true
	a := [byte(0), 0, 0, 0, 1]
	mut b := a.clone()
	b[0]=1
	b[4]=0
	assert is_all_zeros(a) == false
	assert is_all_zeros(b) == false
	mut c := a.clone()
	c[4]=0
	assert is_all_zeros(c) == true
}

fn test_x25519_keypair_from_privkey() {
	//alice's private key
	mut apriv_key := hex2byte('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a') or {return}
	// Alice's public key, X25519(apriv_key, 9):
	apub_key := hex2byte('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a') or {return}
	//Bob's private key:
	mut bpriv_key := hex2byte('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb') or {return}
	//Bob's public key, X25519(bpriv_key, 9):
	bpub_key := hex2byte('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f') or {return}
	//Their shared secret, K:
	//k := hex2byte('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742') or {return}
	cv := new_curve(255) or {return}

	alice_keypair := new_x25519_keypair_from_privkey(cv, mut apriv_key) or {return}
	bob_keypair := new_x25519_keypair_from_privkey(cv, mut bpriv_key) or {return}

	assert alice_keypair.public_key() == apub_key
	assert bob_keypair.public_key() == bpub_key

}

fn test_x255_ecdh() {
	//rfc test vector
	//alice's private key
	mut apriv_key := hex2byte('77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a') or {return}
	// Alice's public key, X25519(apriv_key, 9):
	apub_key := hex2byte('8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a') or {return}
	//Bob's private key:
	mut bpriv_key := hex2byte('5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb') or {return}
	//Bob's public key, X25519(bpriv_key, 9):
	bpub_key := hex2byte('de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f') or {return}
	//Their shared secret, K:
	k := hex2byte('4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742') or {return}

	cv := new_curve(255) or {return}

	mut alice_keypair := new_x25519_keypair_from_privkey(cv, mut apriv_key) or {return}
	mut bob_keypair := new_x25519_keypair_from_privkey(cv, mut bpriv_key) or {return}

	shared_key1 := alice_keypair.x25519_ecdh(cv, mut bob_keypair.public_key()) or {return}
	shared_key2 := bob_keypair.x25519_ecdh(cv, mut alice_keypair.public_key()) or {return}

	assert shared_key1 == k 
	assert shared_key2 == k 
}

fn test_random_ecdh_key_exchange() {
	mut cv := new_curve(255) or {return}
	mut alice_keypair := new_random_x25519_keypair(cv) or {return}
	mut bob_keypair := new_random_x25519_keypair(cv) or {return}

	shared_key1 := alice_keypair.x25519_ecdh(cv, mut bob_keypair.public_key()) or {return}
	shared_key2 := bob_keypair.x25519_ecdh(cv, mut alice_keypair.public_key()) or {return}

	assert shared_key1 == shared_key2
}

fn test_x448_ecdh() {
	//rfc test vector
	//Alice's private key, a:
    mut apriv_key := hex2byte('9a8f4925d1519f5775cf46b04b5800d4ee9ee8bae8bc5565d498c28dd9c9baf574a9419744897391006382a6f127ab1d9ac2d8c0a598726b') or {return}
   	//Alice's public key, X448(a, 5):
    apub_key := hex2byte('9b08f7cc31b7e3e67d22d5aea121074a273bd2b83de09c63faa73d2c22c5d9bbc836647241d953d40c5b12da88120d53177f80e532c41fa0') or {return}
   	//Bob's private key, b:
    mut bpriv_key := hex2byte('1c306a7ac2a0e2e0990b294470cba339e6453772b075811d8fad0d1d6927c120bb5ee8972b0d3e21374c9c921b09d1b0366f10b65173992d') or {return}
   	//Bob's public key, X448(b, 5):
    bpub_key := hex2byte('3eb7a829b0cd20f5bcfc0b599b6feccf6da4627107bdb0d4f345b43027d8b972fc3e34fb4232a13ca706dcb57aec3dae07bdc1c67bf33609') or {return}
   	//Their shared secret, K:
    k := hex2byte('07fff4181ac6cc95ec1c16a94a0f74d12da232ce40a77552281d282bb60c0b56fd2464c335543936521c24403085d59a449a5037514a879d') or {return}

	cv := new_curve(448) or {return}
	
	mut alice_keypair := new_x448_keypair_from_privkey(cv, mut apriv_key) or {return}
	mut bob_keypair := new_x448_keypair_from_privkey(cv, mut bpriv_key) or {return}

	assert alice_keypair.public_key() == apub_key
	assert bob_keypair.public_key() == bpub_key

	shared_key1 := alice_keypair.x448_ecdh(cv, mut bob_keypair.public_key()) or {return}
	shared_key2 := bob_keypair.x448_ecdh(cv, mut alice_keypair.public_key()) or {return}

	assert shared_key1 == k 
	assert shared_key2 == k 
}