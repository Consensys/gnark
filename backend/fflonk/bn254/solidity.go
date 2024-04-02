package fflonk

// MarshalSolidity convert  s a proof to a byte array that can be used in a
// Solidity contract.
func (proof *Proof) MarshalSolidity() []byte {

	res := make([]byte, 0, 1024)

	// uint256 lro_entangled_com_x;
	// uint256 lro_entangled_com_y;
	var tmp64 [64]byte
	tmp64 = proof.LROEntangled.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 Z non entangled
	tmp64 = proof.Z.RawBytes()
	res = append(res, tmp64[:]...)

	// uint256 Z entangled
	tmp64 = proof.ZEntangled.RawBytes()
	res = append(res, tmp64[:]...)

	// H entangled
	tmp64 = proof.HEntangled.RawBytes()
	res = append(res, tmp64[:]...)

	// BSB commitments
	for i := 0; i < len(proof.BsbComEntangled); i++ {
		tmp64 = proof.BsbComEntangled[i].RawBytes()
		res = append(res, tmp64[:]...)
	}

	// at this stage we serialise the fflonk proof

	// claimed values of (in that order):
	// ql, qr, qm, qo, qkIncomplete, s1, s2, s3, qcp_i, l, r, o, z, h1, h2, h3, bsb_i at ζ
	// z at ωζ
	var tmp32 [32]byte
	for i := 0; i < len(proof.BatchOpeningProof.ClaimedValues[0]); i++ {
		tmp32 = proof.BatchOpeningProof.ClaimedValues[0][i][0].Bytes()
		res = append(res, tmp32[:]...)
	}
	tmp32 = proof.BatchOpeningProof.ClaimedValues[0][0][0].Bytes()
	res = append(res, tmp32[:]...)

	// shplonk.W
	tmp64 = proof.BatchOpeningProof.SOpeningProof.W.RawBytes()
	res = append(res, tmp64[:]...)

	// shplonk.WPrime
	tmp64 = proof.BatchOpeningProof.SOpeningProof.WPrime.RawBytes()
	res = append(res, tmp64[:]...)

	// shplonk.ClaimedValues
	for i := 0; i < len(proof.BatchOpeningProof.SOpeningProof.ClaimedValues[0]); i++ {
		tmp32 = proof.BatchOpeningProof.SOpeningProof.ClaimedValues[0][i].Bytes()
		res = append(res, tmp32[:]...)
	}
	tmp32 = proof.BatchOpeningProof.SOpeningProof.ClaimedValues[1][0].Bytes()
	res = append(res, tmp32[:]...)

	return res
}
