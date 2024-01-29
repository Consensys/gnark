package sw_bls12381

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type blsG2SigCircuit struct {
	Pub bls12381.G1Affine
	msg []byte
	Sig bls12381.G2Affine
}

func (c *blsG2SigCircuit) Define(api frontend.API) error {
	msg := uints.NewU8Array(c.msg)
	return BlsAssertG2Verification(api, NewG1Affine(c.Pub), NewG2Affine(c.Sig), msg)
}

// "pubkey": "0xa491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
// "message": "0x5656565656565656565656565656565656565656565656565656565656565656",
// "signature": "0x882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"},
// "output": true}
func TestBlsSigTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	msgHex := "5656565656565656565656565656565656565656565656565656565656565656"
	pubHex := "a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a"
	sigHex := "882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb"

	msgBytes := make([]byte, len(msgHex)>>1)
	hex.Decode(msgBytes, []byte(msgHex))
	pubBytes := make([]byte, len(pubHex)>>1)
	hex.Decode(pubBytes, []byte(pubHex))
	sigBytes := make([]byte, len(sigHex)>>1)
	hex.Decode(sigBytes, []byte(sigHex))

	var pub bls12381.G1Affine
	_, e := pub.SetBytes(pubBytes)
	if e != nil {
		t.Fail()
	}
	var sig bls12381.G2Affine
	_, e = sig.SetBytes(sigBytes)
	if e != nil {
		t.Fail()
	}

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)

	h, e := bls12381.HashToG2(msgBytes, []byte(g2_dst))
	if e != nil {
		t.Fail()
	}

	b, e := bls12381.PairingCheck([]bls12381.G1Affine{g1GNeg, pub}, []bls12381.G2Affine{sig, h})
	if e != nil {
		t.Fail()
	}
	if !b {
		t.Fail() // invalid inputs, won't verify
	}

	circuit := blsG2SigCircuit{
		Pub: pub,
		msg: msgBytes,
		Sig: sig,
	}
	witness := blsG2SigCircuit{
		Pub: pub,
		msg: msgBytes,
		Sig: sig,
	}
	err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
