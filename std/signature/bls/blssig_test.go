package bls

import (
	"encoding/hex"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bls12381"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type blsG2SigCircuit struct {
	Pub PublicKeyG1
	Msg []uints.U8
	Sig SignatureG2
}

func (c *blsG2SigCircuit) Define(api frontend.API) error {
	return c.Pub.Verify(api, &c.Sig, c.Msg)
}

var testCasesG2Sig = []struct {
	pubkey string
	msg    string
	sig    string
	output bool
}{
	{
		"a491d1b0ecd9bb917989f0e74f0dea0422eac4a873e5e2644f368dffb9a6e20fd6e10c1b77654d067c0618f6e5a7f79a",
		"5656565656565656565656565656565656565656565656565656565656565656",
		"882730e5d03f6b42c3abc26d3372625034e1d871b65a8a6b900a56dae22da98abbe1b68f85e49fe7652a55ec3d0591c20767677e33e5cbb1207315c41a9ac03be39c2e7668edc043d6cb1d9fd93033caa8a1c5b0e84bedaeb6c64972503a43eb",
		true,
	},
}

func TestBlsSigTestSolve(t *testing.T) {
	assert := test.NewAssert(t)

	for _, tc := range testCasesG2Sig {
		pubB, err := hex.DecodeString(tc.pubkey)
		assert.NoError(err, "failed to decode pubkey hex")
		msgB, err := hex.DecodeString(tc.msg)
		assert.NoError(err, "failed to decode msg hex")
		sigB, err := hex.DecodeString(tc.sig)
		assert.NoError(err, "failed to decode sig hex")

		var pub bls12381.G1Affine
		n, err := pub.SetBytes(pubB)
		assert.NoError(err, "failed to set pubkey bytes")
		assert.Equal(n, len(pubB), "pubkey bytes length mismatch")
		var sig bls12381.G2Affine
		n, err = sig.SetBytes(sigB)
		assert.NoError(err, "failed to set signature bytes")
		assert.Equal(n, len(sigB), "signature bytes length mismatch")

		err = test.IsSolved(&blsG2SigCircuit{Msg: make([]uints.U8, len(msgB))}, &blsG2SigCircuit{
			Pub: PublicKeyG1(sw_bls12381.NewG1Affine(pub)),
			Msg: uints.NewU8Array(msgB),
			Sig: SignatureG2(sw_bls12381.NewG2Affine(sig)),
		}, ecc.BN254.ScalarField())
		assert.NoError(err, "test solve failed")
	}
}
