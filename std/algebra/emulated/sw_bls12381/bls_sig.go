package sw_bls12381

import (
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
)

const g2_dst = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_"

func BlsAssertG2Verification(api frontend.API, pub G1Affine, sig G2Affine, msg []uints.U8) error {
	pairing, e := NewPairing(api)
	if e != nil {
		return e
	}

	// public key cannot be infinity
	xtest := pairing.g1.curveF.IsZero(&pub.X)
	ytest := pairing.g1.curveF.IsZero(&pub.Y)
	pubTest := api.Or(xtest, ytest)
	api.AssertIsEqual(pubTest, 0)

	// prime order subgroup checks
	pairing.AssertIsOnG1(&pub)
	pairing.AssertIsOnG2(&sig)

	var g1GNeg bls12381.G1Affine
	_, _, g1Gen, _ := bls12381.Generators()
	g1GNeg.Neg(&g1Gen)
	g1GN := NewG1Affine(g1GNeg)

	h, e := HashToG2(api, msg, []byte(g2_dst))
	if e != nil {
		return e
	}

	return pairing.PairingCheck([]*G1Affine{&g1GN, &pub}, []*G2Affine{&sig, h})
}
