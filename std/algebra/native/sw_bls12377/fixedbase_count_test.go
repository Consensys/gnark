package sw_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/test"
)

type nativeBaseMulCount struct {
	S frontend.Variable
	Q G1Affine
}

func (c *nativeBaseMulCount) Define(api frontend.API) error {
	var res G1Affine
	res.ScalarMulBase(api, c.S)
	res.AssertIsEqual(api, c.Q)
	return nil
}

func TestNativeBaseMulCount(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	circuit := nativeBaseMulCount{}
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("native ScalarMulBase r1cs constraints =", ccs.GetNbConstraints())
}

// TestNativeCombScalarMulBase checks the comb-backed native ScalarMulBase
// against gnark-crypto for edge and random scalars.
func TestNativeCombScalarMulBase(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, g, _ := bls12377.Generators()
	r := fr_bls.Modulus()
	scalars := []*big.Int{
		big.NewInt(0),
		big.NewInt(1),
		big.NewInt(2),
		big.NewInt(3),
		new(big.Int).Sub(r, big.NewInt(1)),
		new(big.Int).Sub(r, big.NewInt(2)),
		new(big.Int).Lsh(big.NewInt(1), 128),
	}
	for i := 0; i < 3; i++ {
		var rnd fr_bls.Element
		_, _ = rnd.SetRandom()
		scalars = append(scalars, rnd.BigInt(new(big.Int)))
	}
	for _, s := range scalars {
		var S bls12377.G1Affine
		S.ScalarMultiplication(&g, s)
		circuit := nativeBaseMulCount{}
		witness := nativeBaseMulCount{
			S: s,
			Q: G1Affine{X: S.X.BigInt(new(big.Int)), Y: S.Y.BigInt(new(big.Int))},
		}
		err := test.IsSolved(&circuit, &witness, ecc.BW6_761.ScalarField())
		assert.NoError(err, "s=%s", s.String())
	}
}
