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

type nativeG2BaseMulCount struct {
	S frontend.Variable
	Q g2AffP
}

func (c *nativeG2BaseMulCount) Define(api frontend.API) error {
	var res g2AffP
	res.ScalarMulBase(api, c.S)
	res.AssertIsEqual(api, c.Q)
	return nil
}

func TestNativeG2BaseMulCount(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	circuit := nativeG2BaseMulCount{}
	ccs, err := frontend.Compile(ecc.BW6_761.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("native G2 ScalarMulBase r1cs constraints =", ccs.GetNbConstraints())
}

// TestNativeG2CombScalarMulBase checks the comb-backed G2 ScalarMulBase
// against gnark-crypto for edge and random scalars.
func TestNativeG2CombScalarMulBase(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, g2 := bls12377.Generators()
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
		var S bls12377.G2Affine
		S.ScalarMultiplication(&g2, s)
		circuit := nativeG2BaseMulCount{}
		var w nativeG2BaseMulCount
		w.S = s
		w.Q.Assign(&S)
		err := test.IsSolved(&circuit, &w, ecc.BW6_761.ScalarField())
		assert.NoError(err, "s=%s", s.String())
	}
}

func TestNativeG2CombRejectsWrappedScalarRecode(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, g2 := bls12377.Generators()
	d, err := g2CombDataFor(
		g2.X.A0.BigInt(new(big.Int)),
		g2.X.A1.BigInt(new(big.Int)),
		g2.Y.A0.BigInt(new(big.Int)),
		g2.Y.A1.BigInt(new(big.Int)),
	)
	assert.NoError(err)

	var wrong bls12377.G2Affine
	wrong.ScalarMultiplication(&g2, nativeCombNegativeTwoNScalar(d.n))
	var witness nativeG2BaseMulCount
	witness.S = nativeCombWrappedScalar(d.n)
	witness.Q.Assign(&wrong)

	err = nativeCombSolveWithZeroRecode(&nativeG2BaseMulCount{}, &witness)
	assert.Error(err, "wrapped scalar accepted with malicious all-zero comb recode")
}
