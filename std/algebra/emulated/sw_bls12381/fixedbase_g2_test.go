package sw_bls12381

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381"
	fr_bls "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type g2FixedMulCircuit struct {
	S Scalar
	Q G2Affine
}

func (c *g2FixedMulCircuit) Define(api frontend.API) error {
	g2, err := NewG2(api)
	if err != nil {
		return err
	}
	_, _, _, gen := bls12381.Generators()
	P := NewG2Affine(gen)
	res := g2.ScalarMul(&P, &c.S)
	g2.AssertIsEqual(res, &c.Q)
	return nil
}

func TestG2FixedMulCount(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	circuit := g2FixedMulCircuit{}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("emulated G2 ScalarMul (const gen) r1cs constraints =", ccs.GetNbConstraints())
	ccs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	t.Log("emulated G2 ScalarMul (const gen) scs constraints =", ccs.GetNbConstraints())
}

func TestG2FixedMulCorrectness(t *testing.T) {
	assert := test.NewAssert(t)
	_, _, _, gen := bls12381.Generators()
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
	for i := 0; i < 2; i++ {
		var rnd fr_bls.Element
		_, _ = rnd.SetRandom()
		scalars = append(scalars, rnd.BigInt(new(big.Int)))
	}
	for _, s := range scalars {
		var S bls12381.G2Affine
		S.ScalarMultiplication(&gen, s)
		circuit := g2FixedMulCircuit{}
		witness := g2FixedMulCircuit{
			S: emulated.ValueOf[ScalarField](s),
			Q: NewG2Affine(S),
		}
		err := test.IsSolved(&circuit, &witness, ecc.BN254.ScalarField())
		assert.NoError(err, "s=%s", s.String())
	}
}
