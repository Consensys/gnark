package sw_bn254

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type IsOnCurveCircuit struct {
	Q G2Affine
}

func (c *IsOnCurveCircuit) Define(api frontend.API) error {
	c.Q.AssertIsOnCurve(api)
	return nil
}

func TestIsOnCurve(t *testing.T) {
	assert := test.NewAssert(t)
	_, q := randomG1G2Affines(assert)
	witness := IsOnCurveCircuit{
		Q: NewG2Affine(q),
	}
	err := test.IsSolved(&IsOnCurveCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
