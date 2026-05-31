package maptocurve_octobear

import (
	"testing"

	nativemsh "github.com/consensys/gnark-crypto/ecc/octobear/multiset-hash"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type yIncrementCircuit struct {
	Msg frontend.Variable
	P   G1Affine
}

func (c *yIncrementCircuit) Define(api frontend.API) error {
	p, err := YIncrement(api, c.Msg)
	if err != nil {
		return err
	}
	p.X.AssertIsEqual(api, c.P.X)
	p.Y.AssertIsEqual(api, c.P.Y)
	return nil
}

func TestYIncrement(t *testing.T) {
	assert := test.NewAssert(t)
	msg := uint16(12345)
	p, _, err := nativemsh.Map(msg)
	assert.NoError(err)
	witness := &yIncrementCircuit{
		Msg: msg,
		P:   G1Affine{X: newE8(p.X), Y: newE8(p.Y)},
	}
	assert.CheckCircuit(&yIncrementCircuit{}, test.WithValidAssignment(witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}
