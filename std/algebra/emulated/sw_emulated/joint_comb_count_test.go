package sw_emulated

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

type jointCombCount[T, S emulated.FieldParams] struct {
	P      AffinePoint[T]
	S1, S2 emulated.Element[S]
	Q      AffinePoint[T]
	mode   int // 0: baseline complete, 1: baseline incomplete, 2: comb-composed
}

func (c *jointCombCount[T, S]) Define(api frontend.API) error {
	cr, err := New[T, S](api, GetCurveParams[T]())
	if err != nil {
		return err
	}
	var res *AffinePoint[T]
	switch c.mode {
	case 0:
		res = cr.JointScalarMulBase(&c.P, &c.S2, &c.S1)
	case 1:
		res = cr.JointScalarMulBase(&c.P, &c.S2, &c.S1, algopts.WithIncompleteArithmetic())
	case 2:
		sm1 := cr.scalarMulBaseComb(&c.S1, 8)
		sm2 := cr.ScalarMul(&c.P, &c.S2)
		res = cr.AddUnified(sm1, sm2)
	case 3:
		sm1 := cr.scalarMulBaseComb(&c.S1, 8)
		sm2 := cr.ScalarMul(&c.P, &c.S2, algopts.WithIncompleteArithmetic())
		res = cr.AddUnified(sm1, sm2)
	}
	cr.AssertIsEqual(res, &c.Q)
	return nil
}

func TestJointCombCount(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	for mode := 0; mode <= 3; mode++ {
		circuit := jointCombCount[emulated.Secp256k1Fp, emulated.Secp256k1Fr]{mode: mode}
		ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
		assert.NoError(err)
		t.Log("mode", mode, "r1cs constraints =", ccs.GetNbConstraints())
	}
}
