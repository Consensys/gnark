package emulated_test

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/test"
)

func DivTestHint(nativeMod *big.Int, nativeInputs, nativeOutputs []*big.Int) error {
	return emulated.UnwrapHint(nativeInputs, nativeOutputs,
		func(mod *big.Int, inputs, outputs []*big.Int) error {
			nominator := inputs[0]
			denominator := inputs[1]
			res := new(big.Int).ModInverse(denominator, mod)
			if res == nil {
				return fmt.Errorf("no modular inverse")
			}
			res.Mul(res, nominator)
			res.Mod(res, mod)
			outputs[0].Set(res)
			return nil
		})
}

type testDivHintCircuit[T emulated.FieldParams] struct {
	Nominator   emulated.Element[T]
	Denominator emulated.Element[T]
	Expected    emulated.Element[T]
}

func (c *testDivHintCircuit[T]) Define(api frontend.API) error {
	field, err := emulated.NewField[T](api)
	if err != nil {
		return err
	}
	res, err := field.NewHint(DivTestHint, 1, &c.Nominator, &c.Denominator)
	if err != nil {
		return err
	}
	m := field.Mul(res[0], &c.Denominator)
	field.AssertIsEqual(m, &c.Nominator)
	field.AssertIsEqual(res[0], &c.Expected)
	return nil
}

func TestDivWithHInt(t *testing.T) {
	var a, b, c fr.Element
	a.SetRandom()
	b.SetRandom()
	c.Div(&a, &b)

	circuit := testDivHintCircuit[emulated.BN254Fr]{}
	witness := testDivHintCircuit[emulated.BN254Fr]{
		Nominator:   emulated.ValueOf[emulated.BN254Fr](a),
		Denominator: emulated.ValueOf[emulated.BN254Fr](b),
		Expected:    emulated.ValueOf[emulated.BN254Fr](c),
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&circuit, &witness, test.NoFuzzing(), test.NoSerialization(), test.WithCurves(ecc.BN254),
		test.WithBackends(backend.PLONK),
		test.WithSolverOpts(solver.WithHints(DivTestHint)),
	)
}
