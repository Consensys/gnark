package logderivprecomp

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type TestXORCircuit struct {
	X, Y [100]frontend.Variable
	Res  [100]frontend.Variable
}

func (c *TestXORCircuit) Define(api frontend.API) error {
	tbl, err := New(api, xorHint, []uint{8})
	if err != nil {
		return err
	}
	for i := range c.X {
		res := tbl.Query(c.X[i], c.Y[i])
		api.AssertIsEqual(res[0], c.Res[i])
	}
	return nil
}

func xorHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Xor(inputs[0], inputs[1])
	return nil
}

func TestXor(t *testing.T) {
	assert := test.NewAssert(t)
	bound := big.NewInt(255)
	var xs, ys, ress [100]frontend.Variable
	for i := range xs {
		x, _ := rand.Int(rand.Reader, bound)
		y, _ := rand.Int(rand.Reader, bound)
		ress[i] = new(big.Int).Xor(x, y)
		xs[i] = x
		ys[i] = y
	}
	witness := &TestXORCircuit{X: xs, Y: ys, Res: ress}
	assert.ProverSucceeded(&TestXORCircuit{}, witness,
		test.WithBackends(backend.GROTH16),
		test.WithSolverOpts(solver.WithHints(xorHint)),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.WithCurves(ecc.BN254))
}
