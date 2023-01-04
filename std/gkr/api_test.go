package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type mulNoDependencyCircuit struct {
	X, Y []frontend.Variable
}

func (c *mulNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewGkrApi()
	var x, y frontend.Variable
	var err error
	if x, err = gkr.Import(c.X); err != nil {
		return err
	}
	if y, err = gkr.Import(c.Y); err != nil {
		return err
	}
	gkr.Mul(x, y)
	var gkrOuts [][]frontend.Variable
	if gkrOuts, err = gkr.Compile(api); err != nil {
		return err
	}
	Z := gkrOuts[0]

	for i := range c.X {
		api.AssertIsEqual(Z[i], api.Mul(c.X[i], c.Y[i]))
	}
	return nil
}

func TestSolveMulNoDependency(t *testing.T) {
	assignment := mulNoDependencyCircuit{
		X: []frontend.Variable{1, 2},
		Y: []frontend.Variable{2, 3},
	}
	circuit := mulNoDependencyCircuit{
		X: make([]frontend.Variable, 2),
		Y: make([]frontend.Variable, 2),
	}
	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}
