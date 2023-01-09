package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"testing"
)

type mulNoDependencyCircuit struct {
	X, Y []frontend.Variable
}

func (c *mulNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
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

func TestApiMul(t *testing.T) {
	var (
		x   Variable
		y   *Wire
		z   *Wire
		err error
	)
	api := NewApi()
	x, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	y, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	z = api.Mul(Variable(x), Variable(y)).(Variable)
	test_vector_utils.AssertSliceEqual(t, z.Inputs, []*Wire{x, y}) // TODO: Find out why assert.Equal gives false positives ( []*Wire{x,x} as second argument passes when it shouldn't )

	unsorted := []*Wire{&api.circuit[0], &api.circuit[1], &api.circuit[2]}
	test_vector_utils.AssertSliceEqual(t, []*Wire{x, y, z}, unsorted)

	//sorted := topologicalSort(api.circuit)

	//test_vector_utils.AssertSliceEqual(t, sorted, []*Wire{x, y, z})

	/*assert.Equal(t, x.nbUniqueOutputs, 1)
	assert.Equal(t, y.nbUniqueOutputs, 1)
	assert.Equal(t, z.nbUniqueOutputs, 0)*/
}
