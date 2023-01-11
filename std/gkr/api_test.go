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
		api.Println("z@", i, " = ", Z[i])
		api.Println("x.y = ", api.Mul(c.X[i], c.Y[i]))
		api.AssertIsEqual(Z[i], api.Mul(c.X[i], c.Y[i]))
	}
	return nil
}

func TestMulNoDependency(t *testing.T) {
	assignment := mulNoDependencyCircuit{
		X: []frontend.Variable{1, 2},
		Y: []frontend.Variable{0, 3},
	}
	circuit := mulNoDependencyCircuit{
		X: make([]frontend.Variable, 2),
		Y: make([]frontend.Variable, 2),
	}
	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

type mulWithDependencyCircuit struct {
	XLast frontend.Variable
	Y     []frontend.Variable
}

func (c *mulWithDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x, y frontend.Variable
	var err error

	X := make([]frontend.Variable, len(c.Y))
	X[len(c.Y)-1] = c.XLast
	if x, err = gkr.Import(X); err != nil {
		return err
	}
	if y, err = gkr.Import(c.Y); err != nil {
		return err
	}
	z := gkr.Mul(x, y)

	for i := len(X) - 1; i > 0; i-- {
		gkr.Series(x, z, i-1, i)
	}

	var gkrOuts [][]frontend.Variable
	if gkrOuts, err = gkr.Compile(api); err != nil {
		return err
	}
	Z := gkrOuts[0]

	api.Println("after solving, z=", Z, ", x=", X, ", y=", c.Y)

	for i := len(X) - 1; i >= 0; i-- {
		api.AssertIsEqual(Z[i], api.Mul(X[i], c.Y[i]))
		if i > 0 {
			api.AssertIsEqual(Z[i], X[i-1])
		}
	}
	return nil
}

func TestSolveMulWithDependency(t *testing.T) {

	assignment := mulWithDependencyCircuit{
		XLast: 1,
		Y:     []frontend.Variable{3, 2},
	}
	circuit := mulWithDependencyCircuit{Y: make([]frontend.Variable, len(assignment.Y))}

	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

func TestApiMul(t *testing.T) {
	var (
		x   Variable
		y   Variable
		z   Variable
		err error
	)
	api := NewApi()
	x, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	y, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	z = api.Mul(x, y).(Variable)
	test_vector_utils.AssertSliceEqual(t, api.noPtr.circuit[z].inputs, []int{int(x), int(y)}) // TODO: Find out why assert.Equal gives false positives ( []*Wire{x,x} as second argument passes when it shouldn't )

	//unsorted := []*Wire{&api.noPtr.circuit[0], &api.noPtr.circuit[1], &api.noPtr.circuit[2]}
	//test_vector_utils.AssertSliceEqual(t, []*Wire{x, y, z}, unsorted)

	//sorted := topologicalSort(api.circuit)

	//test_vector_utils.AssertSliceEqual(t, sorted, []*Wire{x, y, z})

	/*assert.Equal(t, x.nbUniqueOutputs, 1)
	assert.Equal(t, y.nbUniqueOutputs, 1)
	assert.Equal(t, z.nbUniqueOutputs, 0)*/
}
