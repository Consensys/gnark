package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254TestVectorUtils "github.com/consensys/gnark-crypto/ecc/bn254/fr/test_vector_utils"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"hash"
	"testing"
)

type doubleNoDependencyCircuit struct {
	X []frontend.Variable
}

func (c *doubleNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x frontend.Variable
	var err error
	if x, err = gkr.Import(c.X); err != nil {
		return err
	}
	z := gkr.Add(x, x)
	var solution Solution
	if solution, err = gkr.Solve(api); err != nil {
		return err
	}
	Z := solution.Export(z)

	for i := range Z {
		api.AssertIsEqual(Z[i], api.Mul(2, c.X[i]))
	}

	var hsh mimc.MiMC
	if hsh, err = mimc.NewMiMC(api); err != nil {
		return err
	}
	//hsh := messageCounter{startState: 0, step: 1}
	return solution.Verify(&hsh)
}

func TestDoubleNoDependencyCircuit(t *testing.T) {
	assignment := doubleNoDependencyCircuit{X: []frontend.Variable{1, 1}}
	circuit := doubleNoDependencyCircuit{X: make([]frontend.Variable, 2)}

	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

type sqNoDependencyCircuit struct {
	X []frontend.Variable
}

func (c *sqNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x frontend.Variable
	var err error
	if x, err = gkr.Import(c.X); err != nil {
		return err
	}
	z := gkr.Mul(x, x)
	var solution Solution
	if solution, err = gkr.Solve(api); err != nil {
		return err
	}
	Z := solution.Export(z)

	for i := range Z {
		api.AssertIsEqual(Z[i], api.Mul(c.X[i], c.X[i]))
	}

	var hsh mimc.MiMC
	if hsh, err = mimc.NewMiMC(api); err != nil {
		return err
	}
	//var hsh hash.Hash = &literalSum{initialState: 0}
	//hsh := messageCounter{startState: 0, step: 1}
	return solution.Verify(&hsh)
}

func TestSqNoDependencyCircuit(t *testing.T) {
	assignment := sqNoDependencyCircuit{X: []frontend.Variable{1, 1}}
	circuit := sqNoDependencyCircuit{X: make([]frontend.Variable, 2)}

	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

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
	z := gkr.Mul(x, y)
	var solution Solution
	if solution, err = gkr.Solve(api); err != nil {
		return err
	}
	X := solution.Export(x)
	Y := solution.Export(y)
	Z := solution.Export(z)
	api.Println("after solving, z=", Z, ", x=", X, ", y=", Y)

	for i := range c.X {
		api.Println("z@", i, " = ", Z[i])
		api.Println("x.y = ", api.Mul(c.X[i], c.Y[i]))
		api.AssertIsEqual(Z[i], api.Mul(c.X[i], c.Y[i]))
	}

	var hsh mimc.MiMC
	if hsh, err = mimc.NewMiMC(api); err != nil {
		return err
	}
	//hsh := messageCounter{startState: 0, step: 1}
	return solution.Verify(&hsh)
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

	var solution Solution
	if solution, err = gkr.Solve(api); err != nil {
		return err
	}
	X = solution.Export(x)
	Y := solution.Export(y)
	Z := solution.Export(z)

	api.Println("after solving, z=", Z, ", x=", X, ", y=", Y)

	lastI := len(X) - 1
	api.AssertIsEqual(Z[lastI], api.Mul(c.XLast, Y[lastI]))
	for i := 0; i < lastI; i++ {
		api.AssertIsEqual(Z[i], api.Mul(Z[i+1], Y[i]))
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

type messageCounter struct {
	startState int
	step       int
	state      int
}

func (c *messageCounter) Sum() frontend.Variable {
	fmt.Println("snarkHash returning", c.state)
	return c.state
}

func (c *messageCounter) Write(data ...frontend.Variable) {
	c.state += len(data) * c.step
}

func (c *messageCounter) Reset() {
	c.state = c.startState
}

func (c *messageCounter) ToStandard() hash.Hash {
	return bn254TestVectorUtils.NewMessageCounter(c.startState, c.step)
}
