package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	bn254TestVectorUtils "github.com/consensys/gnark-crypto/ecc/bn254/fr/test_vector_utils"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
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
		x   constraint.GkrVariable
		y   constraint.GkrVariable
		z   constraint.GkrVariable
		err error
	)
	api := NewApi()
	x, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	y, err = api.Import([]frontend.Variable{nil, nil})
	assert.NoError(t, err)
	z = api.Mul(x, y).(constraint.GkrVariable)
	test_vector_utils.AssertSliceEqual(t, api.toStore.Circuit[z].Inputs, []int{int(x), int(y)}) // TODO: Find out why assert.Equal gives false positives ( []*Wire{x,x} as second argument passes when it shouldn't )

	//unsorted := []*Wire{&api.toStore.circuit[0], &api.toStore.circuit[1], &api.toStore.circuit[2]}
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

func BenchmarkMiMCMerkleTree(b *testing.B) {
	depth := 3
	bottom := make([]frontend.Variable, 1<<depth)

	for i := 0; i < 1<<depth; i++ {
		bottom[i] = i
	}

	assignment := benchMiMCMerkleTreeCircuit{
		depth:   depth,
		XBottom: bottom[:len(bottom)/2],
		YBottom: bottom[len(bottom)/2:],
	}

	circuit := benchMiMCMerkleTreeCircuit{
		depth:   depth,
		XBottom: make([]frontend.Variable, len(assignment.XBottom)),
		YBottom: make([]frontend.Variable, len(assignment.YBottom)),
	}

	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(b, err)
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(b, err)
	//publicWitness := witness.Public()
	pk, _, err := groth16.Setup(cs)
	assert.NoError(b, err)

	b.ResetTimer()
	_, err = groth16.Prove(cs, pk, witness)
	assert.NoError(b, err)
}

type benchMiMCMerkleTreeCircuit struct {
	depth   int
	XBottom []frontend.Variable
	YBottom []frontend.Variable
}

// hard-coded bn254
func (c *benchMiMCMerkleTreeCircuit) Define(api frontend.API) error {

	X := make([]frontend.Variable, 2*len(c.XBottom))
	Y := make([]frontend.Variable, 2*len(c.YBottom))

	copy(X, c.XBottom)
	copy(Y, c.YBottom)

	X[len(X)-1] = 0
	Y[len(X)-1] = 0

	var x, y frontend.Variable
	var err error

	gkr := NewApi()
	if x, err = gkr.Import(X); err != nil {
		return err
	}
	if y, err = gkr.Import(Y); err != nil {
		return err
	}

	// cheat{
	gkr.circuitData.toStore.Circuit = append(gkr.circuitData.toStore.Circuit, constraint.GkrWire{
		Gate:   "mimc",
		Inputs: []int{int(x.(constraint.GkrVariable)), int(y.(constraint.GkrVariable))},
	})
	z := frontend.Variable(constraint.GkrVariable(2))
	// }

	offset := 1 << (c.depth - 1)
	for d := c.depth - 2; d >= 0; d-- {
		for i := 0; i < 1<<d; i++ {
			gkr.Series(x, z, offset+i, offset-1-2*i)
			gkr.Series(y, z, offset+i, offset-2-2*i)
		}
		offset += 1 << d
	}

	solution, err := gkr.Solve(api)
	if err != nil {
		return err
	}
	Z := solution.Export(z)

	challenge, err := api.Compiler().Commit(Z...)
	if err != nil {
		return err
	}

	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}

	return solution.Verify(&hsh, challenge)
}
