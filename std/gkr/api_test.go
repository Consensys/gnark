package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"hash"
	"strconv"
	"testing"
)

//const msgCounterTemplate = "messageCounter{startState:%d, step:%d}"
//var msgCounterParams = messageCounter{}

type doubleNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
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

	return solution.Verify(c.hashName)
}

func TestDoubleNoDependencyCircuit(t *testing.T) {

	xValuess := [][]frontend.Variable{
		{1, 1},
		{1, 2},
	}

	hashes := []string{"-1", "-20"}

	for _, xValues := range xValuess {
		for _, hashName := range hashes {
			assignment := doubleNoDependencyCircuit{X: xValues}
			circuit := doubleNoDependencyCircuit{X: make([]frontend.Variable, len(xValues)), hashName: hashName}

			solve(t, &circuit, &assignment)
		}
	}
}

type sqNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
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

	return solution.Verify(c.hashName)
}

func TestSqNoDependencyCircuit(t *testing.T) {
	assignment := sqNoDependencyCircuit{X: []frontend.Variable{1, 1}}
	circuit := sqNoDependencyCircuit{X: make([]frontend.Variable, 2)}

	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.GROTH16), test.WithCurves(ecc.BN254))
}

type mulNoDependencyCircuit struct {
	X, Y     []frontend.Variable
	hashName string
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

	return solution.Verify(c.hashName)
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

	solve(t, &circuit, &assignment)
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
	fullWitness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(b, err)
	//publicWitness := fullWitness.Public()
	pk, _, err := groth16.Setup(cs)
	assert.NoError(b, err)

	b.ResetTimer()
	_, err = groth16.Prove(cs, pk, fullWitness)
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
	gkr.toStore.Circuit = append(gkr.toStore.Circuit, constraint.GkrWire{
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

	return solution.Verify("mimc", challenge)
}

func solve(t *testing.T, circuit, assignment frontend.Circuit) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	assert.NoError(t, err)
	var (
		fullWitness   *witness.Witness
		publicWitness *witness.Witness
		pk            groth16.ProvingKey
		vk            groth16.VerifyingKey
		proof         groth16.Proof
	)
	fullWitness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	assert.NoError(t, err)
	publicWitness, err = fullWitness.Public()
	assert.NoError(t, err)
	pk, vk, err = groth16.Setup(cs)
	assert.NoError(t, err)
	proof, err = groth16.Prove(cs, pk, fullWitness)
	assert.NoError(t, err)
	err = groth16.Verify(proof, vk, publicWitness)
	assert.NoError(t, err)
}

func registerMiMC() {
	bn254r1cs.HashBuilderRegistry["mimc"] = bn254MiMC.NewMiMC
	stdHash.BuilderRegistry["mimc"] = func(api frontend.API) (stdHash.Hash, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	}
}

/*func registerMessageCounter(startState int, step int) {
	name := fmt.Sprintf(msgCounterTemplate, startState, step)
	bn254r1cs.HashBuilderRegistry[name] = func() hash.Hash {
		return &bn254SumCounter{
			startState: startState,
			step:       step,
		}
	}
	stdHash.BuilderRegistry[name] = func(frontend.API) (stdHash.Hash, error) { // TODO: Move to test_vector_utils?
		return &messageCounter{
			startState: startState,
			step:       step,
		}, nil
	}
}*/

func registerConstant(c int) {
	name := strconv.Itoa(c)
	bn254r1cs.HashBuilderRegistry[name] = func() hash.Hash {
		return constHashBn254(c)
	}
	stdHash.BuilderRegistry[name] = func(frontend.API) (stdHash.Hash, error) {
		return constHash(c), nil
	}
}

func init() {
	registerMiMC()
	registerConstant(-1)
	registerConstant(-20)
	//registerMessageCounter(0, 1)
}

type constHashBn254 int

func (c constHashBn254) Write(p []byte) (int, error) {
	return len(p), nil
}

func (c constHashBn254) Sum([]byte) []byte {
	var x fr.Element
	x.SetInt64(int64(c))
	res := x.Bytes()
	return res[:]
}

func (c constHashBn254) Reset() {}

func (c constHashBn254) Size() int {
	return fr.Bytes
}

func (c constHashBn254) BlockSize() int {
	return fr.Bytes
}

type constHash int

func (c constHash) Sum() frontend.Variable {
	return int(c)
}

func (c constHash) Write(...frontend.Variable) {}

func (c constHash) Reset() {}

/*
// TODO: Incompatible with msgCtr in gnark-crypto. Decide in favor of one or the other (probably this one)
type bn254SumCounter struct {
	startState int
	step       int
	state      int
}

func (ctr *bn254SumCounter) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (ctr *bn254SumCounter) Sum([]byte) []byte {
	ctr.state += ctr.step
	res := make([]byte, fr.Bytes)
	binary.BigEndian.PutUint64(res[len(res)-8:], uint64(ctr.state))
	return res
}

func (ctr *bn254SumCounter) Reset() {
	//ctr.state = ctr.startState
}

func (ctr *bn254SumCounter) Size() int {
	return fr.Bytes
}

func (ctr *bn254SumCounter) BlockSize() int {
	return fr.Bytes
}*/
