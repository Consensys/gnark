package gkr

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/stretchr/testify/assert"
	"hash"
	"strconv"
	"testing"
)

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

	xValuess := [][]frontend.Variable{
		{1, 1},
		{1, 2},
	}

	hashes := []string{"-1", "-20"}

	for _, xValues := range xValuess {
		for _, hashName := range hashes {
			assignment := sqNoDependencyCircuit{X: xValues}
			circuit := sqNoDependencyCircuit{X: make([]frontend.Variable, len(xValues)), hashName: hashName}
			solve(t, &circuit, &assignment)
		}
	}
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
	xValuess := [][]frontend.Variable{
		{1, 2},
	}
	yValuess := [][]frontend.Variable{
		{0, 3},
	}

	hashes := []string{"-1", "-20"}

	for i := range xValuess {
		for _, hashName := range hashes {

			assignment := mulNoDependencyCircuit{
				X: xValuess[i],
				Y: yValuess[i],
			}
			circuit := mulNoDependencyCircuit{
				X:        make([]frontend.Variable, len(xValuess[i])),
				Y:        make([]frontend.Variable, len(yValuess[i])),
				hashName: hashName,
			}

			solve(t, &circuit, &assignment)
		}
	}
}

type mulWithDependencyCircuit struct {
	XLast    frontend.Variable
	Y        []frontend.Variable
	hashName string
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
	return solution.Verify(c.hashName)
}

func TestSolveMulWithDependency(t *testing.T) {

	assignment := mulWithDependencyCircuit{
		XLast: 1,
		Y:     []frontend.Variable{3, 2},
	}
	circuit := mulWithDependencyCircuit{Y: make([]frontend.Variable, len(assignment.Y)), hashName: "-20"}

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
}

func BenchmarkMiMCMerkleTree(b *testing.B) {
	depth := 2
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
	gkr.assignments = append(gkr.assignments, nil)
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

	return solution.Verify("-20", challenge)
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

	registerMiMCGate()
	//registerMessageCounter(0, 1)
}

func registerMiMCGate() {
	RegisteredGates["mimc"] = MiMCCipherGate{Ark: 0}
	bn254r1cs.GkrGateRegistry["mimc"] = mimcCipherGate{}
}

type constHashBn254 int // TODO @Tabaie move to gnark-crypto

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

// Copied from gnark-crypto TODO: Make public?
type mimcCipherGate struct {
	ark fr.Element
}

func (m mimcCipherGate) Evaluate(input ...fr.Element) (res fr.Element) {
	var sum fr.Element

	sum.
		Add(&input[0], &input[1]).
		Add(&sum, &m.ark)

	res.Square(&sum)    // sum^2
	res.Mul(&res, &sum) // sum^3
	res.Square(&res)    //sum^6
	res.Mul(&res, &sum) //sum^7

	return
}

func (m mimcCipherGate) Degree() int {
	return 7
}
