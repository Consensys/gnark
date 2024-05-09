package gkr

import (
	"fmt"
	"hash"
	"math/rand"
	"strconv"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/kzg"
	"github.com/consensys/gnark/backend/plonk"
	bn254r1cs "github.com/consensys/gnark/constraint/bn254"
	"github.com/stretchr/testify/require"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	bn254MiMC "github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	stdHash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/hash/mimc"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test/unsafekzg"
)

// compressThreshold --> if linear expressions are larger than this, the frontend will introduce
// intermediate constraints. The lower this number is, the faster compile time should be (to a point)
// but resulting circuit will have more constraints (slower proving time).
const compressThreshold = 1000

type doubleNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
}

func (c *doubleNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x constraint.GkrVariable
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

			testGroth16(t, &circuit, &assignment)
			testPlonk(t, &circuit, &assignment)
		}
	}
}

type sqNoDependencyCircuit struct {
	X        []frontend.Variable
	hashName string
}

func (c *sqNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x constraint.GkrVariable
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
			testGroth16(t, &circuit, &assignment)
			testPlonk(t, &circuit, &assignment)
		}
	}
}

type mulNoDependencyCircuit struct {
	X, Y     []frontend.Variable
	hashName string
}

func (c *mulNoDependencyCircuit) Define(api frontend.API) error {
	gkr := NewApi()
	var x, y constraint.GkrVariable
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

			testGroth16(t, &circuit, &assignment)
			testPlonk(t, &circuit, &assignment)
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
	var x, y constraint.GkrVariable
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

	testGroth16(t, &circuit, &assignment)
	testPlonk(t, &circuit, &assignment)
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
	require.NoError(t, err)
	y, err = api.Import([]frontend.Variable{nil, nil})
	require.NoError(t, err)
	z = api.Mul(x, y)
	test_vector_utils.AssertSliceEqual(t, api.toStore.Circuit[z].Inputs, []int{int(x), int(y)}) // TODO: Find out why assert.Equal gives false positives ( []*Wire{x,x} as second argument passes when it shouldn't )
}

func BenchmarkMiMCMerkleTree(b *testing.B) {
	depth := 14
	//fmt.Println("start")
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

	benchProof(b, &circuit, &assignment)
}

func benchCompile(b *testing.B, circuit frontend.Circuit) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
		require.NoError(b, err)
	}
}

func benchProof(b *testing.B, circuit, assignment frontend.Circuit) {
	fmt.Println("compiling...")
	start := time.Now().UnixMicro()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(b, err)
	fmt.Println("compiled in", time.Now().UnixMicro()-start, "μs")
	fullWitness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(b, err)
	//publicWitness := fullWitness.Public()
	fmt.Println("setting up...")
	pk, _, err := groth16.Setup(cs)
	require.NoError(b, err)

	fmt.Println("solving and proving...")
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		id := rand.Uint32() % 256 //#nosec G404 -- This is a false positive
		start = time.Now().UnixMicro()
		fmt.Println("groth16 proving", id)
		_, err = groth16.Prove(cs, pk, fullWitness)
		require.NoError(b, err)
		fmt.Println("groth16 proved", id, "in", time.Now().UnixMicro()-start, "μs")

		fmt.Println("mimc total calls: fr=", mimcFrTotalCalls, ", snark=", mimcSnarkTotalCalls)
	}
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

	var x, y constraint.GkrVariable
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
		Inputs: []int{int(x), int(y)},
	})
	gkr.assignments = append(gkr.assignments, nil)
	z := constraint.GkrVariable(2)
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

	challenge, err := api.(frontend.Committer).Commit(Z...)
	if err != nil {
		return err
	}

	return solution.Verify("-20", challenge)
}

func testGroth16(t *testing.T, circuit, assignment frontend.Circuit) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(t, err)
	var (
		fullWitness   witness.Witness
		publicWitness witness.Witness
		pk            groth16.ProvingKey
		vk            groth16.VerifyingKey
		proof         groth16.Proof
	)
	fullWitness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err = fullWitness.Public()
	require.NoError(t, err)
	pk, vk, err = groth16.Setup(cs)
	require.NoError(t, err)
	proof, err = groth16.Prove(cs, pk, fullWitness)
	require.NoError(t, err)
	err = groth16.Verify(proof, vk, publicWitness)
	require.NoError(t, err)
}

func testPlonk(t *testing.T, circuit, assignment frontend.Circuit) {
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit, frontend.WithCompressThreshold(compressThreshold))
	require.NoError(t, err)
	var (
		fullWitness   witness.Witness
		publicWitness witness.Witness
		pk            plonk.ProvingKey
		vk            plonk.VerifyingKey
		proof         plonk.Proof
		kzgSrs        kzg.SRS
	)
	fullWitness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	publicWitness, err = fullWitness.Public()
	require.NoError(t, err)
	kzgSrs, srsLagrange, err := unsafekzg.NewSRS(cs)
	require.NoError(t, err)
	pk, vk, err = plonk.Setup(cs, kzgSrs, srsLagrange)
	require.NoError(t, err)
	proof, err = plonk.Prove(cs, pk, fullWitness)
	require.NoError(t, err)
	err = plonk.Verify(proof, vk, publicWitness)
	require.NoError(t, err)
}

func registerMiMC() {
	bn254r1cs.RegisterHashBuilder("mimc", func() hash.Hash {
		return bn254MiMC.NewMiMC()
	})
	stdHash.Register("mimc", func(api frontend.API) (stdHash.FieldHasher, error) {
		m, err := mimc.NewMiMC(api)
		return &m, err
	})
}

func registerConstant(c int) {
	name := strconv.Itoa(c)
	bn254r1cs.RegisterHashBuilder(name, func() hash.Hash {
		return constHashBn254(c)
	})
	stdHash.Register(name, func(frontend.API) (stdHash.FieldHasher, error) {
		return constHash(c), nil
	})
}

func init() {
	registerMiMC()
	registerConstant(-1)
	registerConstant(-20)
	registerMiMCGate()
}

func registerMiMCGate() {
	Gates["mimc"] = MiMCCipherGate{Ark: 0}
	gkr.Gates["mimc"] = mimcCipherGate{}
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

var mimcFrTotalCalls = 0

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

	mimcFrTotalCalls++
	return
}

func (m mimcCipherGate) Degree() int {
	return 7
}

type mimcNoGkrCircuit struct {
	X         []frontend.Variable
	Y         []frontend.Variable
	mimcDepth int
}

func (c *mimcNoGkrCircuit) Define(api frontend.API) error {
	Z := make([]frontend.Variable, len(c.X))
	zSum := frontend.Variable(0)
	for i := range Z {
		Z[i] = c.Y[i]
		for j := 0; j < c.mimcDepth; j++ {
			Z[i] = MiMCCipherGate{Ark: 0}.Evaluate(api, c.X[i], Z[i])
		}
		zSum = api.Add(zSum, Z[i])
	}
	api.AssertIsDifferent(zSum, 0)
	return nil
}

func BenchmarkMiMCMerkleTreeNoGkrNoDep(b *testing.B) {
	nbInstances := 1 << 18
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment := mimcNoGkrCircuit{
		X: X,
		Y: Y,
	}
	circuit := mimcNoGkrCircuit{
		X: make([]frontend.Variable, nbInstances),
		Y: make([]frontend.Variable, nbInstances),
	}

	benchProof(b, &circuit, &assignment)
}

type mimcNoDepCircuit struct {
	X         []frontend.Variable
	Y         []frontend.Variable
	mimcDepth int
	hashName  string
}

func (c *mimcNoDepCircuit) Define(api frontend.API) error {
	_gkr := NewApi()
	x, err := _gkr.Import(c.X)
	if err != nil {
		return err
	}
	var (
		y, z     constraint.GkrVariable
		solution Solution
	)
	if y, err = _gkr.Import(c.Y); err != nil {
		return err
	}

	// cheat{
	z = y
	for i := 0; i < c.mimcDepth; i++ {
		_gkr.toStore.Circuit = append(_gkr.toStore.Circuit, constraint.GkrWire{
			Gate:   "mimc",
			Inputs: []int{int(x), int(z)},
		})
		_gkr.assignments = append(_gkr.assignments, nil)
		z = constraint.GkrVariable(len(_gkr.toStore.Circuit) - 1)
	}
	// }

	if solution, err = _gkr.Solve(api); err != nil {
		return err
	}
	Z := solution.Export(z)
	return solution.Verify(c.hashName, Z...)
}

func mimcNoDepCircuits(mimcDepth, nbInstances int, hashName string) (circuit, assignment frontend.Circuit) {
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment = &mimcNoDepCircuit{
		X: X,
		Y: Y,
	}
	circuit = &mimcNoDepCircuit{
		X:         make([]frontend.Variable, nbInstances),
		Y:         make([]frontend.Variable, nbInstances),
		mimcDepth: mimcDepth,
		hashName:  hashName,
	}
	return
}

func BenchmarkMiMCNoDepSolve(b *testing.B) {
	//defer profile.Start().Stop()
	circuit, assignment := mimcNoDepCircuits(1, 1<<9, "-20")
	benchProof(b, circuit, assignment)
}

func BenchmarkMiMCFullDepthNoDepSolve(b *testing.B) {
	circuit, assignment := mimcNoDepCircuits(91, 1<<19, "-20")
	benchProof(b, circuit, assignment)
}

func BenchmarkMiMCFullDepthNoDepCompile(b *testing.B) {
	circuit, _ := mimcNoDepCircuits(91, 1<<17, "-20")
	benchCompile(b, circuit)
}

func BenchmarkMiMCNoGkrFullDepthSolve(b *testing.B) {
	circuit, assignment := mimcNoGkrCircuits(91, 1<<19)
	benchProof(b, circuit, assignment)
}

func TestMiMCFullDepthNoDepSolve(t *testing.T) {
	registerMiMC()
	for i := 0; i < 100; i++ {
		circuit, assignment := mimcNoDepCircuits(5, 1<<2, "-20")
		testGroth16(t, circuit, assignment)
		testPlonk(t, circuit, assignment)
	}
}

func TestMiMCFullDepthNoDepSolveWithMiMCHash(t *testing.T) {
	registerMiMC()
	circuit, assignment := mimcNoDepCircuits(5, 1<<2, "mimc")
	testGroth16(t, circuit, assignment)
	testPlonk(t, circuit, assignment)
}

func mimcNoGkrCircuits(mimcDepth, nbInstances int) (circuit, assignment frontend.Circuit) {
	X := make([]frontend.Variable, nbInstances)
	Y := make([]frontend.Variable, nbInstances)
	for i := range X {
		X[i] = i
		Y[i] = -2*i + 1
	}
	assignment = &mimcNoGkrCircuit{
		X: X,
		Y: Y,
	}
	circuit = &mimcNoGkrCircuit{
		X:         make([]frontend.Variable, nbInstances),
		Y:         make([]frontend.Variable, nbInstances),
		mimcDepth: mimcDepth,
	}
	return
}
