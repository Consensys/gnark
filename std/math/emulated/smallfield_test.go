package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

// SmallFieldMulCircuit is a basic circuit that tests multiplication.
type SmallFieldMulCircuit struct {
	A, B Element[emparams.KoalaBear]
	C    Element[emparams.KoalaBear] `gnark:",public"`
}

func (c *SmallFieldMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	result := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(result, &c.C)
	return nil
}

func TestSmallFieldMul(t *testing.T) {
	assert := test.NewAssert(t)

	// Test basic multiplication
	p := emparams.KoalaBear{}.Modulus()
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](a),
		B: ValueOf[emparams.KoalaBear](b),
		C: ValueOf[emparams.KoalaBear](c),
	}

	err := test.IsSolved(&SmallFieldMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

func TestSmallFieldMulProver(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with actual proving
	p := emparams.KoalaBear{}.Modulus()
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](a),
		B: ValueOf[emparams.KoalaBear](b),
		C: ValueOf[emparams.KoalaBear](c),
	}

	assert.CheckCircuit(&SmallFieldMulCircuit{}, test.WithValidAssignment(assignment), test.WithCurves(ecc.BLS12_377))
}

// SmallFieldMultipleMulCircuit tests multiple multiplications.
type SmallFieldMultipleMulCircuit struct {
	A, B, C, D Element[emparams.KoalaBear]
	Result     Element[emparams.KoalaBear] `gnark:",public"`
}

func (c *SmallFieldMultipleMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// Compute (A * B) * (C * D)
	ab := f.Mul(&c.A, &c.B)
	cd := f.Mul(&c.C, &c.D)
	result := f.Mul(ab, cd)
	f.AssertIsEqual(result, &c.Result)
	return nil
}

func TestSmallFieldMultipleMul(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()
	a := big.NewInt(100)
	b := big.NewInt(200)
	c := big.NewInt(300)
	d := big.NewInt(400)

	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, p)
	cd := new(big.Int).Mul(c, d)
	cd.Mod(cd, p)
	result := new(big.Int).Mul(ab, cd)
	result.Mod(result, p)

	assignment := &SmallFieldMultipleMulCircuit{
		A:      ValueOf[emparams.KoalaBear](a),
		B:      ValueOf[emparams.KoalaBear](b),
		C:      ValueOf[emparams.KoalaBear](c),
		D:      ValueOf[emparams.KoalaBear](d),
		Result: ValueOf[emparams.KoalaBear](result),
	}

	err := test.IsSolved(&SmallFieldMultipleMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// SmallFieldAddSubMulCircuit tests a mix of operations.
type SmallFieldAddSubMulCircuit struct {
	A, B, C Element[emparams.KoalaBear]
	Result  Element[emparams.KoalaBear] `gnark:",public"`
}

func (c *SmallFieldAddSubMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// Compute (A + B) * C
	ab := f.Add(&c.A, &c.B)
	result := f.Mul(ab, &c.C)
	f.AssertIsEqual(result, &c.Result)
	return nil
}

func TestSmallFieldAddSubMul(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()
	a := big.NewInt(100)
	b := big.NewInt(200)
	c := big.NewInt(300)

	ab := new(big.Int).Add(a, b)
	result := new(big.Int).Mul(ab, c)
	result.Mod(result, p)

	assignment := &SmallFieldAddSubMulCircuit{
		A:      ValueOf[emparams.KoalaBear](a),
		B:      ValueOf[emparams.KoalaBear](b),
		C:      ValueOf[emparams.KoalaBear](c),
		Result: ValueOf[emparams.KoalaBear](result),
	}

	err := test.IsSolved(&SmallFieldAddSubMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// SmallFieldManyMulCircuit tests many multiplications to verify batching.
type SmallFieldManyMulCircuit struct {
	Inputs []Element[emparams.KoalaBear]
	Result Element[emparams.KoalaBear] `gnark:",public"`
}

func (c *SmallFieldManyMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	if len(c.Inputs) < 2 {
		return nil
	}

	result := f.Mul(&c.Inputs[0], &c.Inputs[1])
	for i := 2; i < len(c.Inputs); i++ {
		result = f.Mul(result, &c.Inputs[i])
	}
	f.AssertIsEqual(result, &c.Result)
	return nil
}

func TestSmallFieldManyMul(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()
	n := 10

	inputs := make([]Element[emparams.KoalaBear], n)
	inputsWitness := make([]Element[emparams.KoalaBear], n)
	result := big.NewInt(1)

	for i := 0; i < n; i++ {
		val := big.NewInt(int64(i + 2))
		inputsWitness[i] = ValueOf[emparams.KoalaBear](val)
		result.Mul(result, val)
		result.Mod(result, p)
	}

	assignment := &SmallFieldManyMulCircuit{
		Inputs: inputsWitness,
		Result: ValueOf[emparams.KoalaBear](result),
	}

	circuit := &SmallFieldManyMulCircuit{
		Inputs: inputs,
	}

	err := test.IsSolved(circuit, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// TestSmallFieldMulWithZero tests multiplication by zero.
func TestSmallFieldMulWithZero(t *testing.T) {
	assert := test.NewAssert(t)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](0),
		B: ValueOf[emparams.KoalaBear](12345),
		C: ValueOf[emparams.KoalaBear](0),
	}

	err := test.IsSolved(&SmallFieldMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// TestSmallFieldMulWithOne tests multiplication by one.
func TestSmallFieldMulWithOne(t *testing.T) {
	assert := test.NewAssert(t)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](1),
		B: ValueOf[emparams.KoalaBear](12345),
		C: ValueOf[emparams.KoalaBear](12345),
	}

	err := test.IsSolved(&SmallFieldMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// TestSmallFieldMulModulus tests multiplication resulting in modulus wraparound.
func TestSmallFieldMulModulus(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()
	// Choose values that will overflow and wrap around
	a := new(big.Int).Sub(p, big.NewInt(1)) // p-1
	b := big.NewInt(2)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](a),
		B: ValueOf[emparams.KoalaBear](b),
		C: ValueOf[emparams.KoalaBear](c),
	}

	err := test.IsSolved(&SmallFieldMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// TestSmallFieldMulRandom tests with random values.
func TestSmallFieldMulRandom(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()

	for i := 0; i < 10; i++ {
		a, _ := rand.Int(rand.Reader, p)
		b, _ := rand.Int(rand.Reader, p)
		c := new(big.Int).Mul(a, b)
		c.Mod(c, p)

		assignment := &SmallFieldMulCircuit{
			A: ValueOf[emparams.KoalaBear](a),
			B: ValueOf[emparams.KoalaBear](b),
			C: ValueOf[emparams.KoalaBear](c),
		}

		err := test.IsSolved(&SmallFieldMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
		assert.NoError(err)
	}
}

// TestSmallFieldBabyBear tests with BabyBear field.
type BabyBearMulCircuit struct {
	A, B Element[emparams.BabyBear]
	C    Element[emparams.BabyBear] `gnark:",public"`
}

func (c *BabyBearMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.BabyBear](api)
	if err != nil {
		return err
	}

	result := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(result, &c.C)
	return nil
}

func TestSmallFieldBabyBear(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.BabyBear{}.Modulus()
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &BabyBearMulCircuit{
		A: ValueOf[emparams.BabyBear](a),
		B: ValueOf[emparams.BabyBear](b),
		C: ValueOf[emparams.BabyBear](c),
	}

	err := test.IsSolved(&BabyBearMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// TestSmallFieldFullProve tests with full Groth16 prove/verify.
func TestSmallFieldFullProve(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping full prove test in short mode")
	}

	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &SmallFieldMulCircuit{
		A: ValueOf[emparams.KoalaBear](a),
		B: ValueOf[emparams.KoalaBear](b),
		C: ValueOf[emparams.KoalaBear](c),
	}

	assert.CheckCircuit(
		&SmallFieldMulCircuit{},
		test.WithValidAssignment(assignment),
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
	)
}

// TestSmallFieldGoldilocks tests with Goldilocks field (64-bit, also single limb).
type GoldilocksMulCircuit struct {
	A, B Element[emparams.Goldilocks]
	C    Element[emparams.Goldilocks] `gnark:",public"`
}

func (c *GoldilocksMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.Goldilocks](api)
	if err != nil {
		return err
	}

	result := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(result, &c.C)
	return nil
}

func TestSmallFieldGoldilocks(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.Goldilocks{}.Modulus()
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := new(big.Int).Mul(a, b)
	c.Mod(c, p)

	assignment := &GoldilocksMulCircuit{
		A: ValueOf[emparams.Goldilocks](a),
		B: ValueOf[emparams.Goldilocks](b),
		C: ValueOf[emparams.Goldilocks](c),
	}

	// Use BLS12-377 which has 253-bit scalar field
	// Goldilocks is 64 bits, so 2*64 + 32 = 160 < 251
	err := test.IsSolved(&GoldilocksMulCircuit{}, assignment, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}

// SmallFieldMulBenchCircuit is for benchmarking many multiplications.
type SmallFieldMulBenchCircuit struct {
	A      []Element[emparams.KoalaBear]
	Result Element[emparams.KoalaBear]
}

func (c *SmallFieldMulBenchCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	result := &c.A[0]
	for i := range c.A[1:] {
		result = f.Mul(result, &c.A[i+1])
	}
	f.AssertIsEqual(result, &c.Result)
	return nil
}

func BenchmarkSmallFieldMulConstraints(b *testing.B) {
	benchmarkCases := []struct {
		name   string
		nbMuls int
	}{
		{"100", 100},
		{"1K", 1000},
		{"10K", 10000},
		{"100K", 100000},
	}

	for _, bc := range benchmarkCases {
		b.Run(bc.name, func(b *testing.B) {
			circuit := &SmallFieldMulBenchCircuit{A: make([]Element[emparams.KoalaBear], bc.nbMuls)}

			for b.Loop() {
				// for some reason, when we don't run the loop here, then the benchmark suite
				// runs the whole benchmark multiple times. I guess it has something to do
				// with the `b.Run` above (i.e. it parallelizes etc). To avoid this, we run an
				// empty b.Loop() here to ensure we only run the compile once.
				//
				// this adds overhead as the `b.Loop()` will be run for `benchtime` period, but
				// by default it is small. Otherwise the benchmark will be very slow.
			}
			csr1, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, circuit)
			if err != nil {
				b.Fatal(err)
			}
			css, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, circuit)
			if err != nil {
				b.Fatal(err)
			}

			constraintsR1CSPerMul := float64(csr1.GetNbConstraints()) / float64(bc.nbMuls)
			b.ReportMetric(constraintsR1CSPerMul, "r1cs_constraints/mul")
			b.ReportMetric(float64(csr1.GetNbConstraints()), "r1cs_total_constraints")
			constraintsSCSPerMul := float64(css.GetNbConstraints()) / float64(bc.nbMuls)
			b.ReportMetric(constraintsSCSPerMul, "scs_constraints/mul")
			b.ReportMetric(float64(css.GetNbConstraints()), "scs_total_constraints")
			b.ReportMetric(0.0, "ns/op") // avoid ns/op reporting as we don't measure time here
		})
	}
}

// TestConstraintCountReduction verifies the constraint count is reduced.
func TestConstraintCountReduction(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping constraint count verification in short mode")
	}

	const nbMuls = 100

	circuit := &SmallFieldMulBenchCircuit{A: make([]Element[emparams.KoalaBear], nbMuls)}

	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	constraintsPerMul := float64(cs.GetNbConstraints()) / nbMuls

	// The small field optimization should give us less than 50 constraints per mul
	// (compared to ~93 for the standard polynomial approach)
	if constraintsPerMul > 50 {
		t.Errorf("constraint count too high: %.2f constraints/mul (expected < 50)", constraintsPerMul)
	}

	t.Logf("Small field optimization: %.2f constraints/mul for 100 muls", constraintsPerMul)
}

// MaliciousMulCircuit is a circuit with 5 multiplications for testing the soundness fix.
type MaliciousMulCircuit struct {
	A, B, C, D, E, F Element[emparams.KoalaBear]
	Result           Element[emparams.KoalaBear] `gnark:",public"`
}

func (c *MaliciousMulCircuit) Define(api frontend.API) error {
	f, err := NewField[emparams.KoalaBear](api)
	if err != nil {
		return err
	}

	// 5 multiplications: ((A*B) * (C*D)) * (E*F)
	ab := f.MulMod(&c.A, &c.B)
	cd := f.MulMod(&c.C, &c.D)
	ef := f.MulMod(&c.E, &c.F)
	abcd := f.MulMod(ab, cd)
	result := f.MulMod(abcd, ef)
	f.AssertIsEqual(result, &c.Result)
	return nil
}

// maliciousSmallMulHint is a hint that returns an incorrect quotient.
// It computes q = (a*b - r') * p^{-1} (mod native) where r' != a*b mod p.
// This should cause the circuit to fail due to the sum-of-quotients range check.
func maliciousSmallMulHint(nativeMod *big.Int, inputs, outputs []*big.Int) error {
	if len(inputs) != 4 {
		return fmt.Errorf("expected 4 inputs, got %d", len(inputs))
	}
	if len(outputs) != 2 {
		return fmt.Errorf("expected 2 outputs, got %d", len(outputs))
	}

	// inputs[0] = nbBits (unused here)
	// inputs[1] = p (emulated modulus)
	// inputs[2] = a
	// inputs[3] = b
	p := inputs[1]
	a := inputs[2]
	b := inputs[3]

	// Compute a * b
	ab := new(big.Int).Mul(a, b)

	// Compute correct r = a*b mod p
	correctR := new(big.Int).Mod(ab, p)

	// Use a WRONG remainder: r' = (r + 1) mod p
	// This is still in range [0, p) but is incorrect
	wrongR := new(big.Int).Add(correctR, big.NewInt(1))
	wrongR.Mod(wrongR, p)

	// Compute q' = (a*b - r') * p^{-1} (mod native)
	// This satisfies a*b ≡ q'*p + r' (mod native) but NOT over integers
	diff := new(big.Int).Sub(ab, wrongR)
	pInv := new(big.Int).ModInverse(p, nativeMod)
	if pInv == nil {
		// If p has no inverse, fall back to correct computation
		q := new(big.Int)
		r := new(big.Int)
		q.QuoRem(ab, p, r)
		outputs[0].Set(q)
		outputs[1].Set(r)
		return nil
	}
	wrongQ := new(big.Int).Mul(diff, pInv)
	wrongQ.Mod(wrongQ, nativeMod)

	outputs[0].Set(wrongQ)
	outputs[1].Set(wrongR)
	return nil
}

// TestSmallFieldMaliciousHintRejected verifies that a malicious prover cannot
// use wrap-around in the native field to provide incorrect quotients.
// This is a regression test for the soundness fix that adds a batched range check
// on the sum of quotients.
func TestSmallFieldMaliciousHintRejected(t *testing.T) {
	assert := test.NewAssert(t)

	p := emparams.KoalaBear{}.Modulus()

	// Create valid inputs and compute the correct result
	a := big.NewInt(12345)
	b := big.NewInt(67890)
	c := big.NewInt(11111)
	d := big.NewInt(22222)
	e := big.NewInt(33333)
	f := big.NewInt(44444)

	// Compute ((a*b) * (c*d)) * (e*f) mod p
	ab := new(big.Int).Mul(a, b)
	ab.Mod(ab, p)
	cd := new(big.Int).Mul(c, d)
	cd.Mod(cd, p)
	ef := new(big.Int).Mul(e, f)
	ef.Mod(ef, p)
	abcd := new(big.Int).Mul(ab, cd)
	abcd.Mod(abcd, p)
	result := new(big.Int).Mul(abcd, ef)
	result.Mod(result, p)

	assignment := &MaliciousMulCircuit{
		A:      ValueOf[emparams.KoalaBear](a),
		B:      ValueOf[emparams.KoalaBear](b),
		C:      ValueOf[emparams.KoalaBear](c),
		D:      ValueOf[emparams.KoalaBear](d),
		E:      ValueOf[emparams.KoalaBear](e),
		F:      ValueOf[emparams.KoalaBear](f),
		Result: ValueOf[emparams.KoalaBear](result),
	}

	// First verify the circuit works with the correct hint
	assert.CheckCircuit(
		&MaliciousMulCircuit{},
		test.WithValidAssignment(assignment),
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
	)

	// Now try with the malicious hint - this should fail due to the range check
	// on the sum of quotients. The malicious hint produces q values that are
	// much larger than expected (≈ native/p instead of < p), causing the sum
	// to exceed the allowed range.
	//
	// But we have to run the full prover for testing as the solver doesn't check
	assert.CheckCircuit(
		&MaliciousMulCircuit{},
		test.WithInvalidAssignment(assignment),
		test.WithCurves(ecc.BLS12_377),
		test.WithBackends(backend.GROTH16),
		test.NoTestEngine(), // test engine doesn't replace hints
		test.WithSolverOpts(solver.OverrideHint(solver.GetHintID(smallMulHint), maliciousSmallMulHint)), // replace with malicious hint
	)
}
