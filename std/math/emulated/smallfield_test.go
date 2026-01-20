package emulated

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
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
