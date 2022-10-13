package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

const testCurve = ecc.BN254

type AssertLimbEqualityCircuit[T FieldParams] struct {
	A, B Element[T]
}

func (c *AssertLimbEqualityCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	f.AssertLimbsEquality(c.A, c.B)
	return nil
}

func testName[T FieldParams]() string {
	var fp T
	return fmt.Sprintf("%s/limb=%d", reflect.TypeOf(fp).Name(), fp.BitsPerLimb())
}

func TestAssertLimbEqualityNoOverflow(t *testing.T) {
	testAssertLimbEqualityNoOverflow[Goldilocks](t)
	testAssertLimbEqualityNoOverflow[Secp256k1](t)
	testAssertLimbEqualityNoOverflow[BN254Fp](t)
}

func testAssertLimbEqualityNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertLimbEqualityCircuit[T]
		val, _ := rand.Int(rand.Reader, fp.Modulus())
		witness.A.Assign(val)
		witness.B.Assign(val)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

// TODO: add also cases which should fail

type AssertIsLessEqualThanCircuit[T FieldParams] struct {
	L, R Element[T]
}

func (c *AssertIsLessEqualThanCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	f.AssertIsLessOrEqual(c.L, c.R)
	return nil
}

func TestAssertIsLessEqualThan(t *testing.T) {
	testAssertIsLessEqualThan[Goldilocks](t)
	testAssertIsLessEqualThan[Secp256k1](t)
	testAssertIsLessEqualThan[BN254Fp](t)
}

func testAssertIsLessEqualThan[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanCircuit[T]
		R, _ := rand.Int(rand.Reader, fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		witness.R.Assign(R)
		witness.L.Assign(L)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type AddCircuit[T FieldParams] struct {
	A, B, C Element[T]
}

func (c *AddCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Add(c.A, c.B)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	testAddCircuitNoOverflow[Goldilocks](t)
	testAddCircuitNoOverflow[Secp256k1](t)
	testAddCircuitNoOverflow[BN254Fp](t)
}

func testAddCircuitNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AddCircuit[T]
		bound := new(big.Int).Rsh(fp.Modulus(), 1)
		val1, _ := rand.Int(rand.Reader, bound)
		val2, _ := rand.Int(rand.Reader, bound)
		res := new(big.Int).Add(val1, val2)
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type MulNoOverflowCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *MulNoOverflowCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(c.A, c.B)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	// testMulCircuitNoOverflow[Goldilocks](t)
	testMulCircuitNoOverflow[Secp256k1](t)
	// testMulCircuitNoOverflow[BN254Fp](t)
}

func testMulCircuitNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MulNoOverflowCircuit[T]
		val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(fp.Modulus().BitLen())/2))
		val2, _ := rand.Int(rand.Reader, new(big.Int).Div(fp.Modulus(), val1))
		res := new(big.Int).Mul(val1, val2)
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16))
	}, testName[T]())
}

type MulCircuitOverflow[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *MulCircuitOverflow[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(c.A, c.B)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	testMulCircuitOverflow[Goldilocks](t)
	testMulCircuitOverflow[Secp256k1](t)
	testMulCircuitOverflow[BN254Fp](t)
}

func testMulCircuitOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MulCircuitOverflow[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).Mul(val1, val2)
		res.Mod(res, fp.Modulus())
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type ReduceAfterAddCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *ReduceAfterAddCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Add(c.A, c.B)
	res = f.Reduce(res)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	testReduceAfterAdd[Goldilocks](t)
	testReduceAfterAdd[Secp256k1](t)
	testReduceAfterAdd[BN254Fp](t)
}

func testReduceAfterAdd[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ReduceAfterAddCircuit[T]
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val1, _ := rand.Int(rand.Reader, val2)
		val3 := new(big.Int).Add(val1, fp.Modulus())
		val3.Sub(val3, val2)
		witness.A.Assign(val3)
		witness.B.Assign(val2)
		witness.C.Assign(val1)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type SubtractCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *SubtractCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Sub(c.A, c.B)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	testSubtractNoOverflow[Goldilocks](t)
	testSubtractNoOverflow[Secp256k1](t)
	testSubtractNoOverflow[BN254Fp](t)

	testSubtractOverflow[Goldilocks](t)
	testSubtractOverflow[Secp256k1](t)
	testSubtractOverflow[BN254Fp](t)
}

func testSubtractNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SubtractCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, val1)
		res := new(big.Int).Sub(val1, val2)
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

func testSubtractOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SubtractCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, new(big.Int).Sub(fp.Modulus(), val1))
		val2.Add(val2, val1)
		res := new(big.Int).Sub(val1, val2)
		res.Mod(res, fp.Modulus())
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type NegationCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *NegationCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Neg(c.A)
	f.AssertIsEqual(res, c.B)
	return nil
}

func TestNegation(t *testing.T) {
	testNegation[Goldilocks](t)
	testNegation[Secp256k1](t)
	testNegation[BN254Fp](t)
}

func testNegation[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness NegationCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).Sub(fp.Modulus(), val1)
		witness.A.Assign(val1)
		witness.B.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type InverseCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *InverseCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Inverse(c.A)
	f.AssertIsEqual(res, c.B)
	return nil
}

func TestInverse(t *testing.T) {
	testInverse[Goldilocks](t)
	testInverse[Secp256k1](t)
	testInverse[BN254Fp](t)
}

func testInverse[T FieldParams](t *testing.T) {
	var fp T
	if !fp.IsPrime() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness InverseCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).ModInverse(val1, fp.Modulus())
		witness.A.Assign(val1)
		witness.B.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type DivisionCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
	C Element[T]
}

func (c *DivisionCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Div(c.A, c.B)
	f.AssertIsEqual(res, c.C)
	return nil
}

func TestDivision(t *testing.T) {
	testDivision[Goldilocks](t)
	testDivision[Secp256k1](t)
	testDivision[BN254Fp](t)
}

func testDivision[T FieldParams](t *testing.T) {
	var fp T
	if !fp.IsPrime() {
		t.Skip()
	}
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness DivisionCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int)
		res.ModInverse(val2, fp.Modulus())
		res.Mul(val1, res)
		res.Mod(res, fp.Modulus())
		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type ToBinaryCircuit[T FieldParams] struct {
	Value Element[T]
	Bits  []frontend.Variable
}

func (c *ToBinaryCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	bits := f.ToBinary(c.Value)
	if len(bits) != len(c.Bits) {
		return fmt.Errorf("got %d bits, expected %d", len(bits), len(c.Bits))
	}
	for i := range bits {
		api.AssertIsEqual(bits[i], c.Bits[i])
	}
	return nil
}

func TestToBinary(t *testing.T) {
	testToBinary[Goldilocks](t)
	testToBinary[Secp256k1](t)
	testToBinary[BN254Fp](t)
}

func testToBinary[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ToBinaryCircuit[T]
		bitLen := fp.BitsPerLimb() * fp.NbLimbs()
		circuit.Bits = make([]frontend.Variable, bitLen)
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		bits := make([]frontend.Variable, bitLen)
		for i := 0; i < len(bits); i++ {
			bits[i] = val1.Bit(i)
		}
		witness.Value.Assign(val1)
		witness.Bits = bits
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type FromBinaryCircuit[T FieldParams] struct {
	Bits []frontend.Variable
	Res  Element[T]
}

func (c *FromBinaryCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.FromBinary(c.Bits)
	f.AssertIsEqual(res, c.Res)
	return nil
}

func TestFromBinary(t *testing.T) {
	testFromBinary[Goldilocks](t)
	testFromBinary[Secp256k1](t)
	testFromBinary[BN254Fp](t)
}

func testFromBinary[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness FromBinaryCircuit[T]
		bitLen := fp.Modulus().BitLen()
		circuit.Bits = make([]frontend.Variable, bitLen)

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		bits := make([]frontend.Variable, bitLen)
		for i := 0; i < len(bits); i++ {
			bits[i] = val1.Bit(i)
		}

		witness.Res.Assign(val1)
		witness.Bits = bits
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type EqualityCheckCircuit[T FieldParams] struct {
	A Element[T]
	B Element[T]
}

func (c *EqualityCheckCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := c.A //f.Set(c.A) TODO @gbotrel fixme
	f.AssertIsEqual(res, c.B)
	return nil
}

func TestConstantEqual(t *testing.T) {
	testConstantEqual[Goldilocks](t)
	testConstantEqual[BN254Fp](t)
	testConstantEqual[Secp256k1](t)
}

func testConstantEqual[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness EqualityCheckCircuit[T]
		val, _ := rand.Int(rand.Reader, fp.Modulus())
		witness.A.Assign(val)
		witness.B.Assign(val)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type SelectCircuit[T FieldParams] struct {
	Selector frontend.Variable
	A        Element[T]
	B        Element[T]
	C        Element[T]
	D        Element[T]
}

func (c *SelectCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	l := f.Mul(c.A, c.B)
	res := f.Select(c.Selector, l, c.C)
	f.AssertIsEqual(res, c.D)
	return nil
}

func TestSelect(t *testing.T) {
	testSelect[Goldilocks](t)
	testSelect[Secp256k1](t)
	testSelect[BN254Fp](t)
}

func testSelect[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness SelectCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		l := new(big.Int).Mul(val1, val2)
		l.Mod(l, fp.Modulus())
		randbit, _ := rand.Int(rand.Reader, big.NewInt(2))
		b := randbit.Uint64()

		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(val3)
		witness.D.Assign([]*big.Int{l, val3}[1-b])
		witness.Selector = b

		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type Lookup2Circuit[T FieldParams] struct {
	Bit0 frontend.Variable
	Bit1 frontend.Variable
	A    Element[T]
	B    Element[T]
	C    Element[T]
	D    Element[T]
	E    Element[T]
}

func (c *Lookup2Circuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Lookup2(c.Bit0, c.Bit1, c.A, c.B, c.C, c.D)
	f.AssertIsEqual(res, c.E)
	return nil
}

func TestLookup2(t *testing.T) {
	testLookup2[Goldilocks](t)
	testLookup2[Secp256k1](t)
	testLookup2[BN254Fp](t)
}

func testLookup2[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness Lookup2Circuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		val4, _ := rand.Int(rand.Reader, fp.Modulus())
		randbit, _ := rand.Int(rand.Reader, big.NewInt(4))

		witness.A.Assign(val1)
		witness.B.Assign(val2)
		witness.C.Assign(val3)
		witness.D.Assign(val4)
		witness.E.Assign([]*big.Int{val1, val2, val3, val4}[randbit.Uint64()])
		witness.Bit0 = randbit.Bit(0)
		witness.Bit1 = randbit.Bit(1)

		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type ComputationCircuit[T FieldParams] struct {
	noReduce bool

	X1, X2, X3, X4, X5, X6 Element[T]
	Res                    Element[T]
}

func (c *ComputationCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := f.Mul(c.X1, c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}
	x13 = f.Mul(x13, c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}

	fx2 := f.Mul(5, c.X2)
	fx2 = f.Reduce(fx2)

	nom := f.Sub(c.X3, c.X4)

	denom := f.Add(c.X5, c.X6)

	free := f.Div(nom, denom)

	res := f.Add(x13, fx2, free)

	f.AssertIsEqual(res, c.Res)
	return nil
}

func TestComputation(t *testing.T) {
	testComputation[Goldilocks](t)
	testComputation[Secp256k1](t)
	testComputation[BN254Fp](t)
}

func testComputation[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness ComputationCircuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		val2, _ := rand.Int(rand.Reader, fp.Modulus())
		val3, _ := rand.Int(rand.Reader, fp.Modulus())
		val4, _ := rand.Int(rand.Reader, fp.Modulus())
		val5, _ := rand.Int(rand.Reader, fp.Modulus())
		val6, _ := rand.Int(rand.Reader, fp.Modulus())

		tmp := new(big.Int)
		res := new(big.Int)
		// res = x1^3
		tmp.Exp(val1, big.NewInt(3), fp.Modulus())
		res.Set(tmp)
		// res = x1^3 + 5*x2
		tmp.Mul(val2, big.NewInt(5))
		res.Add(res, tmp)
		// tmp = (x3-x4)
		tmp.Sub(val3, val4)
		tmp.Mod(tmp, fp.Modulus())
		// tmp2 = (x5+x6)
		tmp2 := new(big.Int)
		tmp2.Add(val5, val6)
		// tmp = (x3-x4)/(x5+x6)
		tmp2.ModInverse(tmp2, fp.Modulus())
		tmp.Mul(tmp, tmp2)
		tmp.Mod(tmp, fp.Modulus())
		// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
		res.Add(res, tmp)
		res.Mod(res, fp.Modulus())

		witness.X1.Assign(val1)
		witness.X2.Assign(val2)
		witness.X3.Assign(val3)
		witness.X4.Assign(val4)
		witness.X5.Assign(val5)
		witness.X6.Assign(val6)
		witness.Res.Assign(res)

		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

func TestOptimisation(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := ComputationCircuit[BN254Fp]{
		noReduce: true,
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs.GetNbConstraints(), 3291)
	ccs2, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs2.GetNbConstraints(), 10722)
}

type FourMulsCircuit[T FieldParams] struct {
	A   Element[T]
	Res Element[T]
}

func (c *FourMulsCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Mul(c.A, c.A, c.A, c.A)
	f.AssertIsEqual(res, c.Res)
	return nil
}

func TestFourMuls(t *testing.T) {
	testFourMuls[Goldilocks](t)
	testFourMuls[Secp256k1](t)
	testFourMuls[BN254Fp](t)
}

func testFourMuls[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness FourMulsCircuit[T]

		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int)
		res.Mul(val1, val1)
		res.Mul(res, val1)
		res.Mul(res, val1)
		res.Mod(res, fp.Modulus())

		witness.A.Assign(val1)
		witness.Res.Assign(res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type PublicElement struct {
	Y Element[BN254Fp] `gnark:",public"`
}

func (c *PublicElement) Define(api frontend.API) error {
	return nil
}

func TestPublicElement(t *testing.T) {
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&PublicElement{}, &PublicElement{}, test.WithCompileOpts(frontend.IgnoreUnconstrainedInputs()))
}
