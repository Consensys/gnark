package emulated

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

const testCurve = ecc.BN254

func testName[T FieldParams]() string {
	var fp T
	return fmt.Sprintf("%s/limb=%d", reflect.TypeOf(fp).Name(), fp.BitsPerLimb())
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
	f.AssertIsLessOrEqual(&c.L, &c.R)
	return nil
}

func TestAssertIsLessEqualThan(t *testing.T) {
	testAssertIsLessEqualThan[Goldilocks](t)
	testAssertIsLessEqualThan[Secp256k1Fp](t)
	testAssertIsLessEqualThan[BN254Fp](t)
}

func testAssertIsLessEqualThan[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanCircuit[T]
		R, _ := rand.Int(rand.Reader, fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		witness.R = ValueOf[T](R)
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type AssertIsLessEqualThanConstantCiruit[T FieldParams] struct {
	L Element[T]
	R *big.Int
}

func (c *AssertIsLessEqualThanConstantCiruit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	R := f.NewElement(c.R)
	f.AssertIsLessOrEqual(&c.L, R)
	return nil
}

func testAssertIsLessEqualThanConstant[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanConstantCiruit[T]
		R, _ := rand.Int(rand.Reader, fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		circuit.R = R
		witness.R = R
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
	assert.Run(func(assert *test.Assert) {
		var circuit, witness AssertIsLessEqualThanConstantCiruit[T]
		R := new(big.Int).Set(fp.Modulus())
		L, _ := rand.Int(rand.Reader, R)
		circuit.R = R
		witness.R = R
		witness.L = ValueOf[T](L)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, fmt.Sprintf("overflow/%s", testName[T]()))
}

func TestAssertIsLessEqualThanConstant(t *testing.T) {
	testAssertIsLessEqualThanConstant[Goldilocks](t)
	testAssertIsLessEqualThanConstant[Secp256k1Fp](t)
	testAssertIsLessEqualThanConstant[BN254Fp](t)
}

type AddCircuit[T FieldParams] struct {
	A, B, C Element[T]
}

func (c *AddCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Add(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	testAddCircuitNoOverflow[Goldilocks](t)
	testAddCircuitNoOverflow[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	testMulCircuitNoOverflow[Goldilocks](t)
	testMulCircuitNoOverflow[Secp256k1Fp](t)
	testMulCircuitNoOverflow[BN254Fp](t)
}

func testMulCircuitNoOverflow[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MulNoOverflowCircuit[T]
		val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(fp.Modulus().BitLen())/2))
		val2, _ := rand.Int(rand.Reader, new(big.Int).Div(fp.Modulus(), val1))
		res := new(big.Int).Mul(val1, val2)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16))
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
	res := f.Mul(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	testMulCircuitOverflow[Goldilocks](t)
	testMulCircuitOverflow[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Add(&c.A, &c.B)
	res = f.Reduce(res)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	testReduceAfterAdd[Goldilocks](t)
	testReduceAfterAdd[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val3)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val1)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Sub(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	testSubtractNoOverflow[Goldilocks](t)
	testSubtractNoOverflow[Secp256k1Fp](t)
	testSubtractNoOverflow[BN254Fp](t)

	testSubtractOverflow[Goldilocks](t)
	testSubtractOverflow[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Neg(&c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestNegation(t *testing.T) {
	testNegation[Goldilocks](t)
	testNegation[Secp256k1Fp](t)
	testNegation[BN254Fp](t)
}

func testNegation[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness NegationCircuit[T]
		val1, _ := rand.Int(rand.Reader, fp.Modulus())
		res := new(big.Int).Sub(fp.Modulus(), val1)
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Inverse(&c.A)
	f.AssertIsEqual(res, &c.B)
	return nil
}

func TestInverse(t *testing.T) {
	testInverse[Goldilocks](t)
	testInverse[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Div(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	return nil
}

func TestDivision(t *testing.T) {
	testDivision[Goldilocks](t)
	testDivision[Secp256k1Fp](t)
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
		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	bits := f.ToBits(&c.Value)
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
	testToBinary[Secp256k1Fp](t)
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
		witness.Value = ValueOf[T](val1)
		witness.Bits = bits
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.FromBits(c.Bits...)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFromBinary(t *testing.T) {
	testFromBinary[Goldilocks](t)
	testFromBinary[Secp256k1Fp](t)
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

		witness.Res = ValueOf[T](val1)
		witness.Bits = bits
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	// res := c.A //f.Set(c.A) TODO @gbotrel fixme
	f.AssertIsEqual(&c.A, &c.B)
	return nil
}

func TestConstantEqual(t *testing.T) {
	testConstantEqual[Goldilocks](t)
	testConstantEqual[BN254Fp](t)
	testConstantEqual[Secp256k1Fp](t)
}

func testConstantEqual[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness EqualityCheckCircuit[T]
		val, _ := rand.Int(rand.Reader, fp.Modulus())
		witness.A = ValueOf[T](val)
		witness.B = ValueOf[T](val)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	l := f.Mul(&c.A, &c.B)
	res := f.Select(c.Selector, l, &c.C)
	f.AssertIsEqual(res, &c.D)
	return nil
}

func TestSelect(t *testing.T) {
	testSelect[Goldilocks](t)
	testSelect[Secp256k1Fp](t)
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

		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val3)
		witness.D = ValueOf[T]([]*big.Int{l, val3}[1-b])
		witness.Selector = b

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
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
	res := f.Lookup2(c.Bit0, c.Bit1, &c.A, &c.B, &c.C, &c.D)
	f.AssertIsEqual(res, &c.E)
	return nil
}

func TestLookup2(t *testing.T) {
	testLookup2[Goldilocks](t)
	testLookup2[Secp256k1Fp](t)
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

		witness.A = ValueOf[T](val1)
		witness.B = ValueOf[T](val2)
		witness.C = ValueOf[T](val3)
		witness.D = ValueOf[T](val4)
		witness.E = ValueOf[T]([]*big.Int{val1, val2, val3, val4}[randbit.Uint64()])
		witness.Bit0 = randbit.Bit(0)
		witness.Bit1 = randbit.Bit(1)

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

type MuxCircuit[T FieldParams] struct {
	Selector frontend.Variable
	Inputs   [8]Element[T]
	Expected Element[T]
}

func (c *MuxCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	inputs := make([]*Element[T], len(c.Inputs))
	for i := range inputs {
		inputs[i] = &c.Inputs[i]
	}
	res := f.Mux(c.Selector, inputs...)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestMux(t *testing.T) {
	testMux[Goldilocks](t)
	testMux[Secp256k1Fp](t)
	testMux[BN254Fp](t)
}

func testMux[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit, witness MuxCircuit[T]
		vals := make([]*big.Int, len(witness.Inputs))
		for i := range witness.Inputs {
			vals[i], _ = rand.Int(rand.Reader, fp.Modulus())
			witness.Inputs[i] = ValueOf[T](vals[i])
		}
		selector, _ := rand.Int(rand.Reader, big.NewInt(int64(len(witness.Inputs))))
		expected := vals[selector.Int64()]
		witness.Expected = ValueOf[T](expected)
		witness.Selector = selector

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	})
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
	x13 := f.Mul(&c.X1, &c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}
	x13 = f.Mul(x13, &c.X1)
	if !c.noReduce {
		x13 = f.Reduce(x13)
	}

	fx2 := f.Mul(f.NewElement(5), &c.X2)
	fx2 = f.Reduce(fx2)

	nom := f.Sub(&c.X3, &c.X4)

	denom := f.Add(&c.X5, &c.X6)

	free := f.Div(nom, denom)

	// res := f.Add(x13, fx2, free)
	res := f.Add(x13, fx2)
	res = f.Add(res, free)

	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestComputation(t *testing.T) {
	testComputation[Goldilocks](t)
	testComputation[Secp256k1Fp](t)
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

		witness.X1 = ValueOf[T](val1)
		witness.X2 = ValueOf[T](val2)
		witness.X3 = ValueOf[T](val3)
		witness.X4 = ValueOf[T](val4)
		witness.X5 = ValueOf[T](val5)
		witness.X6 = ValueOf[T](val6)
		witness.Res = ValueOf[T](res)

		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

func TestOptimisation(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := ComputationCircuit[BN254Fp]{
		noReduce: true,
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs.GetNbConstraints(), 5945)
	ccs2, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs2.GetNbConstraints(), 14859)
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
	res := f.Mul(&c.A, &c.A)
	res = f.Mul(res, &c.A)
	res = f.Mul(res, &c.A)
	f.AssertIsEqual(res, &c.Res)
	return nil
}

func TestFourMuls(t *testing.T) {
	testFourMuls[Goldilocks](t)
	testFourMuls[Secp256k1Fp](t)
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

		witness.A = ValueOf[T](val1)
		witness.Res = ValueOf[T](res)
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
	}, testName[T]())
}

func TestIssue348UnconstrainedLimbs(t *testing.T) {
	t.Skip("regression #348")
	// The inputs were found by the fuzzer. These inputs represent a case where
	// addition overflows due to unconstrained limbs. Usually for random inputs
	// this should lead to some failed assertion, but here the overflow is
	// exactly a multiple of non-native modulus and the equality assertion
	// succeeds.
	//
	// Usually, the widths of non-native element limbs should be bounded, but
	// for freshly initialised elements (using NewElement, or directly by
	// constructing the structure), we do not automatically enforce the widths.
	//
	// The bug is tracked in https://github.com/ConsenSys/gnark/issues/348
	a := big.NewInt(5)
	b, _ := new(big.Int).SetString("21888242871839275222246405745257275088548364400416034343698204186575808495612", 10)
	assert := test.NewAssert(t)
	witness := NegationCircuit[Goldilocks]{
		A: Element[Goldilocks]{overflow: 0, Limbs: []frontend.Variable{a}},
		B: Element[Goldilocks]{overflow: 0, Limbs: []frontend.Variable{b}}}
	err := test.IsSolved(&NegationCircuit[Goldilocks]{}, &witness, testCurve.ScalarField())
	// this should err but does not.
	assert.Error(err)
	err = test.IsSolved(&NegationCircuit[Goldilocks]{}, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	// this should err and does. It errs because we consider all inputs as
	// constants and the field emulation package has a short path for constant
	// inputs.
	assert.Error(err)
}

type AssertInRangeCircuit[T FieldParams] struct {
	X Element[T]
}

func (c *AssertInRangeCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	f.AssertIsInRange(&c.X)
	return nil
}

func TestAssertInRange(t *testing.T) {
	testAssertIsInRange[Goldilocks](t)
	testAssertIsInRange[Secp256k1Fp](t)
	testAssertIsInRange[BN254Fp](t)
}

func testAssertIsInRange[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		X, _ := rand.Int(rand.Reader, fp.Modulus())
		circuit := AssertInRangeCircuit[T]{}
		witness := AssertInRangeCircuit[T]{X: ValueOf[T](X)}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(&witness))
		witness2 := AssertInRangeCircuit[T]{X: ValueOf[T](0)}
		t := 0
		for i := 0; i < int(fp.NbLimbs())-1; i++ {
			L := new(big.Int).Lsh(big.NewInt(1), fp.BitsPerLimb())
			L.Sub(L, big.NewInt(1))
			witness2.X.Limbs[i] = L
			t += int(fp.BitsPerLimb())
		}
		highlimb := fp.Modulus().BitLen() - t
		L := new(big.Int).Lsh(big.NewInt(1), uint(highlimb))
		L.Sub(L, big.NewInt(1))
		witness2.X.Limbs[fp.NbLimbs()-1] = L
		assert.ProverFailed(&circuit, &witness2, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type IsZeroCircuit[T FieldParams] struct {
	X, Y Element[T]
	Zero frontend.Variable
}

func (c *IsZeroCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	R := f.Add(&c.X, &c.Y)
	api.AssertIsEqual(c.Zero, f.IsZero(R))
	return nil
}

func TestIsZero(t *testing.T) {
	testIsZero[Goldilocks](t)
	testIsZero[Secp256k1Fp](t)
	testIsZero[BN254Fp](t)
}

func testIsZero[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		X, _ := rand.Int(rand.Reader, fp.Modulus())
		Y := new(big.Int).Sub(fp.Modulus(), X)
		circuit := IsZeroCircuit[T]{}
		assert.ProverSucceeded(&circuit, &IsZeroCircuit[T]{X: ValueOf[T](X), Y: ValueOf[T](Y), Zero: 1}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
		assert.ProverSucceeded(&circuit, &IsZeroCircuit[T]{X: ValueOf[T](X), Y: ValueOf[T](0), Zero: 0}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type SqrtCircuit[T FieldParams] struct {
	X, Expected Element[T]
}

func (c *SqrtCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.Sqrt(&c.X)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestSqrt(t *testing.T) {
	testSqrt[Goldilocks](t)
	testSqrt[Secp256k1Fp](t)
	testSqrt[BN254Fp](t)
}

func testSqrt[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var X *big.Int
		exp := new(big.Int)
		for {
			X, _ = rand.Int(rand.Reader, fp.Modulus())
			if exp.ModSqrt(X, fp.Modulus()) != nil {
				break
			}
		}
		assert.ProverSucceeded(&SqrtCircuit[T]{}, &SqrtCircuit[T]{X: ValueOf[T](X), Expected: ValueOf[T](exp)}, test.WithCurves(testCurve), test.NoSerializationChecks(), test.WithBackends(backend.GROTH16, backend.PLONK))
	}, testName[T]())
}

type MulNoReduceCircuit[T FieldParams] struct {
	A, B, C          Element[T]
	expectedOverflow uint
	expectedNbLimbs  int
}

func (c *MulNoReduceCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	res := f.MulNoReduce(&c.A, &c.B)
	f.AssertIsEqual(res, &c.C)
	if res.overflow != c.expectedOverflow {
		return fmt.Errorf("unexpected overflow: got %d, expected %d", res.overflow, c.expectedOverflow)
	}
	if len(res.Limbs) != c.expectedNbLimbs {
		return fmt.Errorf("unexpected number of limbs: got %d, expected %d", len(res.Limbs), c.expectedNbLimbs)
	}
	return nil
}

func TestMulNoReduce(t *testing.T) {
	testMulNoReduce[Goldilocks](t)
	testMulNoReduce[Secp256k1Fp](t)
	testMulNoReduce[BN254Fp](t)
}

func testMulNoReduce[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		A, _ := rand.Int(rand.Reader, fp.Modulus())
		B, _ := rand.Int(rand.Reader, fp.Modulus())
		C := new(big.Int).Mul(A, B)
		C.Mod(C, fp.Modulus())
		expectedLimbs := 2*fp.NbLimbs() - 1
		expectedOverFlow := math.Ceil(math.Log2(float64(expectedLimbs+1))) + float64(fp.BitsPerLimb())
		circuit := &MulNoReduceCircuit[T]{expectedOverflow: uint(expectedOverFlow), expectedNbLimbs: int(expectedLimbs)}
		assignment := &MulNoReduceCircuit[T]{A: ValueOf[T](A), B: ValueOf[T](B), C: ValueOf[T](C)}
		assert.CheckCircuit(circuit, test.WithValidAssignment(assignment))
	}, testName[T]())
}

type SumCircuit[T FieldParams] struct {
	Inputs   []Element[T]
	Expected Element[T]
}

func (c *SumCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return err
	}
	inputs := make([]*Element[T], len(c.Inputs))
	for i := range inputs {
		inputs[i] = &c.Inputs[i]
	}
	res := f.Sum(inputs...)
	f.AssertIsEqual(res, &c.Expected)
	return nil
}

func TestSum(t *testing.T) {
	testSum[Goldilocks](t)
	testSum[Secp256k1Fp](t)
	testSum[BN254Fp](t)
}

func testSum[T FieldParams](t *testing.T) {
	var fp T
	nbInputs := 1024
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		circuit := &SumCircuit[T]{Inputs: make([]Element[T], nbInputs)}
		inputs := make([]Element[T], nbInputs)
		result := new(big.Int)
		for i := range inputs {
			val, _ := rand.Int(rand.Reader, fp.Modulus())
			result.Add(result, val)
			inputs[i] = ValueOf[T](val)
		}
		result.Mod(result, fp.Modulus())
		witness := &SumCircuit[T]{Inputs: inputs, Expected: ValueOf[T](result)}
		assert.CheckCircuit(circuit, test.WithValidAssignment(witness))
	}, testName[T]())
}

type expCircuit[T FieldParams] struct {
	Base     Element[T]
	Exp      Element[T]
	Expected Element[T]
}

func (c *expCircuit[T]) Define(api frontend.API) error {
	f, err := NewField[T](api)
	if err != nil {
		return fmt.Errorf("new variable modulus: %w", err)
	}
	res := f.Exp(&c.Base, &c.Exp)
	f.AssertIsEqual(&c.Expected, res)
	return nil
}

func testExp[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	assert.Run(func(assert *test.Assert) {
		var circuit expCircuit[T]
		base, _ := rand.Int(rand.Reader, fp.Modulus())
		exp, _ := rand.Int(rand.Reader, fp.Modulus())
		expected := new(big.Int).Exp(base, exp, fp.Modulus())
		assignment := &expCircuit[T]{
			Base:     ValueOf[T](base),
			Exp:      ValueOf[T](exp),
			Expected: ValueOf[T](expected),
		}
		assert.CheckCircuit(&circuit, test.WithValidAssignment(assignment))
	}, testName[T]())
}
func TestExp(t *testing.T) {
	testExp[Goldilocks](t)
	testExp[BN254Fr](t)
	testExp[emparams.Mod1e512](t)
}
