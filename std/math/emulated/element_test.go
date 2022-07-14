package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

const testCurve = ecc.BN254

var (
	qGoldilocks *big.Int
	qSecp256k1  *big.Int
)

func init() {
	qGoldilocks, _ = new(big.Int).SetString("ffffffff00000001", 16)
	qSecp256k1, _ = new(big.Int).SetString("fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f", 16)
}

// TODO: add also cases which should fail

type emulatedField struct {
	field *field
	name  string
}

func emulatedFields(t *testing.T) []emulatedField {
	t.Helper()
	assert := require.New(t)

	if testing.Short() {
		secp256k1fp, err := newField(qSecp256k1, 64)
		assert.NoError(err)
		return []emulatedField{{secp256k1fp, "secp256k1"}}
	}

	var ret []emulatedField

	for _, l := range []int{32, 48, 64, 120} {
		bn254fp, err := newField(ecc.BN254.BaseField(), l)
		assert.NoError(err)
		ret = append(ret, emulatedField{bn254fp, "bn254fp"})

		secp256k1fp, err := newField(qSecp256k1, l)
		assert.NoError(err)
		ret = append(ret, emulatedField{secp256k1fp, "secp256k1"})
	}
	goldilocks, err := newField(qGoldilocks, 64)
	assert.NoError(err)
	ret = append(ret, emulatedField{goldilocks, "goldilocks"})
	return ret
}

func testName(ef emulatedField) string {
	return fmt.Sprintf("%s/limb=%d", ef.name, ef.field.limbSize)
}

type AssertLimbEqualityCircuit struct {
	field *field // TODO @gbotrel this is not gonna work.

	A Element
	B Element
}

func (c *AssertLimbEqualityCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Set(c.A)
	res.AssertLimbsEquality(c.B)
	return nil
}

func TestAssertLimbEqualityNoOverflow(t *testing.T) {
	for _, emulatedField := range emulatedFields(t) {
		field := emulatedField.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := AssertLimbEqualityCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
			}

			val, _ := rand.Int(rand.Reader, field.r)
			witness := AssertLimbEqualityCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val),
				B:     field.ConstantFromBigOrPanic(val),
			}
			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(emulatedField))
	}
}

type AssertIsLessEqualThanCircuit struct {
	field *field

	L Element
	R Element
}

func (c *AssertIsLessEqualThanCircuit) Define(api frontend.API) error {
	L := c.field.NewElement()
	L.Set(c.L)
	R := c.field.NewElement()
	R.Set(c.R)
	L.AssertIsLessEqualThan(R)
	return nil
}

func TestAssertIsLessEqualThan(t *testing.T) {
	for _, fp := range emulatedFields(t)[:1] {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := AssertIsLessEqualThanCircuit{
				field: field,
				L:     newElement(field),
				R:     newElement(field),
			}
			R, _ := rand.Int(rand.Reader, field.r)
			L, _ := rand.Int(rand.Reader, R)
			witness := AssertIsLessEqualThanCircuit{
				field: field,
				L:     field.ConstantFromBigOrPanic(L),
				R:     field.ConstantFromBigOrPanic(R),
			}
			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type AddCircuit struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *AddCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Add(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := AddCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, new(big.Int).Div(field.r, big.NewInt(2)))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(field.r, big.NewInt(2)))
			res := new(big.Int).Add(val1, val2)
			witness := AddCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type MulNoOverflowCircuit struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *MulNoOverflowCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Mul(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := MulNoOverflowCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(field.r.BitLen())/2))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(field.r, val1))
			res := new(big.Int).Mul(val1, val2)
			witness := MulNoOverflowCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type MulCircuitOverflow struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *MulCircuitOverflow) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Mul(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := MulCircuitOverflow{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, field.r)
			res := new(big.Int).Mul(val1, val2)
			res.Mod(res, field.r)
			witness := MulCircuitOverflow{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type ReduceAfterAddCircuit struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *ReduceAfterAddCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Add(c.A, c.B)
	res.Reduce(res)
	res.AssertIsEqual(c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ReduceAfterAddCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val2, _ := rand.Int(rand.Reader, field.r)
			val1, _ := rand.Int(rand.Reader, val2)
			val3 := new(big.Int).Add(val1, field.r)
			val3.Sub(val3, val2)
			witness := ReduceAfterAddCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val3),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(val1),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type SubtractCircuit struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *SubtractCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Sub(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SubtractCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, val1)
			res := new(big.Int).Sub(val1, val2)
			witness := SubtractCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

func TestSubtractOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SubtractCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, new(big.Int).Sub(field.r, val1))
			val2.Add(val2, val1)
			res := new(big.Int).Sub(val1, val2)
			res.Mod(res, field.r)
			witness := SubtractCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type NegationCircuit struct {
	field *field

	A Element
	B Element
}

func (c *NegationCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Negate(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestNegation(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := NegationCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			res := new(big.Int).Sub(field.r, val1)
			witness := NegationCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type InverseCircuit struct {
	field *field

	A Element
	B Element
}

func (c *InverseCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Inverse(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestInverse(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.field.hasInverses {
			continue
		}
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := InverseCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			res := new(big.Int).ModInverse(val1, field.r)
			witness := InverseCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type DivisionCircuit struct {
	field *field
	A     Element
	B     Element
	C     Element
}

func (c *DivisionCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Div(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestDivision(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.field.hasInverses {
			continue
		}
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := DivisionCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, field.r)
			res := new(big.Int)
			res.ModInverse(val2, field.r)
			res.Mul(val1, res)
			res.Mod(res, field.r)
			witness := DivisionCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type ToBitsCircuit struct {
	field *field

	Value Element
	Bits  []frontend.Variable
}

func (c *ToBitsCircuit) Define(api frontend.API) error {
	el := c.field.NewElement()
	el.Set(c.Value)
	bits := el.ToBits()
	if len(bits) != len(c.Bits) {
		return fmt.Errorf("got %d bits, expected %d", len(bits), len(c.Bits))
	}
	for i := range bits {
		api.AssertIsEqual(bits[i], c.Bits[i])
	}
	return nil
}

func TestToBits(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			bitLen := field.limbSize * field.nbLimbs
			circuit := ToBitsCircuit{
				field: field,
				Value: newElement(field),
				Bits:  make([]frontend.Variable, bitLen),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			bits := make([]frontend.Variable, bitLen)
			for i := 0; i < len(bits); i++ {
				bits[i] = val1.Bit(i)
			}
			witness := ToBitsCircuit{
				field: field,
				Value: field.ConstantFromBigOrPanic(val1),
				Bits:  bits,
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type FromBitsCircuit struct {
	field *field

	Bits []frontend.Variable
	Res  Element
}

func (c *FromBitsCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.FromBits(c.Bits)
	res.AssertIsEqual(c.Res)
	return nil
}

func TestFromBits(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			bitLen := field.r.BitLen()
			circuit := FromBitsCircuit{
				field: field,
				Bits:  make([]frontend.Variable, bitLen),
				Res:   newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			bits := make([]frontend.Variable, bitLen)
			for i := 0; i < len(bits); i++ {
				bits[i] = val1.Bit(i)
			}
			witness := FromBitsCircuit{
				field: field,
				Bits:  bits,
				Res:   field.ConstantFromBigOrPanic(val1),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK), test.WithProverOpts(backend.WithHints(GetHints()...)))
		}, testName(fp))
	}
}

type ConstantCircuit struct {
	field *field

	A Element
	B Element
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Set(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestConstant(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ConstantCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
			}
			val, _ := rand.Int(rand.Reader, field.r)
			witness := ConstantCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val),
				B:     field.ConstantFromBigOrPanic(val),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK), test.WithProverOpts(backend.WithHints(GetHints()...)))
		}, testName(fp))
	}
}

type SelectCircuit struct {
	field *field

	Selector frontend.Variable
	A        Element
	B        Element
	C        Element
}

func (c *SelectCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Select(c.Selector, c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestSelect(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SelectCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, field.r)
			randbit, _ := rand.Int(rand.Reader, big.NewInt(2))
			b := randbit.Uint64()
			witness := SelectCircuit{
				field:    field,
				A:        field.ConstantFromBigOrPanic(val1),
				B:        field.ConstantFromBigOrPanic(val2),
				C:        field.ConstantFromBigOrPanic([]*big.Int{val1, val2}[1-b]),
				Selector: b,
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type Lookup2Circuit struct {
	field *field

	Bit0 frontend.Variable
	Bit1 frontend.Variable
	A    Element
	B    Element
	C    Element
	D    Element
	E    Element
}

func (c *Lookup2Circuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Lookup2(c.Bit0, c.Bit1, c.A, c.B, c.C, c.D)
	res.AssertIsEqual(c.E)
	return nil
}

func TestLookup2(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := Lookup2Circuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
				D:     newElement(field),
				E:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, field.r)
			val3, _ := rand.Int(rand.Reader, field.r)
			val4, _ := rand.Int(rand.Reader, field.r)
			randbit, _ := rand.Int(rand.Reader, big.NewInt(4))
			witness := Lookup2Circuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(val3),
				D:     field.ConstantFromBigOrPanic(val4),
				E:     field.ConstantFromBigOrPanic([]*big.Int{val1, val2, val3, val4}[randbit.Uint64()]),
				Bit0:  randbit.Bit(0),
				Bit1:  randbit.Bit(1),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

type ComputationCircuit struct {
	field    *field
	noReduce bool

	X1, X2, X3, X4, X5, X6 Element
	Res                    Element
}

func (c *ComputationCircuit) Define(api frontend.API) error {
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := c.field.NewElement()
	x13.Mul(c.X1, c.X1)
	if !c.noReduce {
		x13.Reduce(x13)
	}
	x13.Mul(x13, c.X1)
	if !c.noReduce {
		x13.Reduce(x13)
	}

	fx2 := c.field.NewElement()
	five, err := c.field.ConstantFromBig(big.NewInt(5))
	if err != nil {
		return fmt.Errorf("five: %w", err)
	}
	fx2.Mul(five, c.X2)
	fx2.Reduce(fx2)

	nom := c.field.NewElement()
	nom.Sub(c.X3, c.X4)

	denom := c.field.NewElement()
	denom.Add(c.X5, c.X6)

	free := c.field.NewElement()
	free.Div(nom, denom)

	res := c.field.NewElement()
	res.Add(x13, fx2)
	res.Add(res, free)

	res.AssertIsEqual(c.Res)
	return nil
}

func TestComputation(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.field.hasInverses {
			continue
		}
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ComputationCircuit{
				field: field,
				X1:    newElement(field),
				X2:    newElement(field),
				X3:    newElement(field),
				X4:    newElement(field),
				X5:    newElement(field),
				X6:    newElement(field),
				Res:   newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, field.r)
			val2, _ := rand.Int(rand.Reader, field.r)
			val3, _ := rand.Int(rand.Reader, field.r)
			val4, _ := rand.Int(rand.Reader, field.r)
			val5, _ := rand.Int(rand.Reader, field.r)
			val6, _ := rand.Int(rand.Reader, field.r)

			tmp := new(big.Int)
			res := new(big.Int)
			// res = x1^3
			tmp.Exp(val1, big.NewInt(3), field.r)
			res.Set(tmp)
			// res = x1^3 + 5*x2
			tmp.Mul(val2, big.NewInt(5))
			res.Add(res, tmp)
			// tmp = (x3-x4)
			tmp.Sub(val3, val4)
			tmp.Mod(tmp, field.r)
			// tmp2 = (x5+x6)
			tmp2 := new(big.Int)
			tmp2.Add(val5, val6)
			// tmp = (x3-x4)/(x5+x6)
			tmp2.ModInverse(tmp2, field.r)
			tmp.Mul(tmp, tmp2)
			tmp.Mod(tmp, field.r)
			// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
			res.Add(res, tmp)
			res.Mod(res, field.r)

			witness := ComputationCircuit{
				field: field,
				X1:    field.ConstantFromBigOrPanic(val1),
				X2:    field.ConstantFromBigOrPanic(val2),
				X3:    field.ConstantFromBigOrPanic(val3),
				X4:    field.ConstantFromBigOrPanic(val4),
				X5:    field.ConstantFromBigOrPanic(val5),
				X6:    field.ConstantFromBigOrPanic(val6),
				Res:   field.ConstantFromBigOrPanic(res),
			}
			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}

func TestOptimisation(t *testing.T) {
	assert := test.NewAssert(t)
	field, err := newField(ecc.BN254.ScalarField(), 32)
	assert.NoError(err)
	circuit := ComputationCircuit{
		field:    field,
		noReduce: true,
		X1:       newElement(field),
		X2:       newElement(field),
		X3:       newElement(field),
		X4:       newElement(field),
		X5:       newElement(field),
		X6:       newElement(field),
		Res:      newElement(field),
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs.GetNbConstraints(), 3291)
	ccs2, err := frontend.Compile(testCurve.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(err)
	assert.LessOrEqual(ccs2.GetNbConstraints(), 10722)
}

type FourMulsCircuit struct {
	field *field
	A     Element
	Res   Element
}

func (c *FourMulsCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Mul(c.A, c.A)
	res.Mul(res, c.A)
	res.Mul(res, c.A)
	res.AssertIsEqual(c.Res)
	return nil
}

func TestFourMuls(t *testing.T) {
	assert := test.NewAssert(t)
	field, err := newField(ecc.BN254.ScalarField(), 32)
	assert.NoError(err)
	circuit := FourMulsCircuit{
		field: field,
		A:     newElement(field),
		Res:   newElement(field),
	}
	val1, _ := rand.Int(rand.Reader, field.r)
	res := new(big.Int)
	res.Mul(val1, val1)
	res.Mul(res, val1)
	res.Mul(res, val1)
	res.Mod(res, field.r)
	witness := FourMulsCircuit{
		field: field,
		A:     field.ConstantFromBigOrPanic(val1),
		Res:   field.ConstantFromBigOrPanic(res),
	}
	assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
}

type RegroupCircuit struct {
	field *field

	A Element
	B Element
	C Element
}

func (c *RegroupCircuit) Define(api frontend.API) error {
	res := c.field.NewElement()
	res.Add(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	params2 := regroupParams(c.field, uint(api.Compiler().FieldBitLen()), res.overflow)
	res2 := params2.From(res)
	C2 := params2.From(c.C)
	res2.AssertLimbsEquality(C2)
	return nil
}

func TestRegroupCircuit(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		field := fp.field
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := RegroupCircuit{
				field: field,
				A:     newElement(field),
				B:     newElement(field),
				C:     newElement(field),
			}

			val1, _ := rand.Int(rand.Reader, new(big.Int).Div(field.r, big.NewInt(2)))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(field.r, big.NewInt(2)))
			res := new(big.Int).Add(val1, val2)
			witness := RegroupCircuit{
				field: field,
				A:     field.ConstantFromBigOrPanic(val1),
				B:     field.ConstantFromBigOrPanic(val2),
				C:     field.ConstantFromBigOrPanic(res),
			}
			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16, backend.PLONK))
		}, testName(fp))
	}
}
