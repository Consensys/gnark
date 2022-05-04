package nonnative

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

const testCurve = ecc.BN254

// TODO: add also cases which should fail

type emulatedField struct {
	params *Params
	name   string
}

func emulatedFields(t *testing.T) []emulatedField {
	t.Helper()
	var ret []emulatedField
	for _, limbLength := range []int{32, 48, 64, 120} {
		bn254fp, err := NewParams(limbLength, ecc.BN254.Info().Fp.Modulus())
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, emulatedField{bn254fp, "bn254fp"})
		secp256k1fp, err := NewParams(limbLength, new(big.Int).SetBytes([]byte{
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
			0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFC, 0x2F,
		}))
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, emulatedField{secp256k1fp, "secp256k1"})
	}
	return ret
}

func testName(ef emulatedField) string {
	return fmt.Sprintf("%s/limb=%d", ef.name, ef.params.nbBits)
}

type AssertLimbEqualityCircuit struct {
	params *Params

	A Element
	B Element
}

func (c *AssertLimbEqualityCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Set(c.A)
	res.AssertLimbsEquality(c.B)
	return nil
}

func TestAssertLimbEqualityNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := AssertLimbEqualityCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
			}

			val, _ := rand.Int(rand.Reader, params.r)
			witness := AssertLimbEqualityCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val),
				B:      params.ConstantFromBigOrPanic(val),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type AddCircuit struct {
	params *Params

	A Element
	B Element
	C Element
}

func (c *AddCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Add(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := AddCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, new(big.Int).Div(params.r, big.NewInt(2)))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(params.r, big.NewInt(2)))
			res := new(big.Int).Add(val1, val2)
			witness := AddCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type MulNoOverflowCircuit struct {
	params *Params

	A Element
	B Element
	C Element
}

func (c *MulNoOverflowCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Mul(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := MulNoOverflowCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(params.r.BitLen())/2))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(params.r, val1))
			res := new(big.Int).Mul(val1, val2)
			witness := MulNoOverflowCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type MulCircuitOverflow struct {
	params *Params

	A Element
	B Element
	C Element
}

func (c *MulCircuitOverflow) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Mul(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := MulCircuitOverflow{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, params.r)
			res := new(big.Int).Mul(val1, val2)
			res.Mod(res, params.r)
			witness := MulCircuitOverflow{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type ReduceAfterAddCircuit struct {
	params *Params

	A Element
	B Element
	C Element
}

func (c *ReduceAfterAddCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Add(c.A, c.B)
	res.Reduce(res)
	res.AssertIsEqual(c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ReduceAfterAddCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val2, _ := rand.Int(rand.Reader, params.r)
			val1, _ := rand.Int(rand.Reader, val2)
			val3 := new(big.Int).Add(val1, params.r)
			val3.Sub(val3, val2)
			witness := ReduceAfterAddCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val3),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(val1),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type SubtractCircuit struct {
	params *Params

	A Element
	B Element
	C Element
}

func (c *SubtractCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Sub(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SubtractCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, val1)
			res := new(big.Int).Sub(val1, val2)
			witness := SubtractCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

func TestSubtractOverflow(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SubtractCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, new(big.Int).Sub(params.r, val1))
			val2.Add(val2, val1)
			res := new(big.Int).Sub(val1, val2)
			res.Mod(res, params.r)
			witness := SubtractCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type NegationCircuit struct {
	params *Params

	A Element
	B Element
}

func (c *NegationCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Negate(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestNegation(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := NegationCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			res := new(big.Int).Sub(params.r, val1)
			witness := NegationCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type InverseCircuit struct {
	params *Params

	A Element
	B Element
}

func (c *InverseCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Inverse(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestInverse(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.params.hasInverses {
			continue
		}
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := InverseCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			res := new(big.Int).ModInverse(val1, params.r)
			witness := InverseCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type DivisionCircuit struct {
	params *Params
	A      Element
	B      Element
	C      Element
}

func (c *DivisionCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Div(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestDivision(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.params.hasInverses {
			continue
		}
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := DivisionCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, params.r)
			res := new(big.Int)
			res.ModInverse(val2, params.r)
			res.Mul(val1, res)
			res.Mod(res, params.r)
			witness := DivisionCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(res),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type ToBitsCircuit struct {
	params *Params

	Value Element
	Bits  []frontend.Variable
}

func (c *ToBitsCircuit) Define(api frontend.API) error {
	el := c.params.Element(api)
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
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ToBitsCircuit{
				params: params,
				Value:  params.Placeholder(),
				Bits:   make([]frontend.Variable, params.r.BitLen()),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			bits := make([]frontend.Variable, params.r.BitLen())
			for i := 0; i < len(bits); i++ {
				bits[i] = val1.Bit(i)
			}
			witness := ToBitsCircuit{
				params: params,
				Value:  params.ConstantFromBigOrPanic(val1),
				Bits:   bits,
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type ConstantCircuit struct {
	params *Params

	A Element
	B Element
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Set(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestConstant(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ConstantCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
			}
			val, _ := rand.Int(rand.Reader, params.r)
			witness := ConstantCircuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val),
				B:      params.ConstantFromBigOrPanic(val),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.WithProverOpts(backend.WithHints(GetHints()...)))
		}, testName(fp))
	}
}

type SelectCircuit struct {
	params *Params

	Selector frontend.Variable
	A        Element
	B        Element
	C        Element
}

func (c *SelectCircuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Select(c.Selector, c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestSelect(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := SelectCircuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, params.r)
			randbit, _ := rand.Int(rand.Reader, big.NewInt(2))
			b := randbit.Uint64()
			witness := SelectCircuit{
				params:   params,
				A:        params.ConstantFromBigOrPanic(val1),
				B:        params.ConstantFromBigOrPanic(val2),
				C:        params.ConstantFromBigOrPanic([]*big.Int{val1, val2}[1-b]),
				Selector: b,
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type Lookup2Circuit struct {
	params *Params

	Bit0 frontend.Variable
	Bit1 frontend.Variable
	A    Element
	B    Element
	C    Element
	D    Element
	E    Element
}

func (c *Lookup2Circuit) Define(api frontend.API) error {
	res := c.params.Element(api)
	res.Lookup2(c.Bit0, c.Bit1, c.A, c.B, c.C, c.D)
	res.AssertIsEqual(c.E)
	return nil
}

func TestLookup2(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := Lookup2Circuit{
				params: params,
				A:      params.Placeholder(),
				B:      params.Placeholder(),
				C:      params.Placeholder(),
				D:      params.Placeholder(),
				E:      params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, params.r)
			val3, _ := rand.Int(rand.Reader, params.r)
			val4, _ := rand.Int(rand.Reader, params.r)
			randbit, _ := rand.Int(rand.Reader, big.NewInt(4))
			witness := Lookup2Circuit{
				params: params,
				A:      params.ConstantFromBigOrPanic(val1),
				B:      params.ConstantFromBigOrPanic(val2),
				C:      params.ConstantFromBigOrPanic(val3),
				D:      params.ConstantFromBigOrPanic(val4),
				E:      params.ConstantFromBigOrPanic([]*big.Int{val1, val2, val3, val4}[randbit.Uint64()]),
				Bit0:   randbit.Bit(0),
				Bit1:   randbit.Bit(1),
			}

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}

type ComputationCircuit struct {
	params *Params

	X1, X2, X3, X4, X5, X6 Element
	Res                    Element
}

func (c *ComputationCircuit) Define(api frontend.API) error {
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := c.params.Element(api)
	x13.Mul(c.X1, c.X1)
	x13.Reduce(x13)
	x13.Mul(x13, c.X1)
	x13.Reduce(x13)

	fx2 := c.params.Element(api)
	five, err := c.params.ConstantFromBig(big.NewInt(5))
	if err != nil {
		return fmt.Errorf("five: %w", err)
	}
	fx2.Mul(five, c.X2)
	fx2.Reduce(fx2)

	nom := c.params.Element(api)
	nom.Sub(c.X3, c.X4)

	denom := c.params.Element(api)
	denom.Add(c.X5, c.X6)

	free := c.params.Element(api)
	free.Div(nom, denom)

	res := c.params.Element(api)
	res.Add(x13, fx2)
	res.Add(res, free)

	res.AssertIsEqual(c.Res)
	return nil
}

func TestComputation(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		if !fp.params.hasInverses {
			continue
		}
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			circuit := ComputationCircuit{
				params: params,
				X1:     params.Placeholder(),
				X2:     params.Placeholder(),
				X3:     params.Placeholder(),
				X4:     params.Placeholder(),
				X5:     params.Placeholder(),
				X6:     params.Placeholder(),
				Res:    params.Placeholder(),
			}

			val1, _ := rand.Int(rand.Reader, params.r)
			val2, _ := rand.Int(rand.Reader, params.r)
			val3, _ := rand.Int(rand.Reader, params.r)
			val4, _ := rand.Int(rand.Reader, params.r)
			val5, _ := rand.Int(rand.Reader, params.r)
			val6, _ := rand.Int(rand.Reader, params.r)

			tmp := new(big.Int)
			res := new(big.Int)
			// res = x1^3
			tmp.Exp(val1, big.NewInt(3), params.r)
			res.Set(tmp)
			// res = x1^3 + 5*x2
			tmp.Mul(val2, big.NewInt(5))
			res.Add(res, tmp)
			// tmp = (x3-x4)
			tmp.Sub(val3, val4)
			tmp.Mod(tmp, params.r)
			// tmp2 = (x5+x6)
			tmp2 := new(big.Int)
			tmp2.Add(val5, val6)
			// tmp = (x3-x4)/(x5+x6)
			tmp2.ModInverse(tmp2, params.r)
			tmp.Mul(tmp, tmp2)
			tmp.Mod(tmp, params.r)
			// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
			res.Add(res, tmp)
			res.Mod(res, params.r)

			witness := ComputationCircuit{
				params: params,
				X1:     params.ConstantFromBigOrPanic(val1),
				X2:     params.ConstantFromBigOrPanic(val2),
				X3:     params.ConstantFromBigOrPanic(val3),
				X4:     params.ConstantFromBigOrPanic(val4),
				X5:     params.ConstantFromBigOrPanic(val5),
				X6:     params.ConstantFromBigOrPanic(val6),
				Res:    params.ConstantFromBigOrPanic(res),
			}
			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve))
		}, testName(fp))
	}
}
