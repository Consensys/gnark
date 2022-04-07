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

type emulatedField struct {
	params *Params
	name   string
}

func emulatedFields(t *testing.T) []emulatedField {
	t.Helper()
	var ret []emulatedField
	for _, limbLength := range []int{20, 25, 28, 30, 32, 48, 64} {
		f21025, err := NewParams(limbLength, new(big.Int).Lsh(big.NewInt(1), 1024))
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, emulatedField{f21025, "f_2^1025"})
		f21024, err := NewParams(limbLength, new(big.Int).Lsh(big.NewInt(1), 1023))
		if err != nil {
			t.Fatal(err)
		}
		ret = append(ret, emulatedField{f21024, "f_2^1024"})
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
	return fmt.Sprintf("p=%s.../limb=%d", ef.name, ef.params.nbBits)
}

type AssertLimbEqualityCircuit struct {
	field *Params

	A Element
	B Element
}

func (c *AssertLimbEqualityCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Set(c.A)
	res.AssertLimbsEquality(c.B)
	return nil
}

func TestAssertLimbEqualityNoOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness AssertLimbEqualityCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()

			val, _ := rand.Int(rand.Reader, params.n)
			witness.A, err = params.ConstantFromBig(val)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

// TODO: add case where the limbs have different overflows.

type AddCircuit struct {
	field *Params

	A Element
	B Element
	C Element
}

func (c *AddCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Add(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestAddCircuitNoOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness AddCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, new(big.Int).Div(params.n, big.NewInt(2)))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(params.n, big.NewInt(2)))
			res := new(big.Int).Add(val1, val2)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(res)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type MulNoOverflowCircuit struct {
	field *Params

	A Element
	B Element
	C Element
}

func (c *MulNoOverflowCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Mul(c.A, c.B)
	res.AssertLimbsEquality(c.C)
	return nil
}

func TestMulCircuitNoOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness MulNoOverflowCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(params.n.BitLen())/2))
			val2, _ := rand.Int(rand.Reader, new(big.Int).Div(params.n, val1))
			res := new(big.Int).Mul(val1, val2)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(res)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type MulCircuitOverflow struct {
	field *Params

	A Element
	B Element
	C Element
}

func (c *MulCircuitOverflow) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Mul(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestMulCircuitOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness MulCircuitOverflow
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			val2, _ := rand.Int(rand.Reader, params.n)
			res := new(big.Int).Mul(val1, val2)
			res.Mod(res, params.n)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(res)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type ReduceAfterAddCircuit struct {
	field *Params

	A Element
	B Element
	C Element
}

func (c *ReduceAfterAddCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Add(c.A, c.B)
	res.Reduce(res)
	res.AssertIsEqual(c.C)
	return nil
}

func TestReduceAfterAdd(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness ReduceAfterAddCircuit
			circuit.field = params
			witness.field = params

			val2, _ := rand.Int(rand.Reader, params.n)
			val1, _ := rand.Int(rand.Reader, val2)
			val3 := new(big.Int).Add(val1, params.n)
			val3.Sub(val3, val2)

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			witness.A, err = params.ConstantFromBig(val3)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(val1)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type SubtractCircuit struct {
	field *Params

	A Element
	B Element
	C Element
}

func (c *SubtractCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Sub(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestSubtractNoOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness SubtractCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			val2, _ := rand.Int(rand.Reader, val1)
			res := new(big.Int).Sub(val1, val2)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(res)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

func TestSubtractOverflow(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness SubtractCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			val2, _ := rand.Int(rand.Reader, new(big.Int).Sub(params.n, val1))
			val2.Add(val2, val1)
			res := new(big.Int).Sub(val1, val2)
			res.Mod(res, params.n)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			assert.NoError(err)
			witness.C, err = params.ConstantFromBig(res)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type NegationCircuit struct {
	field *Params

	A Element
	B Element
}

func (c *NegationCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Negate(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestNegation(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness NegationCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			res := new(big.Int).Sub(params.n, val1)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(res)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type InverseCircuit struct {
	field *Params

	A Element
	B Element
}

func (c *InverseCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Inverse(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestInverse(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		if !fp.params.hasInverses {
			continue
		}
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness InverseCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			res := new(big.Int).ModInverse(val1, params.n)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(res)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type DivisionCircuit struct {
	field *Params
	A     Element
	B     Element
	C     Element
}

func (c *DivisionCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Div(c.A, c.B)
	res.AssertIsEqual(c.C)
	return nil
}

func TestDivision(t *testing.T) {
	var err error
	for _, fp := range emulatedFields(t) {
		if !fp.params.hasInverses {
			continue
		}
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness DivisionCircuit
			circuit.field = params
			witness.field = params

			circuit.A = params.Placeholder()
			circuit.B = params.Placeholder()
			circuit.C = params.Placeholder()

			val1, _ := rand.Int(rand.Reader, params.n)
			val2, _ := rand.Int(rand.Reader, params.n)
			witness.A, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.B, err = params.ConstantFromBig(val2)
			val2.ModInverse(val2, params.n)
			val2.Mul(val1, val2)
			val2.Mod(val2, params.n)
			witness.C, err = params.ConstantFromBig(val2)
			assert.NoError(err)

			assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type ToBitsCircuit struct {
	field *Params

	Value Element
	Bits  []frontend.Variable
}

func (c *ToBitsCircuit) Define(api frontend.API) error {
	el := c.field.Element(api)
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
	var err error
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		assert.Run(func(assert *test.Assert) {
			var circuit, witness ToBitsCircuit
			circuit.field = params
			witness.field = params

			val1, _ := rand.Int(rand.Reader, params.n)
			bits := make([]frontend.Variable, params.n.BitLen())
			for i := 0; i < len(bits); i++ {
				bits[i] = val1.Bit(i)
			}

			circuit.Value = params.Placeholder()
			circuit.Bits = make([]frontend.Variable, len(bits))

			witness.Value, err = params.ConstantFromBig(val1)
			assert.NoError(err)
			witness.Bits = bits

			assert.ProverSucceeded(&circuit, &witness, test.WithCurves(ecc.BN254))
		}, testName(fp))
	}
}

type ConstantCircuit struct {
	field *Params

	A Element
	B Element
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	res := c.field.Element(api)
	res.Set(c.A)
	res.AssertIsEqual(c.B)
	return nil
}

func TestConstant(t *testing.T) {

}

type ComputationCircuit struct {
	field *Params

	X1, X2, X3, X4, X5 Element
	Res                Element
}

func (c *ComputationCircuit) Define(api frontend.API) error {
	// compute x1 * (x2-x3) / (x4+x5)
	nom := c.field.Element(api)
	nom.Sub(c.X2, c.X3)
	denom := c.field.Element(api)
	denom.Add(c.X4, c.X5)
	div := c.field.Element(api)
	div.Div(nom, denom)
	res := c.field.Element(api)
	res.Mul(c.X1, div)
	res.AssertIsEqual(c.Res)
	return nil
}
