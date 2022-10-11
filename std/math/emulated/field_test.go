package emulated

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"testing"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
)

func witnessData(q *big.Int) (X1, X2, X3, X4, X5, X6, Res *big.Int) {
	x1, _ := rand.Int(rand.Reader, q)
	x2, _ := rand.Int(rand.Reader, q)
	x3, _ := rand.Int(rand.Reader, q)
	x4, _ := rand.Int(rand.Reader, q)
	x5, _ := rand.Int(rand.Reader, q)
	x6, _ := rand.Int(rand.Reader, q)

	tmp := new(big.Int)
	res := new(big.Int)
	// res = x1^3
	tmp.Exp(x1, big.NewInt(3), q)
	res.Set(tmp)
	// res = x1^3 + 5*x2
	tmp.Mul(x2, big.NewInt(5))
	res.Add(res, tmp)
	// tmp = (x3-x4)
	tmp.Sub(x3, x4)
	tmp.Mod(tmp, q)
	// tmp2 = (x5+x6)
	tmp2 := new(big.Int)
	tmp2.Add(x5, x6)
	// tmp = (x3-x4)/(x5+x6)
	tmp2.ModInverse(tmp2, q)
	tmp.Mul(tmp, tmp2)
	tmp.Mod(tmp, q)
	// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
	res.Add(res, tmp)
	res.Mod(res, q)
	return x1, x2, x3, x4, x5, x6, res
}

type WrapperCircuit struct {
	X1, X2, X3, X4, X5, X6 frontend.Variable
	Res                    frontend.Variable
}

func (c *WrapperCircuit) Define(api frontend.API) error {
	// compute x1^3 + 5*x2 + (x3-x4) / (x5+x6)
	x13 := api.Mul(c.X1, c.X1, c.X1)
	fx2 := api.Mul(5, c.X2)
	nom := api.Sub(c.X3, c.X4)
	denom := api.Add(c.X5, c.X6)
	free := api.Div(nom, denom)
	res := api.Add(x13, fx2, free)
	api.AssertIsEqual(res, c.Res)
	return nil
}

func TestTestEngineWrapper(t *testing.T) {
	assert := test.NewAssert(t)

	circuit := WrapperCircuit{
		X1:  NewElement[Secp256k1](nil),
		X2:  NewElement[Secp256k1](nil),
		X3:  NewElement[Secp256k1](nil),
		X4:  NewElement[Secp256k1](nil),
		X5:  NewElement[Secp256k1](nil),
		X6:  NewElement[Secp256k1](nil),
		Res: NewElement[Secp256k1](nil),
	}

	x1, x2, x3, x4, x5, x6, res := witnessData(Secp256k1{}.Modulus())
	witness := WrapperCircuit{
		X1:  NewElement[Secp256k1](x1),
		X2:  NewElement[Secp256k1](x2),
		X3:  NewElement[Secp256k1](x3),
		X4:  NewElement[Secp256k1](x4),
		X5:  NewElement[Secp256k1](x5),
		X6:  NewElement[Secp256k1](x6),
		Res: NewElement[Secp256k1](res),
	}
	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[Secp256k1](api)
		assert.NoError(err)
		return napi
	})
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

func TestCompilerWrapper(t *testing.T) {
	assert := test.NewAssert(t)
	circuit := WrapperCircuit{
		X1:  NewElement[Secp256k1](nil),
		X2:  NewElement[Secp256k1](nil),
		X3:  NewElement[Secp256k1](nil),
		X4:  NewElement[Secp256k1](nil),
		X5:  NewElement[Secp256k1](nil),
		X6:  NewElement[Secp256k1](nil),
		Res: NewElement[Secp256k1](nil),
	}

	x1, x2, x3, x4, x5, x6, res := witnessData(Secp256k1{}.Modulus())
	witness := WrapperCircuit{
		X1:  NewElement[Secp256k1](x1),
		X2:  NewElement[Secp256k1](x2),
		X3:  NewElement[Secp256k1](x3),
		X4:  NewElement[Secp256k1](x4),
		X5:  NewElement[Secp256k1](x5),
		X6:  NewElement[Secp256k1](x6),
		Res: NewElement[Secp256k1](res),
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[Secp256k1]()))
	assert.NoError(err)
	t.Log(ccs.GetNbConstraints())
	// TODO: create proof
	_ = witness
}

func TestIntegrationApi(t *testing.T) {
	assert := test.NewAssert(t)
	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[Secp256k1](api)
		assert.NoError(err)
		return napi
	})
	keys := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i := range keys {
		name := keys[i]
		if name == "inv" || name == "div" || name == "cmp" {
			// TODO @gbotrel thes don't pass when we use emulated field modulus != snark field
			continue
		}
		tData := circuits.Circuits[name]
		assert.Run(func(assert *test.Assert) {
			_, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, tData.Circuit, frontend.WithBuilderWrapper(builderWrapper[Secp256k1]()))
			assert.NoError(err)
		}, name, "compile")
		for i := range tData.ValidAssignments {
			assignment := tData.ValidAssignments[i]
			assert.Run(func(assert *test.Assert) {
				err := test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
				assert.NoError(err)
			}, name, fmt.Sprintf("valid=%d", i))
		}
		for i := range tData.InvalidAssignments {
			assignment := tData.InvalidAssignments[i]
			assert.Run(func(assert *test.Assert) {
				err := test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
				assert.Error(err)
			}, name, fmt.Sprintf("invalid=%d", i))
		}
	}
}

func TestVarToElements(t *testing.T) {
	assert := require.New(t)
	_f, _ := NewField[BN254Fp](nil)

	f := _f.(*field[BN254Fp])

	{
		in := []frontend.Variable{8000, 42}
		out1 := f.varsToElements(in...)
		out2 := f.varsToElements(in)

		assert.Equal(len(out1), len(out2))
		assert.Equal(len(out1), 2)
	}

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("nil input should panic")
		}
	}()
	in := []frontend.Variable{8000, nil, 3000}
	_ = f.varsToElements(in)
}

type addingG1BLS377 struct {
	P           sw_bls12377.G1Affine `gnark:",public"`
	Q           sw_bls12377.G1Affine
	additionRes bls12377.G1Affine
}

//lint:ignore U1000 skipped test
func (circuit *addingG1BLS377) Define(api frontend.API) error {
	additionRes := circuit.P.Double(api, circuit.P)
	api.AssertIsEqual(additionRes.X, &circuit.additionRes.X)
	api.AssertIsEqual(additionRes.Y, &circuit.additionRes.Y)
	return nil
}

func TestAddG1BLS377(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, A, _ := bls12377.Generators()
	var additionRes bls12377.G1Affine
	additionRes = *additionRes.Add(&A, &A)

	circuit := addingG1BLS377{
		additionRes: additionRes,
		P:           sw_bls12377.G1Affine{X: NewElement[BLS12377Fp](nil), Y: NewElement[BLS12377Fp](nil)},
		Q:           sw_bls12377.G1Affine{X: NewElement[BLS12377Fp](nil), Y: NewElement[BLS12377Fp](nil)},
	}
	witness := addingG1BLS377{
		additionRes: additionRes,
		P: sw_bls12377.G1Affine{
			X: NewElement[BLS12377Fp](A.X),
			Y: NewElement[BLS12377Fp](A.Y),
		},
		Q: sw_bls12377.G1Affine{
			X: NewElement[BLS12377Fp](A.X),
			Y: NewElement[BLS12377Fp](A.Y),
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[BLS12377Fp](api)
		assert.NoError(err)
		return napi
	})
	// TODO @gbotrel test engine when test.SetAllVariablesAsConstants() also consider witness as
	// constant. It shouldn't.
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt) //, test.SetAllVariablesAsConstants())
	assert.NoError(err)
	// _, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()))
	// assert.NoError(err)
	// TODO: create proof
}

type addingG2BLS377 struct {
	P           sw_bls12377.G2Affine `gnark:",public"`
	Q           sw_bls12377.G2Affine
	additionRes bls12377.G2Affine
}

//lint:ignore U1000 skipped test
func (circuit *addingG2BLS377) Define(api frontend.API) error {
	additionRes := circuit.P.Double(api, circuit.Q)
	api.AssertIsEqual(additionRes.X.A0, &circuit.additionRes.X.A0)
	api.AssertIsEqual(additionRes.X.A1, &circuit.additionRes.X.A1)
	api.AssertIsEqual(additionRes.Y.A0, &circuit.additionRes.Y.A0)
	api.AssertIsEqual(additionRes.Y.A1, &circuit.additionRes.Y.A1)
	return nil
}

func TestAddG2BLS377(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, _, Q := bls12377.Generators()
	var additionRes bls12377.G2Affine
	additionRes = *additionRes.Add(&Q, &Q)

	circuit := addingG2BLS377{
		additionRes: additionRes,
		P: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
		},
		Q: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
		},
	}
	witness := addingG2BLS377{
		additionRes: additionRes,
		P: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.X.A0),
				A1: NewElement[BLS12377Fp](Q.X.A1),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.Y.A0),
				A1: NewElement[BLS12377Fp](Q.Y.A1),
			},
		},
		Q: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.X.A0),
				A1: NewElement[BLS12377Fp](Q.X.A1),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.Y.A0),
				A1: NewElement[BLS12377Fp](Q.Y.A1),
			},
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[BLS12377Fp](api)
		assert.NoError(err)
		return napi
	})
	// TODO @gbotrel test engine when test.SetAllVariablesAsConstants() also consider witness as
	// constant. It shouldn't.
	// assert.ProverSucceeded(&circuit, &witness, test.WithCurves(testCurve), test.NoSerialization(), test.WithBackends(backend.GROTH16))

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt) //, test.SetAllVariablesAsConstants())
	// assert.NoError(err)
	// _, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()))
	assert.NoError(err)
	// TODO: create proof
}

type pairingBLS377 struct {
	P          sw_bls12377.G1Affine `gnark:",public"`
	Q          sw_bls12377.G2Affine
	pairingRes bls12377.GT
}

//lint:ignore U1000 skipped test
func (circuit *pairingBLS377) Define(api frontend.API) error {
	pairingRes, _ := sw_bls12377.Pair(api,
		[]sw_bls12377.G1Affine{circuit.P},
		[]sw_bls12377.G2Affine{circuit.Q})
	api.AssertIsEqual(pairingRes.C0.B0.A0, &circuit.pairingRes.C0.B0.A0)
	api.AssertIsEqual(pairingRes.C0.B0.A1, &circuit.pairingRes.C0.B0.A1)
	api.AssertIsEqual(pairingRes.C0.B1.A0, &circuit.pairingRes.C0.B1.A0)
	api.AssertIsEqual(pairingRes.C0.B1.A1, &circuit.pairingRes.C0.B1.A1)
	api.AssertIsEqual(pairingRes.C0.B2.A0, &circuit.pairingRes.C0.B2.A0)
	api.AssertIsEqual(pairingRes.C0.B2.A1, &circuit.pairingRes.C0.B2.A1)
	api.AssertIsEqual(pairingRes.C1.B0.A0, &circuit.pairingRes.C1.B0.A0)
	api.AssertIsEqual(pairingRes.C1.B0.A1, &circuit.pairingRes.C1.B0.A1)
	api.AssertIsEqual(pairingRes.C1.B1.A0, &circuit.pairingRes.C1.B1.A0)
	api.AssertIsEqual(pairingRes.C1.B1.A1, &circuit.pairingRes.C1.B1.A1)
	api.AssertIsEqual(pairingRes.C1.B2.A0, &circuit.pairingRes.C1.B2.A0)
	api.AssertIsEqual(pairingRes.C1.B2.A1, &circuit.pairingRes.C1.B2.A1)
	return nil
}

func TestPairingBLS377(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, P, Q := bls12377.Generators()
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes := bls12377.FinalExponentiation(&milRes)

	circuit := pairingBLS377{
		pairingRes: pairingRes,
		P: sw_bls12377.G1Affine{
			X: NewElement[BLS12377Fp](nil),
			Y: NewElement[BLS12377Fp](nil),
		},
		Q: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](nil),
				A1: NewElement[BLS12377Fp](nil),
			},
		},
	}
	witness := pairingBLS377{
		pairingRes: pairingRes,
		P: sw_bls12377.G1Affine{
			X: NewElement[BLS12377Fp](P.X),
			Y: NewElement[BLS12377Fp](P.Y),
		},
		Q: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.X.A0),
				A1: NewElement[BLS12377Fp](Q.X.A1),
			},
			Y: fields_bls12377.E2{
				A0: NewElement[BLS12377Fp](Q.Y.A0),
				A1: NewElement[BLS12377Fp](Q.Y.A1),
			},
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[BLS12377Fp](api)
		assert.NoError(err)
		return napi
	})
	// TODO @gbotrel test engine when test.SetAllVariablesAsConstants() also consider witness as
	// constant. It shouldn't.
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt) //, test.SetAllVariablesAsConstants())
	assert.NoError(err)
	// _, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()))
	// assert.NoError(err)
	// TODO: create proof
}

type ConstantCircuit struct {
}

func (c *ConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1](api)
	if err != nil {
		return err
	}
	{
		c1 := NewElement[Secp256k1](42)
		b1, ok := f.ConstantValue(c1)
		if !ok {
			return errors.New("42 should be constant")
		}
		if !(b1.IsUint64() && b1.Uint64() == 42) {
			return errors.New("42 != constant(42)")
		}
	}
	{
		m := f.(*field[Secp256k1]).Modulus()
		b1, ok := f.ConstantValue(m)
		if !ok {
			return errors.New("modulus should be constant")
		}
		if b1.Cmp(Secp256k1{}.Modulus()) != 0 {
			return errors.New("modulus != constant(modulus)")
		}
	}

	return nil
}

func TestConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness ConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type MulConstantCircuit struct {
}

func (c *MulConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1](api)
	if err != nil {
		return err
	}
	c0 := NewElement[Secp256k1](0)
	c1 := NewElement[Secp256k1](0)
	c2 := NewElement[Secp256k1](0)
	r := f.Mul(c0, c1)
	f.AssertIsEqual(r, c2)

	return nil
}

func TestMulConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness MulConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}

type SubConstantCircuit struct {
}

func (c *SubConstantCircuit) Define(api frontend.API) error {
	f, err := NewField[Secp256k1](api)
	if err != nil {
		return err
	}
	c0 := NewElement[Secp256k1](0)
	c1 := NewElement[Secp256k1](0)
	c2 := NewElement[Secp256k1](0)
	r := f.Sub(c0, c1)
	if r.(Element[Secp256k1]).overflow != 0 {
		return fmt.Errorf("overflow %d != 0", r.(Element[Secp256k1]).overflow)
	}
	// rc, ok := f.ConstantValue(r)
	// if !ok {
	// 	return errors.New("0 - 0 is not constant")
	// }
	// if !rc.IsUint64() && rc.Uint64() == 0 {
	// 	return fmt.Errorf("0 - 0 = %s", rc.String())
	// }
	f.AssertIsEqual(r, c2)

	return nil
}

func TestSubConstantCircuit(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness SubConstantCircuit

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)
}
