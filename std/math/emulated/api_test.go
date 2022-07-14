package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"sort"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/internal/backend/circuits"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/test"
)

func newAPI(native frontend.API, params *Params) API {
	return &fakeAPI{
		api:    native,
		params: params,
	}
}

func witnessData(mod *big.Int) (X1, X2, X3, X4, X5, X6, Res *big.Int) {
	val1, _ := rand.Int(rand.Reader, mod)
	val2, _ := rand.Int(rand.Reader, mod)
	val3, _ := rand.Int(rand.Reader, mod)
	val4, _ := rand.Int(rand.Reader, mod)
	val5, _ := rand.Int(rand.Reader, mod)
	val6, _ := rand.Int(rand.Reader, mod)

	tmp := new(big.Int)
	res := new(big.Int)
	// res = x1^3
	tmp.Exp(val1, big.NewInt(3), mod)
	res.Set(tmp)
	// res = x1^3 + 5*x2
	tmp.Mul(val2, big.NewInt(5))
	res.Add(res, tmp)
	// tmp = (x3-x4)
	tmp.Sub(val3, val4)
	tmp.Mod(tmp, mod)
	// tmp2 = (x5+x6)
	tmp2 := new(big.Int)
	tmp2.Add(val5, val6)
	// tmp = (x3-x4)/(x5+x6)
	tmp2.ModInverse(tmp2, mod)
	tmp.Mul(tmp, tmp2)
	tmp.Mod(tmp, mod)
	// res = x1^3 + 5*x2 + (x3-x4)/(x5+x6)
	res.Add(res, tmp)
	res.Mod(res, mod)
	return val1, val2, val3, val4, val5, val6, res
}

type EmulatedApiCircuit struct {
	Params *Params

	X1, X2, X3, X4, X5, X6 Element
	Res                    Element
}

func (c *EmulatedApiCircuit) Define(api frontend.API) error {
	if c.Params != nil {
		api = newAPI(api, c.Params)
	}
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

func TestEmulatedApi(t *testing.T) {
	assert := test.NewAssert(t)

	r := ecc.BN254.ScalarField()
	params, err := NewParams(32, r)
	assert.NoError(err)

	circuit := EmulatedApiCircuit{
		Params: params,
		X1:     params.Placeholder(),
		X2:     params.Placeholder(),
		X3:     params.Placeholder(),
		X4:     params.Placeholder(),
		X5:     params.Placeholder(),
		X6:     params.Placeholder(),
		Res:    params.Placeholder(),
	}

	x1, x2, x3, x4, x5, x6, res := witnessData(params.r)
	witness := EmulatedApiCircuit{
		Params: params,
		X1:     params.ConstantFromBigOrPanic(x1),
		X2:     params.ConstantFromBigOrPanic(x2),
		X3:     params.ConstantFromBigOrPanic(x3),
		X4:     params.ConstantFromBigOrPanic(x4),
		X5:     params.ConstantFromBigOrPanic(x5),
		X6:     params.ConstantFromBigOrPanic(x6),
		Res:    params.ConstantFromBigOrPanic(res),
	}

	assert.ProverSucceeded(&circuit, &witness, test.WithProverOpts(backend.WithHints(GetHints()...)), test.WithCurves(testCurve), test.NoSerialization())
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
	r := ecc.BN254.ScalarField()
	params, err := NewParams(32, r)
	assert.NoError(err)

	circuit := WrapperCircuit{
		X1:  params.Placeholder(),
		X2:  params.Placeholder(),
		X3:  params.Placeholder(),
		X4:  params.Placeholder(),
		X5:  params.Placeholder(),
		X6:  params.Placeholder(),
		Res: params.Placeholder(),
	}
	x1, x2, x3, x4, x5, x6, res := witnessData(params.r)
	witness := WrapperCircuit{
		X1:  params.ConstantFromBigOrPanic(x1),
		X2:  params.ConstantFromBigOrPanic(x2),
		X3:  params.ConstantFromBigOrPanic(x3),
		X4:  params.ConstantFromBigOrPanic(x4),
		X5:  params.ConstantFromBigOrPanic(x5),
		X6:  params.ConstantFromBigOrPanic(x6),
		Res: params.ConstantFromBigOrPanic(res),
	}
	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		return newAPI(api, params)
	})
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

func TestCompilerWrapper(t *testing.T) {
	assert := test.NewAssert(t)
	r := ecc.BN254.ScalarField()
	params, err := NewParams(32, r)
	assert.NoError(err)

	circuit := WrapperCircuit{}
	x1, x2, x3, x4, x5, x6, res := witnessData(params.r)
	witness := WrapperCircuit{
		X1:  params.ConstantFromBigOrPanic(x1),
		X2:  params.ConstantFromBigOrPanic(x2),
		X3:  params.ConstantFromBigOrPanic(x3),
		X4:  params.ConstantFromBigOrPanic(x4),
		X5:  params.ConstantFromBigOrPanic(x5),
		X6:  params.ConstantFromBigOrPanic(x6),
		Res: params.ConstantFromBigOrPanic(res),
	}
	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(BuilderWrapper(params)))
	assert.NoError(err)
	t.Log(ccs.GetNbConstraints())
	// TODO: create proof
	_ = witness
}

func TestIntegrationApi(t *testing.T) {
	assert := test.NewAssert(t)
	r := ecc.BN254.ScalarField()
	params, err := NewParams(32, r)
	assert.NoError(err)
	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		return newAPI(api, params)
	})
	keys := make([]string, 0, len(circuits.Circuits))
	for k := range circuits.Circuits {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	for i := range keys {
		name := keys[i]
		tData := circuits.Circuits[name]
		assert.Run(func(assert *test.Assert) {
			_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, tData.Circuit, frontend.WithBuilderWrapper(BuilderWrapper(params)))
			assert.NoError(err)
		}, name, "compile")
		for i := range tData.ValidAssignments {
			assignment := tData.ValidAssignments[i]
			assert.Run(func(assert *test.Assert) {
				err = test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
				assert.NoError(err)
			}, name, fmt.Sprintf("valid=%d", i))
		}
		for i := range tData.InvalidAssignments {
			assignment := tData.InvalidAssignments[i]
			assert.Run(func(assert *test.Assert) {
				err = test.IsSolved(tData.Circuit, assignment, testCurve.ScalarField(), wrapperOpt)
				assert.Error(err)
			}, name, fmt.Sprintf("invalid=%d", i))
		}
	}
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
	t.Skip()
	assert := test.NewAssert(t)
	params, err := NewParams(32, ecc.BW6_761.ScalarField())
	assert.NoError(err)

	_, _, P, Q := bls12377.Generators()
	milRes, _ := bls12377.MillerLoop([]bls12377.G1Affine{P}, []bls12377.G2Affine{Q})
	pairingRes := bls12377.FinalExponentiation(&milRes)

	circuit := pairingBLS377{}

	pxb := new(big.Int)
	pyb := new(big.Int)
	qxab := new(big.Int)
	qxbb := new(big.Int)
	qyab := new(big.Int)
	qybb := new(big.Int)
	witness := pairingBLS377{
		pairingRes: pairingRes,
		P: sw_bls12377.G1Affine{
			X: params.ConstantFromBigOrPanic(P.X.ToBigIntRegular(pxb)),
			Y: params.ConstantFromBigOrPanic(P.Y.ToBigIntRegular(pyb)),
		},
		Q: sw_bls12377.G2Affine{
			X: fields_bls12377.E2{
				A0: params.ConstantFromBigOrPanic(Q.X.A0.ToBigIntRegular(qxab)),
				A1: params.ConstantFromBigOrPanic(Q.X.A1.ToBigIntRegular(qxbb)),
			},
			Y: fields_bls12377.E2{
				A0: params.ConstantFromBigOrPanic(Q.Y.A0.ToBigIntRegular(qyab)),
				A1: params.ConstantFromBigOrPanic(Q.Y.A1.ToBigIntRegular(qybb)),
			},
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		return newAPI(api, params)
	})
	err = test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(BuilderWrapper(params)))
	assert.NoError(err)
	// TODO: create proof
}
