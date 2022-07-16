package emulated

import (
	"crypto/rand"
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
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
	// _, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()))
	// assert.NoError(err)
	// TODO: create proof
}
