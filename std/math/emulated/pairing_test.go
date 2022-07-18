package emulated

import (
	"testing"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/test"
)

type mlBLS377 struct {
	P sw_bls12377.G1Affine `gnark:",public"`
	Q sw_bls12377.G2Affine
}

func (circuit *mlBLS377) Define(api frontend.API) error {
	_, _ = fakeMillerLoop(api, circuit.P, circuit.Q)
	return nil
}

func TestMillerLoopBLS377(t *testing.T) {
	assert := test.NewAssert(t)

	_, _, P, Q := bls12377.Generators()

	circuit := mlBLS377{
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
	witness := mlBLS377{
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
	// reference for N = 2:
	// 12:53:18 DBG counters add=2803841 equals=450685 fromBinary=0 mul=2809986 sub=19506 toBinary=0
	// for 32 squares:
	// 13:37:56 DBG counters add=17445340 equals=2809325 fromBinary=0 mul=17467554 sub=116816 toBinary=0
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

// fakeMillerLoop matches pairing.MillerLoop, except we only run 2 iterations, for benchmarking / troubleshooting purposes
func fakeMillerLoop(api frontend.API, P sw_bls12377.G1Affine, Q sw_bls12377.G2Affine) (sw_bls12377.GT, error) {
	// check input size match
	var res sw_bls12377.GT
	res.SetOne()

	var l1, _ sw_bls12377.LineEvaluation

	Qacc := Q
	yInv := api.DivUnchecked(1, P.Y)
	xOverY := api.DivUnchecked(P.X, P.Y)

	// k = 0
	Qacc, l1 = sw_bls12377.DoubleStep(api, &Qacc)
	res.C1.B0.MulByFp(api, l1.R0, xOverY)
	res.C1.B1.MulByFp(api, l1.R1, yInv)

	const N = 32
	for i := 0; i < N; i++ {
		res.Square(api, res)
		// Qacc, l1, l2 = sw_bls12377.DoubleAndAddStep(api, &Qacc, &Q)
		// l1.R0.MulByFp(api, l1.R0, xOverY)
		// l1.R1.MulByFp(api, l1.R1, yInv)
		// res.MulBy034(api, l1.R0, l1.R1)
		// l2.R0.MulByFp(api, l2.R0, xOverY)
		// l2.R1.MulByFp(api, l2.R1, yInv)
		// res.MulBy034(api, l2.R0, l2.R1)
	}

	return res, nil
}
