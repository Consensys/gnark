package emulated

import (
	"errors"
	"math/big"
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
	_, _ = fakeMillerLoop(api, []sw_bls12377.G1Affine{circuit.P}, []sw_bls12377.G2Affine{circuit.Q})
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
	// reference: 12:17:33 DBG counters add=1271017 equals=206709 fromBinary=0 mul=1274544 sub=9165 toBinary=0
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)
}

// fakeMillerLoop matches pairing.MillerLoop, except we only run 1 iteration, for benchmarking / troubleshooting purposes
func fakeMillerLoop(api frontend.API, P []sw_bls12377.G1Affine, Q []sw_bls12377.G2Affine) (sw_bls12377.GT, error) {
	// check input size match
	n := len(P)
	if n == 0 || n != len(Q) {
		return sw_bls12377.GT{}, errors.New("invalid inputs sizes")
	}

	const nbIterations = 3
	var ateLoopBin [nbIterations]uint
	var ateLoopBigInt big.Int
	const ateLoop = 9586122913090633729
	ateLoopBigInt.SetUint64(ateLoop)
	for i := 0; i < nbIterations; i++ {
		ateLoopBin[i] = ateLoopBigInt.Bit(i)
	}

	var res sw_bls12377.GT
	res.SetOne()

	var l1, l2 sw_bls12377.LineEvaluation
	Qacc := make([]sw_bls12377.G2Affine, n)
	yInv := make([]frontend.Variable, n)
	xOverY := make([]frontend.Variable, n)
	for k := 0; k < n; k++ {
		Qacc[k] = Q[k]
		yInv[k] = api.DivUnchecked(1, P[k].Y)
		xOverY[k] = api.DivUnchecked(P[k].X, P[k].Y)
	}

	// k = 0
	Qacc[0], l1 = sw_bls12377.DoubleStep(api, &Qacc[0])
	res.C1.B0.MulByFp(api, l1.R0, xOverY[0])
	res.C1.B1.MulByFp(api, l1.R1, yInv[0])

	if n >= 2 {
		// k = 1
		Qacc[1], l1 = sw_bls12377.DoubleStep(api, &Qacc[1])
		l1.R0.MulByFp(api, l1.R0, xOverY[1])
		l1.R1.MulByFp(api, l1.R1, yInv[1])
		res.Mul034By034(api, l1.R0, l1.R1, res.C1.B0, res.C1.B1)
	}

	if n >= 3 {
		// k >= 2
		for k := 2; k < n; k++ {
			Qacc[k], l1 = sw_bls12377.DoubleStep(api, &Qacc[k])
			l1.R0.MulByFp(api, l1.R0, xOverY[k])
			l1.R1.MulByFp(api, l1.R1, yInv[k])
			res.MulBy034(api, l1.R0, l1.R1)
		}
	}

	for i := len(ateLoopBin) - 3; i >= 0; i-- {
		res.Square(api, res)

		if ateLoopBin[i] == 0 {
			for k := 0; k < n; k++ {
				Qacc[k], l1 = sw_bls12377.DoubleStep(api, &Qacc[k])
				l1.R0.MulByFp(api, l1.R0, xOverY[k])
				l1.R1.MulByFp(api, l1.R1, yInv[k])
				res.MulBy034(api, l1.R0, l1.R1)
			}
			continue
		}

		for k := 0; k < n; k++ {
			Qacc[k], l1, l2 = sw_bls12377.DoubleAndAddStep(api, &Qacc[k], &Q[k])
			l1.R0.MulByFp(api, l1.R0, xOverY[k])
			l1.R1.MulByFp(api, l1.R1, yInv[k])
			res.MulBy034(api, l1.R0, l1.R1)
			l2.R0.MulByFp(api, l2.R0, xOverY[k])
			l2.R1.MulByFp(api, l2.R1, yInv[k])
			res.MulBy034(api, l2.R0, l2.R1)
		}
	}

	return res, nil
}
