package emulated

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/fields_bls12377"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/test"
)

type mlBLS377 struct {
	R sw_bls12377.GT
}

func (circuit *mlBLS377) Define(api frontend.API) error {
	circuit.R, _ = e12Squares(api, circuit.R)
	return nil
}

func TestE12SquareBLS377(t *testing.T) {
	if testing.Short() {
		t.Skip()
	}
	assert := test.NewAssert(t)

	circuit := mlBLS377{
		R: sw_bls12377.GT{
			C0: fields_bls12377.E6{
				B0: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B1: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B2: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
			},
			C1: fields_bls12377.E6{
				B0: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B1: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B2: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
			},
		},
	}

	witness := mlBLS377{
		R: sw_bls12377.GT{
			C0: fields_bls12377.E6{
				B0: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B1: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B2: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
			},
			C1: fields_bls12377.E6{
				B0: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B1: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
				B2: fields_bls12377.E2{
					A0: NewElement[BLS12377Fp](nil),
					A1: NewElement[BLS12377Fp](nil),
				},
			},
		},
	}

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[BLS12377Fp](api)
		assert.NoError(err)
		return napi
	})

	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt) //, test.SetAllVariablesAsConstants())
	assert.NoError(err)

	_, err = frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()), frontend.IgnoreUnconstrainedInputs())
	assert.NoError(err)

}

// e12Squares
func e12Squares(api frontend.API, R sw_bls12377.GT) (sw_bls12377.GT, error) {
	const N = 4
	for i := 0; i < N; i++ {
		R.Square(api, R)
	}

	return R, nil
}
