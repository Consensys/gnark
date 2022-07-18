package emulated

import (
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/sw_bls12377"
	"github.com/consensys/gnark/test"
)

type mlBLS377 struct {
}

func (circuit *mlBLS377) Define(api frontend.API) error {
	_, _ = e12Squares(api)
	return nil
}

func TestE12SquareBLS377(t *testing.T) {
	assert := test.NewAssert(t)

	var circuit, witness mlBLS377

	wrapperOpt := test.WithApiWrapper(func(api frontend.API) frontend.API {
		napi, err := NewField[BLS12377Fp](api)
		assert.NoError(err)
		return napi
	})
	// for 32 squares:
	// 13:44:31 DBG counters add=17176833 equals=2762193 fromBinary=0 mul=17197636 sub=115001 toBinary=0
	err := test.IsSolved(&circuit, &witness, testCurve.ScalarField(), wrapperOpt)
	assert.NoError(err)

	ccs, err := frontend.Compile(testCurve.ScalarField(), r1cs.NewBuilder, &circuit, frontend.WithBuilderWrapper(builderWrapper[BLS12377Fp]()))
	assert.NoError(err)

	t.Log("nbConstraints", ccs.GetNbConstraints())

}

// e12Squares
func e12Squares(api frontend.API) (sw_bls12377.GT, error) {
	// check input size match
	var res sw_bls12377.GT
	res.SetOne()

	const N = 2
	for i := 0; i < N; i++ {
		res.Square(api, res)
	}

	return res, nil
}
