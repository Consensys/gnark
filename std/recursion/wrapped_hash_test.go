package recursion_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr_bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315"
	fr_bls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/algebra/emulated/sw_bn254"
	"github.com/consensys/gnark/std/algebra/native/sw_bls12377"
	"github.com/consensys/gnark/std/algebra/native/sw_bls24315"
	"github.com/consensys/gnark/std/recursion"
	"github.com/consensys/gnark/test"
)

type shortHashCircuit struct {
	Input  []frontend.Variable
	Output frontend.Variable
	inner  ecc.ID
}

func (c *shortHashCircuit) Define(api frontend.API) error {
	hasher, err := recursion.NewHash(api, c.inner.ScalarField(), false)
	if err != nil {
		return err
	}
	for i := range c.Input {
		hasher.Write(c.Input[i])
	}
	res := hasher.Sum()
	api.AssertIsEqual(c.Output, res)
	return nil
}

func TestShortHash(t *testing.T) {
	outerCurves := []ecc.ID{
		ecc.BN254,
		ecc.BLS12_381,
		ecc.BLS12_377,
		ecc.BW6_761,
		ecc.BW6_633,
		ecc.BLS24_315,
		ecc.BLS24_317,
	}
	innerCurves := []ecc.ID{
		ecc.BN254,
		ecc.BLS12_381,
		ecc.BLS12_377,
		ecc.BW6_761,
		ecc.BW6_633,
		ecc.BLS24_315,
		ecc.BLS24_317,
	}

	assert := test.NewAssert(t)
	nbInputs := 19
	for _, outer := range outerCurves {
		outer := outer
		for _, inner := range innerCurves {
			inner := inner
			assert.Run(func(assert *test.Assert) {
				circuit := &shortHashCircuit{Input: make([]frontend.Variable, nbInputs), inner: inner}
				h, err := recursion.NewShort(outer.ScalarField(), inner.ScalarField())
				assert.NoError(err)
				witness := &shortHashCircuit{Input: make([]frontend.Variable, nbInputs), inner: inner}
				buf := make([]byte, (outer.ScalarField().BitLen()+7)/8)
				for i := range witness.Input {
					el, err := rand.Int(rand.Reader, outer.ScalarField())
					assert.NoError(err)
					el.FillBytes(buf)
					h.Write(buf)
					witness.Input[i] = el
				}
				res := h.Sum(nil)
				witness.Output = res
				assert.CheckCircuit(circuit, test.WithCurves(outer), test.WithValidAssignment(witness), test.NoFuzzing(), test.NoSerializationChecks(), test.NoSolidityChecks())
			}, outer.String(), inner.String())
		}
	}
}
