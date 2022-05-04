package nonnative

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/test"
)

func TestComposition(t *testing.T) {
	assert := test.NewAssert(t)
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert.Run(func(assert *test.Assert) {
			n, err := rand.Int(rand.Reader, params.r)
			if err != nil {
				assert.FailNow("rand int", err)
			}
			res := make([]*big.Int, params.nbLimbs)
			for i := range res {
				res[i] = new(big.Int)
			}
			if err = Decompose(n, params.nbBits, res); err != nil {
				assert.FailNow("decompose", err)
			}
			n2 := new(big.Int)
			if err = Recompose(res, params.nbBits, n2); err != nil {
				assert.FailNow("recompose", err)
			}
			if n2.Cmp(n) != 0 {
				assert.FailNow("inequal")
			}
		}, testName(fp))
	}
}

func TestSubPadding(t *testing.T) {
	for _, fp := range emulatedFields(t) {
		params := fp.params
		assert := test.NewAssert(t)
		for i := params.nbLimbs; i < 2*params.nbLimbs; i++ {
			assert.Run(func(assert *test.Assert) {
				limbs := subPadding(params, 0, i)
				padValue := new(big.Int)
				if err := Recompose(limbs, params.nbBits, padValue); err != nil {
					assert.FailNow("recompose", err)
				}
				padValue.Mod(padValue, params.r)
				assert.Zero(padValue.Cmp(big.NewInt(0)), "padding not multiple of order")
			}, fmt.Sprintf("%s/nbLimbs=%d", testName(fp), i))
		}
	}
}
