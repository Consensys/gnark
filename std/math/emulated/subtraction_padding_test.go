package emulated

import (
	"fmt"
	"math/big"
	"testing"

	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/test"
)

func TestSubPadding(t *testing.T) {
	testSubPadding[BN254Fp](t)
	testSubPadding[Secp256k1Fp](t)
	testSubPadding[BLS12377Fp](t)
	testSubPadding[Goldilocks](t)
}

func testSubPadding[T FieldParams](t *testing.T) {
	var fp T
	assert := test.NewAssert(t)
	for i := fp.NbLimbs(); i < 2*fp.NbLimbs(); i++ {
		assert.Run(func(assert *test.Assert) {
			ls := subPadding(fp.Modulus(), fp.BitsPerLimb(), 0, i)
			padValue := new(big.Int)
			if err := limbs.Recompose(ls, fp.BitsPerLimb(), padValue); err != nil {
				assert.FailNow("recompose", err)
			}
			padValue.Mod(padValue, fp.Modulus())
			assert.Zero(padValue.Cmp(big.NewInt(0)), "padding not multiple of order")
		}, fmt.Sprintf("%s/nbLimbs=%d", testName[T](), i))
	}
}
