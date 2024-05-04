package emulated

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark/test"
)

func TestComposition(t *testing.T) {
	testComposition[BN254Fp](t)
	testComposition[Secp256k1Fp](t)
	testComposition[BLS12377Fp](t)
	testComposition[Goldilocks](t)
}

func testComposition[T FieldParams](t *testing.T) {
	t.Helper()
	assert := test.NewAssert(t)
	var fp T
	assert.Run(func(assert *test.Assert) {
		n, err := rand.Int(rand.Reader, fp.Modulus())
		if err != nil {
			assert.FailNow("rand int", err)
		}
		res := make([]*big.Int, fp.NbLimbs())
		for i := range res {
			res[i] = new(big.Int)
		}
		if err = decompose(n, fp.BitsPerLimb(), res); err != nil {
			assert.FailNow("decompose", err)
		}
		n2 := new(big.Int)
		if err = recompose(res, fp.BitsPerLimb(), n2); err != nil {
			assert.FailNow("recompose", err)
		}
		if n2.Cmp(n) != 0 {
			assert.FailNow("unequal")
		}
	}, testName[T]())
}

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
			limbs := subPadding(fp.Modulus(), fp.BitsPerLimb(), 0, i)
			padValue := new(big.Int)
			if err := recompose(limbs, fp.BitsPerLimb(), padValue); err != nil {
				assert.FailNow("recompose", err)
			}
			padValue.Mod(padValue, fp.Modulus())
			assert.Zero(padValue.Cmp(big.NewInt(0)), "padding not multiple of order")
		}, fmt.Sprintf("%s/nbLimbs=%d", testName[T](), i))
	}
}
