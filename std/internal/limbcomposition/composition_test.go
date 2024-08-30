package limbs_test

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"reflect"
	"testing"

	limbs "github.com/consensys/gnark/std/internal/limbcomposition"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/consensys/gnark/std/math/emulated/emparams"
	"github.com/consensys/gnark/test"
)

func TestComposition(t *testing.T) {
	testComposition[emparams.BN254Fp](t)
	testComposition[emparams.Secp256k1Fp](t)
	testComposition[emparams.BLS12377Fp](t)
	testComposition[emparams.Goldilocks](t)
}

func testComposition[T emulated.FieldParams](t *testing.T) {
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
		if err = limbs.Decompose(n, fp.BitsPerLimb(), res); err != nil {
			assert.FailNow("decompose", err)
		}
		n2 := new(big.Int)
		if err = limbs.Recompose(res, fp.BitsPerLimb(), n2); err != nil {
			assert.FailNow("recompose", err)
		}
		if n2.Cmp(n) != 0 {
			assert.FailNow("unequal")
		}
	}, fmt.Sprintf("%s/limb=%d", reflect.TypeOf(fp).Name(), fp.BitsPerLimb()))
}
