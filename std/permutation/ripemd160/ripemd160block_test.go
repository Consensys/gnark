package ripemd160

import (
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type blockCircuit struct {
	CurrentDig [5]uints.U32
	In         [64]uints.U8
	Expected   [5]uints.U32
}

func (c *blockCircuit) Define(api frontend.API) error {
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	res := Permute(uapi, c.CurrentDig, c.In)
	for i := range c.Expected {
		uapi.AssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestBlockGeneric(t *testing.T) {
	assert := test.NewAssert(t)
	s := rand.New(rand.NewSource(time.Now().Unix())) //nolint G404, test code
	witness := blockCircuit{}
	dig := digest{}
	var in [64]byte
	for i := range dig.s {
		dig.s[i] = s.Uint32()
		witness.CurrentDig[i] = uints.NewU32(dig.s[i])
	}
	for i := range in {
		in[i] = byte(s.Uint32() & 0xff)
		witness.In[i] = uints.NewU8(in[i])
	}
	blockGeneric(&dig, in[:])
	for i := range dig.s {
		witness.Expected[i] = uints.NewU32(dig.s[i])
	}
	err := test.IsSolved(&blockCircuit{}, &witness, ecc.BN254.ScalarField())
	assert.NoError(err)
}
