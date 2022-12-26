package keccakf_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
	"github.com/consensys/gnark/test"
)

type keccakfCircuit struct {
	In       [25]frontend.Variable
	Expected [25]frontend.Variable `gnark:",public"`
}

func (c *keccakfCircuit) Define(api frontend.API) error {
	uapi := keccakf.Uint64api{}
	in := [25]keccakf.Xuint64{}
	for i := range c.In {
		in[i] = uapi.AsUint64(c.In[i])
	}
	res := keccakf.Permute(api, &in)
	for i := range res {
		api.AssertIsEqual(res[i], c.Expected[i])
	}
	return nil
}

func TestKeccakf(t *testing.T) {
	var nativeIn [25]uint64
	for i := range nativeIn {
		nativeIn[i] = 2
	}
	nativeOut := keccakF1600(nativeIn)
	witness := keccakfCircuit{}
	for i := range nativeIn {
		witness.In[i] = nativeIn[i]
		witness.Expected[i] = nativeOut[i]
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&keccakfCircuit{}, &witness, test.WithCurves(ecc.BN254))
}
