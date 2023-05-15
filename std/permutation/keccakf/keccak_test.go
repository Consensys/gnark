package keccakf_test

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/keccakf"
	"github.com/consensys/gnark/test"
)

type keccakfCircuit struct {
	In       [25]frontend.Variable
	Expected [25]frontend.Variable `gnark:",public"`
}

func (c *keccakfCircuit) Define(api frontend.API) error {
	var res [25]frontend.Variable
	for i := range res {
		res[i] = c.In[i]
	}
	for i := 0; i < 2; i++ {
		res = keccakf.Permute(api, res)
	}
	for i := range res {
		api.AssertIsEqual(res[i], c.Expected[i])
	}
	return nil
}

func TestKeccakf(t *testing.T) {
	var nativeIn [25]uint64
	var res [25]uint64
	for i := range nativeIn {
		nativeIn[i] = 2
		res[i] = 2
	}
	for i := 0; i < 2; i++ {
		res = keccakF1600(res)
	}
	witness := keccakfCircuit{}
	for i := range nativeIn {
		witness.In[i] = nativeIn[i]
		witness.Expected[i] = res[i]
	}
	assert := test.NewAssert(t)
	assert.ProverSucceeded(&keccakfCircuit{}, &witness,
		test.WithCurves(ecc.BN254),
		test.WithBackends(backend.GROTH16, backend.PLONK),
		test.NoFuzzing())
}
