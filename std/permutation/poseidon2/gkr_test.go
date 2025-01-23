package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestGkrGates(t *testing.T) {
	h := Hash{
		params: parameters{
			t:  2,
			d:  3,
			rF: 4,
			rP: 2,
		},
	}
	h.params.roundKeys = make([][]big.Int, h.params.rF+h.params.rP)
	k := int64(1)
	for i := range h.params.roundKeys {
		h.params.roundKeys[i] = make([]big.Int, h.params.t)
		for j := range h.params.roundKeys[i] {
			h.params.roundKeys[i][j].SetInt64(k)
			k++
		}
	}

	circuit := testGkrGatesCircuit{
		h:  &h,
		In: [2]frontend.Variable{0, 0},
	}

	assert.NoError(t, test.IsSolved(&circuit, &circuit, ecc.BLS12_377.ScalarField()))
}

type testGkrGatesCircuit struct {
	h  *Hash
	In [2]frontend.Variable
}

func (c *testGkrGatesCircuit) Define(api frontend.API) error {
	halfRf := c.h.params.rF / 2
	x, y := c.In[0], c.In[1]

	fullRound := func(i int) {
		gate := extKeySBoxGate{
			roundKey: &c.h.params.roundKeys[i][0],
			d:        c.h.params.d,
		}

		x1 := gate.Evaluate(api, x, y)

		gate.roundKey = &c.h.params.roundKeys[i][1]
		x, y = x1, gate.Evaluate(api, y, x)
	}

	for i := range halfRf {
		fullRound(i)
		//api.Println("x after round", i, "sBox", x)
	}

	{ // i = halfRf: first partial round
		var gate gkr.Gate = &extKeySBoxGate{
			roundKey: &c.h.params.roundKeys[halfRf][0],
			d:        c.h.params.d,
		}
		x1 := gate.Evaluate(api, x, y)

		gate = &extKeyGate2{
			roundKey: &c.h.params.roundKeys[halfRf][1],
			d:        c.h.params.d,
		}
		x, y = x1, gate.Evaluate(api, x, y)
		//api.Println("x after round", halfRf, "sBox", x)
	}

	for i := halfRf + 1; i < halfRf+c.h.params.rP; i++ {
		var gate gkr.Gate = &extKeySBoxGate{ // for x1, intKeySBox is identical to extKeySBox
			roundKey: &c.h.params.roundKeys[i][0],
			d:        c.h.params.d,
		}
		x1 := gate.Evaluate(api, x, y)

		gate = &intKeyGate2{
			roundKey: &c.h.params.roundKeys[i][1],
			d:        c.h.params.d,
		}
		x, y = x1, gate.Evaluate(api, x, y)
		api.Println("y after round", i, "sBox", y)
	}

	{
		i := halfRf + c.h.params.rP
		var gate gkr.Gate = &extKeySBoxGate{
			roundKey: &c.h.params.roundKeys[i][0],
			d:        c.h.params.d,
		}
		x1 := gate.Evaluate(api, x, y)

		gate = &intKeySBoxGate2{
			roundKey: &c.h.params.roundKeys[i][1],
			d:        c.h.params.d,
		}
		x, y = x1, gate.Evaluate(api, x, y)
		api.Println("x after round", i, "sBox", x)
		api.Println("y after round", i, "sBox", y)
	}

	for i := halfRf + c.h.params.rP + 1; i < c.h.params.rP+c.h.params.rF; i++ {
		fullRound(i)
		api.Println("x after round", i, "sBox", x)
		api.Println("y after round", i, "sBox", y)
	}

	x = extGate{}.Evaluate(api, x, y)

	xCp := c.In
	if err := c.h.Permutation(api, xCp[:]); err != nil {
		return err
	}

	api.AssertIsEqual(xCp[0], x)
	return nil
}
