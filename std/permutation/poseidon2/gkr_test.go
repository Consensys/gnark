package poseidon2

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
	}

	for i := halfRf + c.h.params.rP + 1; i < c.h.params.rP+c.h.params.rF; i++ {
		fullRound(i)
	}

	y = extGate{}.Evaluate(api, y, x)

	xCp := c.In
	if err := c.h.Permutation(api, xCp[:]); err != nil {
		return err
	}

	api.AssertIsEqual(xCp[1], y) // as a compression function, the output is the second one
	api.Println(y)
	return nil
}

func TestGkrPermutation(t *testing.T) {
	pos2Fr := poseidon2.NewHash(2, rF, rP, seed)
	const n = 1
	var k int64
	ins := make([][2]frontend.Variable, n)
	outs := make([]frontend.Variable, n)
	for i := range n {
		var x [2]fr.Element
		ins[i] = [2]frontend.Variable{k, k + 1}

		x[0].SetInt64(k)
		x[1].SetInt64(k + 1)

		require.NoError(t, pos2Fr.Permutation(x[:]))
		outs[i] = x[1]

		k += 2
	}

	circuit := testGkrPermutationCircuit{
		Ins:  ins,
		Outs: outs,
	}

	AddGkrGatesSolution()

	require.NoError(t, test.IsSolved(&circuit, &circuit, ecc.BLS12_377.ScalarField()))
}

type testGkrPermutationCircuit struct {
	Ins  [][2]frontend.Variable
	Outs []frontend.Variable
}

func (c *testGkrPermutationCircuit) Define(api frontend.API) error {

	pos2 := newGkrPermutations(api)
	api.AssertIsEqual(len(c.Ins), len(c.Outs))
	for i := range c.Ins {
		api.AssertIsEqual(c.Outs[i], pos2.permute(c.Ins[i][0], c.Ins[i][1]))

	}

	return nil
}
