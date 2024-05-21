package fri

import (
	"math/big"

	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
)

// exp helper function that returns x^{e}
func exp(api frontend.API, x frontend.Variable, e []frontend.Variable) frontend.Variable {

	res := frontend.Variable(1)
	for i := 0; i < len(e); i++ {
		res = api.Mul(res, res)
		a := api.Mul(res, x)
		res = api.Select(e[len(e)-i-1], a, res)
	}
	return res
}

// // mustBeInSameFiber ensures that {g1,g2} = f^{-1}(x) where f: x -> x^{2}
// func mustBeInSameFiber(api frontend.API, g1, g2, x frontend.Variable) {
// 	_g1 := api.Mul(g1, g1)
// 	_g2 := api.Mul(g2, g2)
// 	api.AssertIsEqual(_g1, _g2)
// }

// convertCanonicalSorted convert the index i, an entry in a
// sorted polynomial, to the corresponding entry in canonical
// representation. n is the size of the polynomial (cf gnark-crypto).
func convertCanonicalSorted(i, n int) int {

	if i < n/2 {
		return 2 * i
	} else {
		l := n - (i + 1)
		l = 2 * l
		return n - l - 1
	}

}

// deriveQueriesPositions derives the indices of the oracle
// function that the verifier has to pick, in sorted form.
// * pos is the initial position, i.e. the logarithm of the first challenge
// * size is the size of the initial polynomial
// * The result is a slice of []int, where each entry is a tuple (iₖ), such that
// the verifier needs to evaluate ∑ₖ oracle(iₖ)xᵏ to build
// the folded function (cf gnark-crypto).
//
// In inputs, there are, in this order:
// * position: the initial position of the challenge (the log of the challenge)
// * size: the size of the multiplicative group
// * nbSteps: the number of steps for a round
//
// outputs:
// * slice of positions to query during a round
var DeriveQueriesPositions = func(_ *big.Int, inputs []*big.Int, res []*big.Int) error {

	pos := inputs[0].Uint64()
	s := inputs[1].Uint64()
	nbSteps := inputs[2].Uint64()

	res[0].SetUint64(pos)
	for i := 1; i < int(nbSteps); i++ {
		a := res[i-1].Uint64()
		t := (a - (a % 2)) / 2
		b := convertCanonicalSorted(int(t), int(s/2))
		res[i].SetUint64(uint64(b))
		s = s / 2
	}

	return nil
}

func init() {
	solver.RegisterHint(DeriveQueriesPositions)
}
