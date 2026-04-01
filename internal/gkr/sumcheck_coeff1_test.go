package gkr

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/polynomial"
	"github.com/consensys/gnark/test"
)

type coeffOneFrontendLazyClaim struct{}

func (coeffOneFrontendLazyClaim) degree(int) int { return 1 }

func (coeffOneFrontendLazyClaim) roundCombinationCoeff(int) (frontend.Variable, bool) {
	return 1, true
}

func (coeffOneFrontendLazyClaim) varsNum() int { return 1 }

func (coeffOneFrontendLazyClaim) verifyFinalEval(api frontend.API, r []frontend.Variable, purportedValue frontend.Variable, proof []frontend.Variable) error {
	if len(r) != 1 {
		return fmt.Errorf("unexpected challenge length %d", len(r))
	}
	api.AssertIsEqual(r[0], 2)
	api.AssertIsEqual(purportedValue, 14)
	return nil
}

type coeffOneFrontendVerifyCircuit struct {
	G0         frontend.Variable
	ClaimedSum frontend.Variable
}

func (c *coeffOneFrontendVerifyCircuit) Define(api frontend.API) error {
	proof := sumcheckProof{
		PartialSumPolys: []polynomial.Polynomial{{c.G0}},
	}
	tr := transcript{h: newMessageCounter(api, 2, 0)}
	return verifySumcheck(api, coeffOneFrontendLazyClaim{}, proof, c.ClaimedSum, 1, &tr)
}

func TestFrontendSumcheckVerifyCoeffOneReconstruction(t *testing.T) {
	assert := test.NewAssert(t)
	assert.CheckCircuit(
		&coeffOneFrontendVerifyCircuit{},
		test.WithValidAssignment(&coeffOneFrontendVerifyCircuit{G0: 4, ClaimedSum: 9}),
		test.WithInvalidAssignment(&coeffOneFrontendVerifyCircuit{G0: 5, ClaimedSum: 9}),
	)
}
