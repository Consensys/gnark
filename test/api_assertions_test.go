package test

import (
	"github.com/consensys/gnark/frontend"
	"math/rand"
	"testing"
)

func TestIsCrumb(t *testing.T) {
	c := []frontend.Variable{0, 1, 2, 3}
	assert := NewAssert(t)
	assert.SolvingSucceeded(&isCrumbCircuit{C: make([]frontend.Variable, len(c))}, &isCrumbCircuit{C: c})
	for n := 0; n < 20; n++ {
		x := rand.Intn(65531) + 4 //#nosec G404 weak rng OK for test
		assert.SolvingFailed(&isCrumbCircuit{C: []frontend.Variable{nil}}, &isCrumbCircuit{C: []frontend.Variable{x}})
	}
}

type isCrumbCircuit struct {
	C []frontend.Variable
}

func (circuit *isCrumbCircuit) Define(api frontend.API) error {
	for _, x := range circuit.C {
		api.AssertIsCrumb(x)
	}
	return nil
}
