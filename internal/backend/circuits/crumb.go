package circuits

import (
	"github.com/consensys/gnark/frontend"
	"golang.org/x/exp/rand"
)

type isCrumbCircuit struct {
	C []frontend.Variable
}

func (circuit *isCrumbCircuit) Define(api frontend.API) error {
	for _, x := range circuit.C {
		api.AssertIsCrumb(x)
	}
	return nil
}

func init() {
	c := []frontend.Variable{0, 1, 2, 3}
	good := []frontend.Circuit{
		&isCrumbCircuit{C: c},
	}
	addNewEntry("isCrumb/case=good", &isCrumbCircuit{C: make([]frontend.Variable, len(c))}, good, nil, nil)
	var bad []frontend.Circuit
	for n := 0; n < 20; n++ {
		x := rand.Intn(65531) + 4 //#nosec G404 weak rng OK for test
		bad = append(bad, &isCrumbCircuit{C: []frontend.Variable{x}})
	}
	addNewEntry("isCrumb/case=bad", &isCrumbCircuit{C: []frontend.Variable{nil}}, nil, bad, nil)
}
