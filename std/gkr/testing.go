package gkr

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	gkrBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/gkr"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

// SolveAll IS A TEST FUNCTION USED ONLY TO DEBUG a GKR circuit
// The output is the values of all variables, across all instances
func (api *API) SolveAll(parentApi frontend.API) [][]frontend.Variable {
	res := make([][]frontend.Variable, len(api.toStore.Circuit))
	for i, w := range api.toStore.Circuit { // TODO use assignments
		res[i] = make([]frontend.Variable, api.nbInstances())
		copy(res[i], api.assignments[i])
		if len(w.Inputs) == 0 {
			continue
		}
		degree := Gates[w.Gate].Degree()
		var degreeFr int
		if parentApi.Compiler().Field().Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			degreeFr = gkrBls12377.Gates[w.Gate].Degree()
		} else {
			panic("field not yet supported")
		}
		if degree != degreeFr {
			panic(fmt.Errorf("gate \"%s\" degree mismatch: SNARK %d, Raw %d", w.Gate, degree, degreeFr))
		}
	}
	for instanceI := range api.nbInstances() {
		for wireI, w := range api.toStore.Circuit {
			if len(w.Dependencies) != 0 && len(w.Inputs) != 0 {
				panic(fmt.Errorf("non-input wire %d should not have dependencies", wireI))
			}
			for _, dep := range w.Dependencies {
				if dep.InputInstance == instanceI {
					if dep.OutputInstance >= instanceI {
						panic(fmt.Errorf("out of order dependency not yet supported in SolveAll; (wire %d, instance %d) depends on (wire %d, instance %d)", wireI, instanceI, dep.OutputWire, dep.OutputInstance))
					}
					if res[wireI][instanceI] != nil {
						panic(fmt.Errorf("dependency (wire %d, instance %d) <- (wire %d, instance %d) attempting to override existing value assignment", wireI, instanceI, dep.OutputWire, dep.OutputInstance))
					}
					res[wireI][instanceI] = api.assignments[dep.OutputWire][dep.OutputInstance]
				}
			}

			if res[wireI][instanceI] == nil { // no assignment or dependency
				if len(w.Inputs) == 0 {
					panic(fmt.Errorf("input wire %d, instance %d has no dependency or explicit assignment", wireI, instanceI))
				}
				ins := make([]frontend.Variable, len(w.Inputs))
				for i, in := range w.Inputs {
					ins[i] = res[in][instanceI]
				}
				expectedV, err := parentApi.Compiler().NewHint(frGateHint(w.Gate), 1, ins...)
				if err != nil {
					panic(err)
				}
				res[wireI][instanceI] = Gates[w.Gate].Evaluate(parentApi, ins...)
				parentApi.AssertIsEqual(expectedV[0], res[wireI][instanceI]) // snark and raw gate evaluations must agree
			}

		}
	}
	return res
}

func frGateHint(gateName string) hint.Hint {
	return func(mod *big.Int, ins, outs []*big.Int) error {
		if len(outs) != 1 {
			return errors.New("gate must have one output")
		}
		if ecc.BLS12_377.ScalarField().Cmp(mod) == 0 {

			gate := gkrBls12377.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			x := make([]frBls12377.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else {
			return errors.New("field not supported")
		}
		return nil
	}
}
