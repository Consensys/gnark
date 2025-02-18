package gkr

import (
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	frBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	gkrBls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377/fr/gkr"
	frBls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr"
	gkrBls12381 "github.com/consensys/gnark-crypto/ecc/bls12-381/fr/gkr"
	frBls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr"
	gkrBls24315 "github.com/consensys/gnark-crypto/ecc/bls24-315/fr/gkr"
	frBls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr"
	gkrBls24317 "github.com/consensys/gnark-crypto/ecc/bls24-317/fr/gkr"
	frBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	gkrBn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	frBw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr"
	gkrBw6633 "github.com/consensys/gnark-crypto/ecc/bw6-633/fr/gkr"
	frBw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	gkrBw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr/gkr"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"math/big"
)

// SolveInTestEngine solves the defined circuit directly inside the SNARK circuit. This means that the method does not compute the GKR proof of the circuit and does not embed the GKR proof verifier inside a SNARK.
// The output is the values of all variables, across all instances; i.e. indexed variable-first, instance-second.
// This method only works under the test engine and should only be called to debug a GKR circuit, as the GKR prover's errors can be obscure.
func (api *API) SolveInTestEngine(parentApi frontend.API) [][]frontend.Variable {
	res := make([][]frontend.Variable, len(api.toStore.Circuit))
	degreeTestedGates := make(map[string]struct{})
	for i, w := range api.toStore.Circuit {
		res[i] = make([]frontend.Variable, api.nbInstances())
		copy(res[i], api.assignments[i])
		if len(w.Inputs) == 0 {
			continue
		}
		degree := Gates[w.Gate].Degree()
		var degreeFr int
		if parentApi.Compiler().Field().Cmp(ecc.BLS12_377.ScalarField()) == 0 {
			degreeFr = gkrBls12377.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BN254.ScalarField()) == 0 {
			degreeFr = gkrBn254.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BLS24_315.ScalarField()) == 0 {
			degreeFr = gkrBls24315.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BW6_761.ScalarField()) == 0 {
			degreeFr = gkrBw6761.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BLS12_381.ScalarField()) == 0 {
			degreeFr = gkrBls12381.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BLS24_317.ScalarField()) == 0 {
			degreeFr = gkrBls24317.Gates[w.Gate].Degree()
		} else if parentApi.Compiler().Field().Cmp(ecc.BW6_633.ScalarField()) == 0 {
			degreeFr = gkrBw6633.Gates[w.Gate].Degree()
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
						panic(fmt.Errorf("out of order dependency not yet supported in SolveInTestEngine; (wire %d, instance %d) depends on (wire %d, instance %d)", wireI, instanceI, dep.OutputWire, dep.OutputInstance))
					}
					if res[wireI][instanceI] != nil {
						panic(fmt.Errorf("dependency (wire %d, instance %d) <- (wire %d, instance %d) attempting to override existing value assignment", wireI, instanceI, dep.OutputWire, dep.OutputInstance))
					}
					res[wireI][instanceI] = res[dep.OutputWire][dep.OutputInstance]
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
				expectedV, err := parentApi.Compiler().NewHint(frGateHint(w.Gate, degreeTestedGates), 1, ins...)
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

func frGateHint(gateName string, degreeTestedGates map[string]struct{}) hint.Hint {
	return func(mod *big.Int, ins, outs []*big.Int) error {
		if len(outs) != 1 {
			return errors.New("gate must have one output")
		}
		if ecc.BLS12_377.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls12377.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBls12377.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBls12377.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BN254.ScalarField().Cmp(mod) == 0 {
			gate := gkrBn254.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBn254.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBn254.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS24_315.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls24315.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBls24315.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBls24315.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BW6_761.ScalarField().Cmp(mod) == 0 {
			gate := gkrBw6761.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBw6761.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBw6761.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS12_381.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls12381.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBls12381.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBls12381.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS24_317.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls24317.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBls24317.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}

			x := make([]frBls24317.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BW6_633.ScalarField().Cmp(mod) == 0 {
			gate := gkrBw6633.Gates[gateName]
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			if _, ok := degreeTestedGates[gateName]; !ok {
				if err := gkrBw6633.TestGateDegree(gate, len(ins)); err != nil {
					return fmt.Errorf("gate %s: %w", gateName, err)
				}
				degreeTestedGates[gateName] = struct{}{}
			}
			x := make([]frBw6633.Element, len(ins))
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
