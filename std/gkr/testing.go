package gkr

import (
	"errors"
	"fmt"
	"math/big"
	"sync"

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
)

// SolveInTestEngine solves the defined circuit directly inside the SNARK circuit. This means that the method does not compute the GKR proof of the circuit and does not embed the GKR proof verifier inside a SNARK.
// The output is the values of all variables, across all instances; i.e. indexed variable-first, instance-second.
// This method only works under the test engine and should only be called to debug a GKR circuit, as the GKR prover's errors can be obscure.
func (api *API) SolveInTestEngine(parentApi frontend.API) [][]frontend.Variable {
	res := make([][]frontend.Variable, len(api.toStore.Circuit))
	var degreeTestedGates sync.Map
	for i, w := range api.toStore.Circuit {
		res[i] = make([]frontend.Variable, api.nbInstances())
		copy(res[i], api.assignments[i])
		if len(w.Inputs) == 0 {
			continue
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
				expectedV, err := parentApi.Compiler().NewHint(frGateHint(GateName(w.Gate), &degreeTestedGates), 1, ins...)
				if err != nil {
					panic(err)
				}
				res[wireI][instanceI] = GetGate(GateName(w.Gate)).Evaluate(parentApi, ins...)
				parentApi.AssertIsEqual(expectedV[0], res[wireI][instanceI]) // snark and raw gate evaluations must agree
			}
		}
	}
	return res
}

func frGateHint(gateName GateName, degreeTestedGates *sync.Map) hint.Hint {
	return func(mod *big.Int, ins, outs []*big.Int) error {
		const dummyGateName = "dummy-solve-in-test-engine-gate"
		var degreeFr, nbInFr, solvableVarFr int
		if len(outs) != 1 {
			return errors.New("gate must have one output")
		}
		if ecc.BLS12_377.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls12377.GetGate(gkrBls12377.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBls12377.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBls12377.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBls12377.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BN254.ScalarField().Cmp(mod) == 0 {
			gate := gkrBn254.GetGate(gkrBn254.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBn254.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBn254.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBn254.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS24_315.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls24315.GetGate(gkrBls24315.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBls24315.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBls24315.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBls24315.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BW6_761.ScalarField().Cmp(mod) == 0 {
			gate := gkrBw6761.GetGate(gkrBw6761.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBw6761.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBw6761.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBw6761.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS12_381.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls12381.GetGate(gkrBls12381.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBls12381.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBls12381.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBls12381.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BLS24_317.ScalarField().Cmp(mod) == 0 {
			gate := gkrBls24317.GetGate(gkrBls24317.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBls24317.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBls24317.WithDegree(degreeFr)); err != nil {
					return err
				}
			}
			x := make([]frBls24317.Element, len(ins))
			for i := range ins {
				x[i].SetBigInt(ins[i])
			}
			y := gate.Evaluate(x...)
			y.BigInt(outs[0])
		} else if ecc.BW6_633.ScalarField().Cmp(mod) == 0 {
			gate := gkrBw6633.GetGate(gkrBw6633.GateName(gateName))
			if gate == nil {
				return fmt.Errorf("gate \"%s\" not found", gateName)
			}
			degreeFr = gate.Degree()
			nbInFr = gate.NbIn()
			solvableVarFr = gate.SolvableVar()
			if _, ok := degreeTestedGates.Load(gateName); !ok {
				// re-register the gate to make sure the degree is correct
				if err := gkrBw6633.RegisterGate(dummyGateName, gate.Evaluate, nbInFr, gkrBw6633.WithDegree(degreeFr)); err != nil {
					return err
				}
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

		degreeTestedGates.Store(gateName, struct{}{})

		if degreeFr != GetGate(gateName).Degree() {
			return fmt.Errorf("gate \"%s\" degree mismatch: SNARK %d, Raw %d", gateName, GetGate(gateName).Degree(), degreeFr)
		}

		if nbInFr != len(ins) { // TODO @Tabaie also check against GetGate(gateName].NbIn()
			return fmt.Errorf("gate \"%s\" input count mismatch: SNARK %d, Raw %d", gateName, len(ins), nbInFr)
		}

		if solvableVarFr != GetGate(gateName).SolvableVar() {
			return fmt.Errorf("gate \"%s\" designated solvable variable mismatch: SNARK %d, Raw %d", gateName, GetGate(gateName).SolvableVar(), solvableVarFr)
		}

		return nil
	}
}
