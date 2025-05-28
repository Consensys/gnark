package gkrapi

import (
	"errors"
	"fmt"
	"sync"

	"github.com/consensys/gnark/constraint/solver/gkrgates"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/internal/utils"
	"github.com/consensys/gnark/std/gkr"
	stdHash "github.com/consensys/gnark/std/hash"
)

type solveInTestEngineSettings struct {
	hashName string
}

type SolveInTestEngineOption func(*solveInTestEngineSettings)

func WithHashName(name string) SolveInTestEngineOption {
	return func(s *solveInTestEngineSettings) {
		s.hashName = name
	}
}

// SolveInTestEngine solves the defined circuit directly inside the SNARK circuit. This means that the method does not compute the GKR proof of the circuit and does not embed the GKR proof verifier inside a SNARK.
// The output is the values of all variables, across all instances; i.e. indexed variable-first, instance-second.
// This method only works under the test engine and should only be called to debug a GKR circuit, as the GKR prover's errors can be obscure.
func (api *API) SolveInTestEngine(parentApi frontend.API, options ...SolveInTestEngineOption) [][]frontend.Variable {
	gateVer, err := gkrgates.NewGateVerifier(utils.FieldToCurve(parentApi.Compiler().Field()))
	if err != nil {
		panic(err)
	}

	var s solveInTestEngineSettings
	for _, o := range options {
		o(&s)
	}
	if s.hashName != "" {
		// hash something and make sure it gives the same answer both on prover and verifier sides
		// TODO @Tabaie If indeed cheap, move this feature to Verify so that it is always run
		h, err := stdHash.GetFieldHasher(s.hashName, parentApi)
		if err != nil {
			panic(err)
		}
		nbBytes := (parentApi.Compiler().FieldBitLen() + 7) / 8
		toHash := frontend.Variable(0)
		for i := range nbBytes {
			toHash = parentApi.Add(parentApi.Mul(toHash, 256), i%256)
		}
		h.Reset()
		h.Write(toHash)
		hashed := h.Sum()

		hintOut, err := parentApi.Compiler().NewHint(CheckHashHint(s.hashName), 1, toHash, hashed)
		if err != nil {
			panic(err)
		}
		parentApi.AssertIsEqual(hintOut[0], hashed) // the hint already checks this
	}

	res := make([][]frontend.Variable, len(api.toStore.Circuit))
	var verifiedGates sync.Map
	for i, w := range api.toStore.Circuit {
		res[i] = make([]frontend.Variable, api.nbInstances())
		copy(res[i], api.assignments[i])
		if len(w.Inputs) == 0 {
			continue
		}
	}
	for instanceI := range api.nbInstances() {
		for wireI, w := range api.toStore.Circuit {
			deps := api.toStore.Dependencies[wireI]
			if len(deps) != 0 && len(w.Inputs) != 0 {
				panic(fmt.Errorf("non-input wire %d should not have dependencies", wireI))
			}
			for _, dep := range deps {
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
				gate := gkrgates.Get(gkr.GateName(w.Gate))
				if gate == nil && !w.IsInput() {
					panic(fmt.Errorf("gate %s not found", w.Gate))
				}
				if _, ok := verifiedGates.Load(w.Gate); !ok {
					verifiedGates.Store(w.Gate, struct{}{})

					err = errors.Join(
						gateVer.VerifyDegree(gate),
						gateVer.VerifySolvability(gate),
					)
					if err != nil {
						panic(fmt.Errorf("gate %s: %w", w.Gate, err))
					}
				}
				if gate != nil {
					res[wireI][instanceI] = gate.Evaluate(parentApi, ins...)
				}
			}
		}
	}
	return res
}
