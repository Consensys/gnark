/*
Copyright © 2021 ConsenSys Software Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package frontend

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/internal/backend/compiled"

	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

// toR1CS constructs a rank-1 constraint sytem
func (cs *R1CS) toR1CS(curveID ecc.ID) (compiled.CompiledConstraintSystem, error) {

	// wires = public wires  | secret wires | internal wires

	// setting up the result
	res := compiled.R1CS{
		CS: compiled.CS{
			NbInternalVariables: cs.internal,
			NbPublicVariables:   len(cs.public),
			NbSecretVariables:   len(cs.secret),
			DebugInfo:           make([]compiled.LogEntry, len(cs.debugInfo)),
			Logs:                make([]compiled.LogEntry, len(cs.logs)),
			MHints:              make(map[int]compiled.Hint, len(cs.mHints)),
			MDebug:              make(map[int]int),
			Counters:            make([]compiled.Counter, len(cs.counters)),
		},
		Constraints: make([]compiled.R1C, len(cs.constraints)),
	}

	// for logs, debugInfo and hints the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// computational constraints (= gates)
	for i, r1c := range cs.constraints {
		res.Constraints[i] = compiled.R1C{
			L: r1c.L.Clone(),
			R: r1c.R.Clone(),
			O: r1c.O.Clone(),
		}
	}

	// for a R1CS, the correspondance between constraint and debug info won't change, we just copy
	for k, v := range cs.mDebug {
		res.MDebug[k] = v
	}

	// same fore counters
	// for i, c := range cs.counters {
	// 	res.Counters[i] = compiled.Counter{
	// 		From:          c.From.Name,
	// 		To:            c.To.Name,
	// 		NbVariables:   c.NbVariables,
	// 		NbConstraints: c.NbConstraints,
	// 		CurveID:       curveID,
	// 		BackendID:     backend.GROTH16,
	// 	}
	// }
	res.Counters = cs.counters

	// offset variable ID depeneding on visibility
	shiftVID := func(oldID int, visibility compiled.Visibility) int {
		switch visibility {
		case compiled.Internal:
			return oldID + len(cs.public) + len(cs.secret)
		case compiled.Public:
			return oldID
		case compiled.Secret:
			return oldID + len(cs.public)
		}
		return oldID
	}

	// we just need to offset our ids, such that wires = [ public wires  | secret wires | internal wires ]
	offsetIDs := func(l compiled.LinearExpression) {
		for j := 0; j < len(l); j++ {
			_, vID, visibility := l[j].Unpack()
			l[j].SetWireID(shiftVID(vID, visibility))
		}
	}

	for i := 0; i < len(res.Constraints); i++ {
		offsetIDs(res.Constraints[i].L.LinExp)
		offsetIDs(res.Constraints[i].R.LinExp)
		offsetIDs(res.Constraints[i].O.LinExp)
	}

	// we need to offset the ids in the hints
	for vID, hint := range cs.mHints {
		k := shiftVID(vID, compiled.Internal)
		inputs := make([]compiled.LinearExpression, len(hint.Inputs))
		copy(inputs, hint.Inputs)
		for j := 0; j < len(inputs); j++ {
			offsetIDs(inputs[j])
		}
		res.MHints[k] = compiled.Hint{ID: hint.ID, Inputs: inputs}
	}

	// we need to offset the ids in logs & debugInfo
	for i := 0; i < len(cs.logs); i++ {
		res.Logs[i] = compiled.LogEntry{
			Format:    cs.logs[i].Format,
			ToResolve: make([]compiled.Term, len(cs.logs[i].ToResolve)),
		}
		copy(res.Logs[i].ToResolve, cs.logs[i].ToResolve)

		for j := 0; j < len(res.Logs[i].ToResolve); j++ {
			_, vID, visibility := res.Logs[i].ToResolve[j].Unpack()
			res.Logs[i].ToResolve[j].SetWireID(shiftVID(vID, visibility))
		}
	}
	for i := 0; i < len(cs.debugInfo); i++ {
		res.DebugInfo[i] = compiled.LogEntry{
			Format:    cs.debugInfo[i].Format,
			ToResolve: make([]compiled.Term, len(cs.debugInfo[i].ToResolve)),
		}
		copy(res.DebugInfo[i].ToResolve, cs.debugInfo[i].ToResolve)

		for j := 0; j < len(res.DebugInfo[i].ToResolve); j++ {
			_, vID, visibility := res.DebugInfo[i].ToResolve[j].Unpack()
			res.DebugInfo[i].ToResolve[j].SetWireID(shiftVID(vID, visibility))
		}
	}

	switch curveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BW6_633:
		return bw6633r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewR1CS(res, cs.coeffs), nil
	case ecc.UNKNOWN:
		return &res, nil
	default:
		panic("not implemtented")
	}
}
