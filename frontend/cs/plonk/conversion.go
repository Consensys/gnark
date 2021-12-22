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

package plonk

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
	"github.com/consensys/gnark/internal/backend/compiled"
)

func (cs *sparseR1CS) Compile() (frontend.CompiledConstraintSystem, error) {

	res := compiled.SparseR1CS{
		CS:          cs.CS,
		Constraints: cs.Constraints,
	}
	res.NbPublicVariables = len(cs.Public)
	res.NbSecretVariables = len(cs.Secret)

	// Logs, DebugInfo and hints are copied, the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// shift variable ID
	// we want publicWires | privateWires | internalWires
	shiftVID := func(oldID int, visibility compiled.Visibility) int {
		switch visibility {
		case compiled.Internal:
			return oldID + res.NbPublicVariables + res.NbSecretVariables
		case compiled.Public:
			return oldID
		case compiled.Secret:
			return oldID + res.NbPublicVariables
		default:
			return oldID
		}
	}

	offsetTermID := func(t *compiled.Term) {
		_, VID, visibility := t.Unpack()
		t.SetWireID(shiftVID(VID, visibility))
	}

	// offset the IDs of all constraints so that the variables are
	// numbered like this: [publicVariables | secretVariables | internalVariables ]
	for i := 0; i < len(res.Constraints); i++ {
		r1c := &res.Constraints[i]
		offsetTermID(&r1c.L)
		offsetTermID(&r1c.R)
		offsetTermID(&r1c.O)
		offsetTermID(&r1c.M[0])
		offsetTermID(&r1c.M[1])
	}

	// we need to offset the ids in Logs & DebugInfo
	for i := 0; i < len(cs.Logs); i++ {
		for j := 0; j < len(res.Logs[i].ToResolve); j++ {
			offsetTermID(&res.Logs[i].ToResolve[j])
		}
	}
	for i := 0; i < len(cs.DebugInfo); i++ {
		for j := 0; j < len(res.DebugInfo[i].ToResolve); j++ {
			offsetTermID(&res.DebugInfo[i].ToResolve[j])
		}
	}

	// we need to offset the ids in the hints
	shiftedMap := make(map[int]compiled.Hint)
	for VID, hint := range cs.MHints {
		k := shiftVID(VID, compiled.Internal)
		inputs := make([]interface{}, len(hint.Inputs))
		copy(inputs, hint.Inputs)
		for j := 0; j < len(inputs); j++ {
			switch t := inputs[j].(type) {
			case compiled.Term:
				offsetTermID(&t)
				inputs[j] = t // TODO check if we can remove it
			default:
				inputs[j] = t
			}
		}
		shiftedMap[k] = compiled.Hint{ID: hint.ID, Inputs: inputs}
	}
	res.MHints = shiftedMap

	switch cs.CurveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	case ecc.BW6_633:
		return bw6633r1cs.NewSparseR1CS(res, cs.Coeffs), nil
	default:
		panic("unknown curveID")
	}

}
