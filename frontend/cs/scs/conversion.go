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

package scs

import (
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/frontend/schema"
	bls12377r1cs "github.com/consensys/gnark/internal/backend/bls12-377/cs"
	bls12381r1cs "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	bls24315r1cs "github.com/consensys/gnark/internal/backend/bls24-315/cs"
	bn254r1cs "github.com/consensys/gnark/internal/backend/bn254/cs"
	bw6633r1cs "github.com/consensys/gnark/internal/backend/bw6-633/cs"
	bw6761r1cs "github.com/consensys/gnark/internal/backend/bw6-761/cs"
)

func (cs *sparseR1CS) Compile(opt frontend.CompileConfig) (frontend.CompiledConstraintSystem, error) {

	// ensure all inputs and hints are constrained
	if !opt.IgnoreUnconstrainedInputs {
		if err := cs.checkVariables(); err != nil {
			return nil, err
		}
	}

	res := compiled.SparseR1CS{
		ConstraintSystem: cs.ConstraintSystem,
		Constraints:      cs.Constraints,
	}
	res.NbPublicVariables = len(cs.Public)
	res.NbSecretVariables = len(cs.Secret)

	// Logs, DebugInfo and hints are copied, the only thing that will change
	// is that ID of the wires will be offseted to take into account the final wire vector ordering
	// that is: public wires  | secret wires | internal wires

	// shift variable ID
	// we want publicWires | privateWires | internalWires
	shiftVID := func(oldID int, visibility schema.Visibility) int {
		switch visibility {
		case schema.Internal:
			return oldID + res.NbPublicVariables + res.NbSecretVariables
		case schema.Public:
			return oldID
		case schema.Secret:
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
	shiftedMap := make(map[int]*compiled.Hint)
HINTLOOP:
	for _, hint := range cs.MHints {
		ws := make([]int, len(hint.Wires))
		// we set for all outputs in shiftedMap. If one shifted output
		// is in shiftedMap, then all are
		for i, vID := range hint.Wires {
			ws[i] = shiftVID(vID, schema.Internal)
			if _, ok := shiftedMap[ws[i]]; i == 0 && ok {
				continue HINTLOOP
			}
		}
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
		ch := &compiled.Hint{ID: hint.ID, Inputs: inputs, Wires: ws}
		for _, vID := range ws {
			shiftedMap[vID] = ch
		}
	}
	res.MHints = shiftedMap

	// build levels
	res.Levels = buildLevels(res)

	switch cs.CurveID {
	case ecc.BLS12_377:
		return bls12377r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BLS12_381:
		return bls12381r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BN254:
		return bn254r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BW6_761:
		return bw6761r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BLS24_315:
		return bls24315r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	case ecc.BW6_633:
		return bw6633r1cs.NewSparseR1CS(res, cs.st.Coeffs), nil
	default:
		panic("unknown curveID")
	}

}

func (cs *sparseR1CS) SetSchema(s *schema.Schema) {
	if cs.Schema != nil {
		panic("SetSchema called multiple times")
	}
	cs.Schema = s
}

func buildLevels(ccs compiled.SparseR1CS) [][]int {

	b := levelBuilder{
		mWireToNode: make(map[int]int, ccs.NbInternalVariables), // at which node we resolved which wire
		nodeLevels:  make([]int, len(ccs.Constraints)),          // level of a node
		mLevels:     make(map[int]int),                          // level counts
		ccs:         ccs,
		nbInputs:    ccs.NbPublicVariables + ccs.NbSecretVariables,
	}

	// for each constraint, we're going to find its direct dependencies
	// that is, wires (solved by previous constraints) on which it depends
	// each of these dependencies is tagged with a level
	// current constraint will be tagged with max(level) + 1
	for cID, c := range ccs.Constraints {

		b.nodeLevel = 0

		b.processTerm(c.L, cID)
		b.processTerm(c.R, cID)
		b.processTerm(c.O, cID)

		b.nodeLevels[cID] = b.nodeLevel
		b.mLevels[b.nodeLevel]++

	}

	levels := make([][]int, len(b.mLevels))
	for i := 0; i < len(levels); i++ {
		// allocate memory
		levels[i] = make([]int, 0, b.mLevels[i])
	}

	for n, l := range b.nodeLevels {
		levels[l] = append(levels[l], n)
	}

	return levels
}

type levelBuilder struct {
	ccs      compiled.SparseR1CS
	nbInputs int

	mWireToNode map[int]int // at which node we resolved which wire
	nodeLevels  []int       // level per node
	mLevels     map[int]int // number of constraint per level

	nodeLevel int // current level
}

func (b *levelBuilder) processTerm(t compiled.Term, cID int) {
	wID := t.WireID()
	if wID < b.nbInputs {
		// it's a input, we ignore it
		return
	}

	// if we know a which constraint solves this wire, then it's a dependency
	n, ok := b.mWireToNode[wID]
	if ok {
		if n != cID { // can happen with hints...
			// we add a dependency, check if we need to increment our current level
			if b.nodeLevels[n] >= b.nodeLevel {
				b.nodeLevel = b.nodeLevels[n] + 1 // we are at the next level at least since we depend on it
			}
		}
		return
	}

	// check if it's a hint and mark all the output wires
	if h, ok := b.ccs.MHints[wID]; ok {

		for _, in := range h.Inputs {
			switch t := in.(type) {
			case compiled.Variable:
				for _, tt := range t.LinExp {
					b.processTerm(tt, cID)
				}
			case compiled.LinearExpression:
				for _, tt := range t {
					b.processTerm(tt, cID)
				}
			case compiled.Term:
				b.processTerm(t, cID)
			}
		}

		for _, hwid := range h.Wires {
			b.mWireToNode[hwid] = cID
		}

		return
	}

	// mark this wire solved by current node
	b.mWireToNode[wID] = cID

}
