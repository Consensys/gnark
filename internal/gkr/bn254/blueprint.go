// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package gkr

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/polynomial"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/gkr/gkrtypes"
)

// circuitEvaluator evaluates all gates in a circuit for one instance
type circuitEvaluator struct {
	evaluators []gateEvaluator // one evaluator per wire
}

// BlueprintGKRSolve is a BN254-specific blueprint for solving GKR circuit instances.
type BlueprintGKRSolve struct {
	// Circuit structure
	Circuit      gkrtypes.Circuit
	NbInputs     int
	NbOutputVars int
	InputWires   []int
	OutputWires  []int
	MaxNbIn      int // maximum number of inputs for any gate

	// Stateful data - stored as native fr.Element
	nbInstances   int
	assignment    WireAssignment // []polynomial.MultiLin
	evaluatorPool sync.Pool      // pool of circuitEvaluator for reuse

	lock sync.Mutex
}

// InitializeEvaluatorPool initializes the evaluator pool for this blueprint
func (b *BlueprintGKRSolve) InitializeEvaluatorPool(circuit gkrtypes.Circuit, maxGateStackSize int) {
	elementPool := polynomial.NewPool(maxGateStackSize)
	b.evaluatorPool = sync.Pool{
		New: func() interface{} {
			ce := &circuitEvaluator{
				evaluators: make([]gateEvaluator, len(circuit)),
			}
			for wI := range circuit {
				w := &circuit[wI]
				if !w.IsInput() {
					ce.evaluators[wI] = newGateEvaluator(w.Gate.Compiled(), len(w.Inputs), &elementPool)
				}
			}
			return ce
		},
	}
}

// Ensures BlueprintGKRSolve implements BlueprintStateful
var _ constraint.BlueprintStateful[constraint.U64] = (*BlueprintGKRSolve)(nil)

// Solve implements the BlueprintStateful interface.
func (b *BlueprintGKRSolve) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	instanceIdx := b.nbInstances

	// Initialize assignment array if this is the first instance
	if b.assignment == nil {
		b.assignment = make(WireAssignment, len(b.Circuit))
		for i := range b.assignment {
			b.assignment[i] = make(polynomial.MultiLin, 0, 16) // pre-allocate
		}
	}

	// Grow assignment slices to accommodate this instance
	for i := range b.assignment {
		for len(b.assignment[i]) <= instanceIdx {
			var zero fr.Element
			b.assignment[i] = append(b.assignment[i], zero)
		}
	}

	// Read input values from instruction calldata
	nbInputsInst := int(inst.Calldata[1])
	if nbInputsInst != b.NbInputs {
		return fmt.Errorf("expected %d inputs, got %d", b.NbInputs, nbInputsInst)
	}

	offset := 2

	// Get a circuit evaluator from the pool
	ce := b.evaluatorPool.Get().(*circuitEvaluator)
	defer b.evaluatorPool.Put(ce)

	// Process all wires in topological order (circuit is already sorted)
	inputIdx := 0
	for wI := range b.Circuit {
		w := &b.Circuit[wI]

		if w.IsInput() {
			// Read input value from calldata and convert to fr.Element
			val, delta := s.Read(inst.Calldata[offset:])
			offset += delta

			// Convert U64 to fr.Element
			bigInt := s.ToBigInt(val)
			b.assignment[wI][instanceIdx].SetBigInt(bigInt)
			inputIdx++
		} else {
			// Get evaluator for this wire from the circuit evaluator
			evaluator := &ce.evaluators[wI]

			// Push gate inputs
			for _, inWI := range w.Inputs {
				evaluator.pushInput(&b.assignment[inWI][instanceIdx])
			}

			// Evaluate the gate
			b.assignment[wI][instanceIdx].Set(evaluator.evaluate())
		}
	}

	// Set output wires for the instruction (convert fr.Element to U64)
	outputIdx := 0
	for _, outWI := range b.OutputWires {
		var bigInt big.Int
		b.assignment[outWI][instanceIdx].BigInt(&bigInt)
		s.SetValue(uint32(outputIdx+int(inst.WireOffset)), s.FromInterface(&bigInt))
		outputIdx++
	}

	b.nbInstances++
	return nil
}

// Reset implements BlueprintStateful
func (b *BlueprintGKRSolve) Reset() {
	b.nbInstances = 0
	b.assignment = nil
}

// CalldataSize implements Blueprint
func (b *BlueprintGKRSolve) CalldataSize() int {
	return -1 // variable size
}

// NbConstraints implements Blueprint
func (b *BlueprintGKRSolve) NbConstraints() int {
	return 0
}

// NbOutputs implements Blueprint
func (b *BlueprintGKRSolve) NbOutputs(inst constraint.Instruction) int {
	return b.NbOutputVars
}

// UpdateInstructionTree implements Blueprint
func (b *BlueprintGKRSolve) UpdateInstructionTree(inst constraint.Instruction, tree constraint.InstructionTree) constraint.Level {
	maxLevel := constraint.LevelUnset

	nbInputsInst := int(inst.Calldata[1])
	offset := 2

	for range nbInputsInst {
		n := int(inst.Calldata[offset])
		offset++

		for range n {
			wireID := inst.Calldata[offset+1]
			offset += 2
			if !tree.HasWire(wireID) {
				continue
			}
			if level := tree.GetWireLevel(wireID); level > maxLevel {
				maxLevel = level
			}
		}
	}

	outputLevel := maxLevel + 1
	for i := range b.NbOutputVars {
		tree.InsertWire(uint32(i+int(inst.WireOffset)), outputLevel)
	}

	return outputLevel
}

// GetAssignment returns the assignment for a specific wire and instance (for debugging)
func (b *BlueprintGKRSolve) GetAssignment(s constraint.Solver[constraint.U64], wireIdx, instanceIdx int) (constraint.U64, error) {
	b.lock.Lock()
	defer b.lock.Unlock()

	var zero constraint.U64
	if wireIdx >= len(b.assignment) || instanceIdx >= len(b.assignment[wireIdx]) {
		return zero, fmt.Errorf("wire %d instance %d out of bounds", wireIdx, instanceIdx)
	}

	// Convert fr.Element to U64
	var bigInt big.Int
	b.assignment[wireIdx][instanceIdx].BigInt(&bigInt)
	return s.FromInterface(&bigInt), nil
}

// GetAssignments returns all assignments for proving
func (b *BlueprintGKRSolve) GetAssignments() WireAssignment {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.assignment
}

// GetNbInstances returns the number of instances solved
func (b *BlueprintGKRSolve) GetNbInstances() int {
	b.lock.Lock()
	defer b.lock.Unlock()
	return b.nbInstances
}

// BlueprintGKRProve is a BN254-specific blueprint for generating GKR proofs.
type BlueprintGKRProve struct {
	SolveBlueprint *BlueprintGKRSolve
	HashName       string

	lock sync.Mutex
}

// Ensures BlueprintGKRProve implements BlueprintSolvable
var _ constraint.BlueprintSolvable[constraint.U64] = (*BlueprintGKRProve)(nil)

// Solve implements the BlueprintSolvable interface for proving.
func (b *BlueprintGKRProve) Solve(s constraint.Solver[constraint.U64], inst constraint.Instruction) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	// Get assignments from solve blueprint (already in fr.Element form)
	assignments := b.SolveBlueprint.GetAssignments()
	if len(assignments) == 0 {
		return fmt.Errorf("no assignments available for proving")
	}

	// Read initial challenges from instruction calldata
	nbChallenges := int(inst.Calldata[2])
	challenges := make([]fr.Element, nbChallenges)
	offset := 3
	for i := range nbChallenges {
		val, delta := s.Read(inst.Calldata[offset:])
		offset += delta

		// Convert U64 to fr.Element
		bigInt := s.ToBigInt(val)
		challenges[i].SetBigInt(bigInt)
	}

	// Convert challenges to [][]byte for Fiat-Shamir
	insBytes := make([][]byte, len(challenges))
	for i := range challenges {
		insBytes[i] = make([]byte, fr.Bytes)
		challenges[i].BigInt((*big.Int)(nil)).FillBytes(insBytes[i])
	}

	// Create Fiat-Shamir settings
	hsh := hash.NewHash(b.HashName + "_BN254")
	fsSettings := fiatshamir.WithHash(hsh, insBytes...)

	// Call the BN254-specific Prove function (assignments already WireAssignment type)
	proof, err := Prove(b.SolveBlueprint.Circuit, assignments, fsSettings)
	if err != nil {
		return fmt.Errorf("bn254 prove failed: %w", err)
	}

	// Serialize proof and convert to U64
	proofSize := 0
	for i := range proof {
		for _, poly := range proof[i].partialSumPolys {
			proofSize += len(poly)
		}
		if proof[i].finalEvalProof != nil {
			proofSize += len(proof[i].finalEvalProof)
		}
	}

	outsBig := make([]*big.Int, proofSize)
	for i := range outsBig {
		outsBig[i] = new(big.Int)
	}
	if err := proof.SerializeToBigInts(outsBig); err != nil {
		return fmt.Errorf("failed to serialize proof: %w", err)
	}

	// Set output wires (convert big.Int to U64)
	for i, bigVal := range outsBig {
		s.SetValue(uint32(i+int(inst.WireOffset)), s.FromInterface(bigVal))
	}

	return nil
}

// CalldataSize implements Blueprint
func (b *BlueprintGKRProve) CalldataSize() int {
	return -1 // variable size
}

// NbConstraints implements Blueprint
func (b *BlueprintGKRProve) NbConstraints() int {
	return 0
}

// NbOutputs implements Blueprint
func (b *BlueprintGKRProve) NbOutputs(inst constraint.Instruction) int {
	if len(inst.Calldata) > 1 {
		return int(inst.Calldata[1])
	}
	return 0
}

// UpdateInstructionTree implements Blueprint
func (b *BlueprintGKRProve) UpdateInstructionTree(inst constraint.Instruction, tree constraint.InstructionTree) constraint.Level {
	maxLevel := constraint.LevelUnset

	if len(inst.Calldata) < 3 {
		return maxLevel + 1
	}

	nbChallenges := int(inst.Calldata[2])
	offset := 3

	for range nbChallenges {
		n := int(inst.Calldata[offset])
		offset++

		for range n {
			wireID := inst.Calldata[offset+1]
			offset += 2
			if !tree.HasWire(wireID) {
				continue
			}
			if level := tree.GetWireLevel(wireID); level > maxLevel {
				maxLevel = level
			}
		}
	}

	outputLevel := maxLevel + 1
	proofSize := int(inst.Calldata[1])
	for i := range proofSize {
		tree.InsertWire(uint32(i+int(inst.WireOffset)), outputLevel)
	}

	return outputLevel
}
