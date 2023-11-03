package constraint

import (
	"fmt"
)

// TODO @gbotrel this shouldn't be there, but we need to figure out a clean way to serialize
// blueprints

// BlueprintLookupHint is a blueprint that facilitates the lookup of values in a table.
// It is essentially a hint to the solver, but enables storing the table entries only once.
type BlueprintLookupHint struct {
	EntriesCalldata []uint32

	// stores the maxLevel of the entries computed by WireWalker
	maxLevel         Level
	maxLevelPosition int
	maxLevelOffset   int
}

// ensures BlueprintLookupHint implements the BlueprintSolvable interface
var _ BlueprintSolvable = (*BlueprintLookupHint)(nil)

func (b *BlueprintLookupHint) Solve(s Solver, inst Instruction) error {
	nbEntries := int(inst.Calldata[1])
	entries := make([]Element, nbEntries)

	// read the static entries from the blueprint
	// TODO @gbotrel cache that.
	offset, delta := 0, 0
	for i := 0; i < nbEntries; i++ {
		entries[i], delta = s.Read(b.EntriesCalldata[offset:])
		offset += delta
	}

	nbInputs := int(inst.Calldata[2])

	// read the inputs from the instruction
	inputs := make([]Element, nbInputs)
	offset = 3
	for i := 0; i < nbInputs; i++ {
		inputs[i], delta = s.Read(inst.Calldata[offset:])
		offset += delta
	}

	// set the outputs
	nbOutputs := nbInputs

	for i := 0; i < nbOutputs; i++ {
		idx, isUint64 := s.Uint64(inputs[i])
		if !isUint64 || idx >= uint64(len(entries)) {
			return fmt.Errorf("lookup query too large")
		}
		// we set the output wire to the value of the entry
		s.SetValue(uint32(i+int(inst.WireOffset)), entries[idx])
	}
	return nil
}

func (b *BlueprintLookupHint) CalldataSize() int {
	// variable size
	return -1
}
func (b *BlueprintLookupHint) NbConstraints() int {
	return 0
}

// NbOutputs return the number of output wires this blueprint creates.
func (b *BlueprintLookupHint) NbOutputs(inst Instruction) int {
	return int(inst.Calldata[2])
}

func (b *BlueprintLookupHint) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	// depend on the table UP to the number of entries at time of instruction creation.
	nbEntries := int(inst.Calldata[1])

	// check if we already cached the max level
	if b.maxLevelPosition-1 < nbEntries { // adjust for default value of b.maxLevelPosition (0)

		j := b.maxLevelOffset // skip the entries we already processed
		for i := b.maxLevelPosition; i < nbEntries; i++ {
			// first we have the length of the linear expression
			n := int(b.EntriesCalldata[j])
			j++
			for k := 0; k < n; k++ {
				wireID := b.EntriesCalldata[j+1]
				j += 2
				if !tree.HasWire(wireID) {
					continue
				}
				if level := tree.GetWireLevel(wireID); (level + 1) > b.maxLevel {
					b.maxLevel = level + 1
				}
			}
		}
		b.maxLevelOffset = j
		b.maxLevelPosition = nbEntries
	}

	maxLevel := b.maxLevel - 1 // offset for default value.

	// update the max level with the lookup query inputs wires
	nbInputs := int(inst.Calldata[2])
	j := 3
	for i := 0; i < nbInputs; i++ {
		// first we have the length of the linear expression
		n := int(inst.Calldata[j])
		j++
		for k := 0; k < n; k++ {
			wireID := inst.Calldata[j+1]
			j += 2
			if !tree.HasWire(wireID) {
				continue
			}
			if level := tree.GetWireLevel(wireID); level > maxLevel {
				maxLevel = level
			}
		}
	}

	// finally we have the outputs
	maxLevel++
	for i := 0; i < nbInputs; i++ {
		tree.InsertWire(uint32(i+int(inst.WireOffset)), maxLevel)
	}

	return maxLevel
}
