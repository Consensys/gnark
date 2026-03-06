package constraint

// BlueprintBatchInverse implements [Blueprint] and [BlueprintSolvable].
// It solves n modular inversions in a single batch using the standard
// Montgomery prefix-product trick: one field inversion + O(n) multiplications.
//
// Calldata: [totalSize, n, coeffID_0, wireID_0, ..., coeffID_{n-1}, wireID_{n-1}]
// Output wires: inst.WireOffset + 0..n-1
type BlueprintBatchInverse[E Element] struct{}

func (b *BlueprintBatchInverse[E]) CalldataSize() int {
	// this blueprint does not have a fixed calldata size, it depends on the number of inversions n.
	// the first two uint32 are reserved for totalSize and n, then we have n pairs of (coeffID, wireID).
	// since the blueprint interface requires a fixed size, we return -1 to indicate that the actual size is dynamic.
	// the caller must ensure that the first uint32 of calldata contains the total size, and the second uint32 contains n.
	return -1
}

func (b *BlueprintBatchInverse[E]) NbConstraints() int {
	// this blueprint is a solving blueprint only and does not create
	// constraints/instructions itself due to the dynamic nature of the number
	// of inputs. so, the actual number of added constraints is determined at
	// circuit compile time when we record the instruction calling this
	// blueprint.
	return 0
}

func (b *BlueprintBatchInverse[E]) NbOutputs(inst Instruction) int {
	// the number of output wires is equal to n, which is the second uint32 in calldata.
	return int(inst.Calldata[1])
}

func (b *BlueprintBatchInverse[E]) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	n := int(inst.Calldata[1])
	maxLevel := LevelUnset
	for i := 0; i < n; i++ {
		wireID := inst.Calldata[2+2*i+1]
		if !tree.HasWire(wireID) {
			// input is constant or circuit input (level 0), we can ignore it
			// for level calculation.
			continue
		}
		if level := tree.GetWireLevel(wireID); level > maxLevel {
			maxLevel = level
		}
	}
	outputLevel := maxLevel + 1
	for i := 0; i < n; i++ {
		tree.InsertWire(inst.WireOffset+uint32(i), outputLevel)
	}
	return outputLevel
}

func (b *BlueprintBatchInverse[E]) Solve(s Solver[E], inst Instruction) error {
	n := int(inst.Calldata[1])
	if n == 0 {
		return nil
	}

	// Read input values (coeff * wire for each entry)
	inputs := make([]E, n)
	for i := 0; i < n; i++ {
		inputs[i] = s.GetValue(inst.Calldata[2+2*i], inst.Calldata[2+2*i+1])
	}

	// Native batch inversion: modifies inputs in place (zero inputs become zero).
	s.BatchInverse(inputs)

	for i := 0; i < n; i++ {
		s.SetValue(inst.WireOffset+uint32(i), inputs[i])
	}
	return nil
}
