package constraint

// BlueprintBatchInverse implements [Blueprint] and [BlueprintSolvable].
// It solves n modular inversions in a single batch using the standard
// Montgomery prefix-product trick: one field inversion + O(n) multiplications.
//
// Calldata layout (variable-length linear expressions per input):
//
//	[totalSize, n, nTerms_0, cID_{0,0}, vID_{0,0}, …, nTerms_1, cID_{1,0}, vID_{1,0}, …, …]
//
// Each input i is a linear expression of nTerms_i terms (pairs of coeffID, wireID).
// Output wires: inst.WireOffset + 0..n-1
type BlueprintBatchInverse[E Element] struct{}

func (b *BlueprintBatchInverse[E]) CalldataSize() int {
	return -1
}

func (b *BlueprintBatchInverse[E]) NbConstraints() int {
	return 0
}

func (b *BlueprintBatchInverse[E]) NbOutputs(inst Instruction) int {
	return int(inst.Calldata[1])
}

func (b *BlueprintBatchInverse[E]) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	n := int(inst.Calldata[1])
	maxLevel := LevelUnset
	j := 2
	for i := 0; i < n; i++ {
		nTerms := int(inst.Calldata[j])
		j++
		for k := 0; k < nTerms; k++ {
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

	// Read input values: each input is a linear expression evaluated by s.Read.
	inputs := make([]E, n)
	calldata := inst.Calldata[2:]
	for i := 0; i < n; i++ {
		var nRead int
		inputs[i], nRead = s.Read(calldata)
		calldata = calldata[nRead:]
	}

	// Native batch inversion: modifies inputs in place (zero inputs become zero).
	s.BatchInverse(inputs)

	for i := 0; i < n; i++ {
		s.SetValue(inst.WireOffset+uint32(i), inputs[i])
	}
	return nil
}
