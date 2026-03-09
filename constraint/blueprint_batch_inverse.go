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

	// Montgomery batch inversion: one field inversion + O(n) multiplications.
	// We store prefix products in a []E slice and track calldata offsets so
	// we can re-read inputs in the backward pass without a separate []E for
	// inputs. This eliminates the BatchInverse method from the Field interface.
	wireOffset := inst.WireOffset

	// Forward pass: evaluate each input LE, build prefix products, record
	// calldata offsets for the backward pass.
	prefix := make([]E, n) // prefix[i] = product of non-zero inputs before i
	offsets := make([]uint32, n)
	calldataBase := inst.Calldata[2:]
	calldata := calldataBase
	acc := s.One()
	var zero E
	for i := 0; i < n; i++ {
		offsets[i] = uint32(len(calldataBase) - len(calldata))
		val, nRead := s.Read(calldata)
		calldata = calldata[nRead:]
		if val == zero {
			// prefix[i] stays zero (sentinel for zero input)
			continue
		}
		prefix[i] = acc
		acc = s.Mul(acc, val)
	}

	// Invert the accumulated product.
	invAcc, _ := s.Inverse(acc)

	// Backward pass: re-read each input, combine with prefix product and
	// running inverse accumulator to produce the final inverse.
	for i := n - 1; i >= 0; i-- {
		if prefix[i] == zero {
			s.SetValue(wireOffset+uint32(i), zero)
			continue
		}
		val, _ := s.Read(calldataBase[offsets[i]:])
		result := s.Mul(prefix[i], invAcc)
		invAcc = s.Mul(invAcc, val)
		s.SetValue(wireOffset+uint32(i), result)
	}
	return nil
}
