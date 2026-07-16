// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import "fmt"

// BlueprintWireAliases assigns eliminated internal alias wires from their
// canonical representative. It contributes no proof constraints.
type BlueprintWireAliases[E Element] struct{}

func (b BlueprintWireAliases[E]) CalldataSize() int {
	return -1
}

func (b BlueprintWireAliases[E]) NbConstraints() int {
	return 0
}

func (b BlueprintWireAliases[E]) NbOutputs(inst Instruction) int {
	return 0
}

func (b BlueprintWireAliases[E]) UpdateInstructionTree(inst Instruction, tree InstructionTree) Level {
	n := int(inst.Calldata[1])
	maxLevel := LevelUnset
	j := 2
	for i := 0; i < n; i++ {
		dst, src := inst.Calldata[j], inst.Calldata[j+1]
		j += 2
		if tree.HasWire(src) {
			if level := tree.GetWireLevel(src); level > maxLevel {
				maxLevel = level
			}
		}
		if tree.HasWire(dst) {
			if level := tree.GetWireLevel(dst); level > maxLevel {
				maxLevel = level
			}
		}
	}

	aliasLevel := maxLevel + 1
	j = 2
	for i := 0; i < n; i++ {
		dst := inst.Calldata[j]
		j += 2
		if tree.HasWire(dst) && tree.GetWireLevel(dst) == LevelUnset {
			tree.InsertWire(dst, aliasLevel)
		}
	}
	return aliasLevel
}

func (b BlueprintWireAliases[E]) Solve(s Solver[E], inst Instruction) error {
	n := int(inst.Calldata[1])
	j := 2
	for i := 0; i < n; i++ {
		dst, src := inst.Calldata[j], inst.Calldata[j+1]
		j += 2
		if !s.IsSolved(src) {
			return fmt.Errorf("alias source wire %d is not solved", src)
		}
		srcValue := s.GetValue(CoeffIdOne, src)
		if s.IsSolved(dst) {
			if s.GetValue(CoeffIdOne, dst) != srcValue {
				return fmt.Errorf("alias destination wire %d does not match source wire %d", dst, src)
			}
			continue
		}
		s.SetValue(dst, srcValue)
	}
	return nil
}

func compressWireAliases(pairs [][2]uint32, to *[]uint32) {
	nbInputs := 2 + 2*len(pairs)
	*to = append(*to, uint32(nbInputs), uint32(len(pairs)))
	for _, pair := range pairs {
		*to = append(*to, pair[0], pair[1])
	}
}
