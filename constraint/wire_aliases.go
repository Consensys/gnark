// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package constraint

import "math"

// ApplyWireAliases rewrites stored proof-relevant wire references through rep
// and rebuilds the instruction tree. It does not remove or renumber wires.
func (system *System) ApplyWireAliases(rep func(uint32) uint32, genericSparseID, aliasID BlueprintID, aliases [][2]uint32) {
	if rep == nil {
		return
	}

	oldInstructions := system.Instructions
	newInstructions := make([]PackedInstruction, 0, len(oldInstructions)+1)
	newCallData := make([]uint32, 0, len(system.CallData))

	for _, blueprint := range system.Blueprints {
		switch b := blueprint.(type) {
		case *BlueprintLookupHint[U64]:
			b.resetLevelCache()
			rewriteLookupHintEntriesCalldata(b.EntriesCalldata, rep)
		case *BlueprintLookupHint[U32]:
			b.resetLevelCache()
			rewriteLookupHintEntriesCalldata(b.EntriesCalldata, rep)
		}
	}

	system.lbWireLevel = make([]Level, system.NbInternalVariables)
	for i := range system.lbWireLevel {
		system.lbWireLevel[i] = LevelUnset
	}
	system.Levels = system.Levels[:0]

	nbConstraints := 0
	for _, pi := range oldInstructions {
		inst := pi.Unpack(system)
		bID := pi.BlueprintID
		blueprint := system.Blueprints[bID]

		start := len(newCallData)
		switch b := blueprint.(type) {
		case BlueprintR1C:
			var c R1C
			b.DecompressR1C(&c, inst)
			rewriteLinearExpression(c.L, rep)
			rewriteLinearExpression(c.R, rep)
			rewriteLinearExpression(c.O, rep)
			b.CompressR1C(&c, &newCallData)

		case BlueprintSparseR1C:
			var c SparseR1C
			b.DecompressSparseR1C(&c, inst)
			rewriteSparseR1C(&c, rep)
			if system.Type == SystemSparseR1CS && shouldUseGenericSparse(system, blueprint, genericSparseID, c) {
				bID = genericSparseID
				b = system.Blueprints[bID].(BlueprintSparseR1C)
			}
			b.CompressSparseR1C(&c, &newCallData)

		case BlueprintHint:
			var h HintMapping
			b.DecompressHint(&h, inst)
			for _, input := range h.Inputs {
				rewriteLinearExpression(input, rep)
			}
			b.CompressHint(h, &newCallData)

		case *BlueprintBatchInverse[U64], *BlueprintBatchInverse[U32]:
			newCallData = append(newCallData, inst.Calldata...)
			rewriteBatchInverseCalldata(newCallData[start:], rep)

		case *BlueprintLookupHint[U64]:
			newCallData = append(newCallData, inst.Calldata...)
			rewriteLookupHintCalldata(newCallData[start:], rep)

		case *BlueprintLookupHint[U32]:
			newCallData = append(newCallData, inst.Calldata...)
			rewriteLookupHintCalldata(newCallData[start:], rep)

		default:
			newCallData = append(newCallData, inst.Calldata...)
		}

		pi.BlueprintID = bID
		pi.StartCallData = uint64(start)
		pi.ConstraintOffset = uint32(nbConstraints)
		nbConstraints += system.Blueprints[bID].NbConstraints()
		newInstructions = append(newInstructions, pi)

		treeInst := Instruction{
			ConstraintOffset: pi.ConstraintOffset,
			WireOffset:       pi.WireOffset,
			Calldata:         newCallData[start:],
		}
		level := system.Blueprints[bID].UpdateInstructionTree(treeInst, system)
		system.appendInstructionToLevel(uint32(len(newInstructions)-1), level)
	}

	if len(aliases) > 0 {
		start := len(newCallData)
		compressWireAliases(aliases, &newCallData)
		pi := PackedInstruction{
			BlueprintID:      aliasID,
			ConstraintOffset: uint32(nbConstraints),
			WireOffset:       uint32(system.NbInternalVariables + system.GetNbPublicVariables() + system.GetNbSecretVariables()),
			StartCallData:    uint64(start),
		}
		newInstructions = append(newInstructions, pi)
		treeInst := Instruction{
			ConstraintOffset: pi.ConstraintOffset,
			WireOffset:       pi.WireOffset,
			Calldata:         newCallData[start:],
		}
		level := system.Blueprints[aliasID].UpdateInstructionTree(treeInst, system)
		system.appendInstructionToLevel(uint32(len(newInstructions)-1), level)
	}

	system.Instructions = newInstructions
	system.CallData = newCallData
	system.NbConstraints = nbConstraints
}

func rewriteLinearExpression(l LinearExpression, rep func(uint32) uint32) {
	for i := range l {
		if !l[i].IsConstant() {
			l[i].VID = rep(l[i].VID)
		}
	}
}

func rewriteSparseR1C(c *SparseR1C, rep func(uint32) uint32) {
	if c.QL != CoeffIdZero || c.QM != CoeffIdZero {
		c.XA = rep(c.XA)
	}
	if c.QR != CoeffIdZero || c.QM != CoeffIdZero {
		c.XB = rep(c.XB)
	}
	if c.QO != CoeffIdZero {
		c.XC = rep(c.XC)
	}
}

func rewriteBatchInverseCalldata(calldata []uint32, rep func(uint32) uint32) {
	n := int(calldata[1])
	j := 2
	for i := 0; i < n; i++ {
		j = rewriteLinearExpressionCalldata(calldata, j, rep)
	}
}

func rewriteLookupHintEntriesCalldata(calldata []uint32, rep func(uint32) uint32) {
	for j := 0; j < len(calldata); {
		j = rewriteLinearExpressionCalldata(calldata, j, rep)
	}
}

func rewriteLookupHintCalldata(calldata []uint32, rep func(uint32) uint32) {
	nbInputs := int(calldata[2])
	j := 3
	for i := 0; i < nbInputs; i++ {
		j = rewriteLinearExpressionCalldata(calldata, j, rep)
	}
}

func rewriteLinearExpressionCalldata(calldata []uint32, j int, rep func(uint32) uint32) int {
	n := int(calldata[j])
	j++
	for k := 0; k < n; k++ {
		j++ // coeff ID
		if calldata[j] != math.MaxUint32 {
			calldata[j] = rep(calldata[j])
		}
		j++
	}
	return j
}

func shouldUseGenericSparse(system *System, blueprint Blueprint, genericSparseID BlueprintID, c SparseR1C) bool {
	if genericSparseID == blueprintIDInvalid || genericSparseID >= BlueprintID(len(system.Blueprints)) {
		return false
	}
	if !isSparseAssignmentBlueprint(blueprint) {
		return false
	}
	if !system.HasWire(c.XC) {
		return true
	}
	return system.GetWireLevel(c.XC) != LevelUnset
}

func isSparseAssignmentBlueprint(blueprint Blueprint) bool {
	switch blueprint.(type) {
	case *BlueprintSparseR1CAdd[U64], *BlueprintSparseR1CAdd[U32],
		*BlueprintSparseR1CMul[U64], *BlueprintSparseR1CMul[U32]:
		return true
	default:
		return false
	}
}

func (system *System) appendInstructionToLevel(iID uint32, level Level) {
	if level < 0 {
		level = 0
	}
	if int(level) >= len(system.Levels) {
		system.Levels = append(system.Levels, []uint32{iID})
		return
	}
	system.Levels[level] = append(system.Levels[level], iID)
}

const blueprintIDInvalid BlueprintID = ^BlueprintID(0)
