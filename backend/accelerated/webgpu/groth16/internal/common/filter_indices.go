//go:build js && wasm

package common

import "github.com/consensys/gnark/constraint"

func ComputeKeptIndices(infinity []bool) []int {
	if len(infinity) == 0 {
		return nil
	}
	count := 0
	for _, isInfinity := range infinity {
		if !isInfinity {
			count++
		}
	}
	indices := make([]int, 0, count)
	for i, isInfinity := range infinity {
		if !isInfinity {
			indices = append(indices, i)
		}
	}
	return indices
}

func CommitmentWireIndexesToRemove(commitmentInfo constraint.Groth16Commitments) []int {
	if len(commitmentInfo) == 0 {
		return nil
	}
	count := len(commitmentInfo)
	privateCommitted := commitmentInfo.GetPrivateCommitted()
	for _, indexes := range privateCommitted {
		count += len(indexes)
	}
	out := make([]int, 0, count)
	for _, indexes := range privateCommitted {
		out = append(out, indexes...)
	}
	out = append(out, commitmentInfo.CommitmentIndexes()...)
	return out
}
