package constraint

type Blueprint interface {
	// NbInputs return the number of calldata input this blueprint expects.
	// If this is unknown at compile time, implementation must return -1 and store
	// the actual number of inputs in the first index of the calldata.
	NbInputs() int

	// NbConstraints return the number of constraints this blueprint creates. For a hint, that's 0.
	NbConstraints() int

	// // Wires fills the wires that appear in the instantiation of this blueprint.
	// Wires(calldata []uint32, wires *[]uint32)
}

// BlueprintSolvable represents a blueprint that knows how to solve itself.
type BlueprintSolvable interface {
	// Solve may return an error if the decoded constraint / calldata is unsolvable.
	Solve(s Solver, calldata []uint32) error
}

// BlueprintR1C indicates that the blueprint and associated calldata encodes a R1C
type BlueprintR1C interface {
	CompressR1C(c *R1C) []uint32
	DecompressR1C(into *R1C, calldata []uint32)
}

// BlueprintSparseR1C indicates that the blueprint and associated calldata encodes a SparseR1C.
type BlueprintSparseR1C interface {
	CompressSparseR1C(c *SparseR1C) []uint32
	DecompressSparseR1C(into *SparseR1C, calldata []uint32)
}

// BlueprintHint indicates that the blueprint and associated calldata encodes a hint.
type BlueprintHint interface {
	CompressHint(HintMapping) []uint32
	DecompressHint(h *HintMapping, calldata []uint32)
}

type BlueprintSparseR1CBlock interface {
	CompressBlock()
	DecompressBlock() []SparseR1C
}
