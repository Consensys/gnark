package constraint

type BlueprintID uint32

// Blueprint enable representing heterogenous constraints or instructions in a constraint system
// in a memory efficient way. Blueprints essentially help the frontend/ to "compress"
// constraints or instructions, and specify for the solving (or zksnark setup) part how to
// "decompress" and optionally "solve" the associated wires.
type Blueprint interface {
	// NbInputs return the number of calldata input this blueprint expects.
	// If this is unknown at compile time, implementation must return -1 and store
	// the actual number of inputs in the first index of the calldata.
	NbInputs() int

	// NbConstraints return the number of constraints this blueprint creates.
	NbConstraints() int
}

// Solver represents the state of a constraint system solver at runtime. Blueprint can interact
// with this object to perform run time logic, solve constraints and assign values in the solution.
type Solver interface {
	Field
	GetValue(cID, vID uint32) Element
	GetCoeff(cID uint32) Element
	SetValue(vID uint32, f Element)
	IsSolved(vID uint32) bool
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

// Compressable represent an object that knows how to encode itself as a []uint32.
type Compressable interface {
	Compress(to *[]uint32)
}

// Decompressable represent an object that knows how to decode itself into a []uint32.
type Decompressable interface {
	Decompress(in []uint32)
}
