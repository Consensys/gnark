package cs

// ID represent a unique ID for a constraint system type
type ID uint16

const (
	UNKNOWN ID = iota
	R1CS       // R1CS used in gnark/backend/groth16
	SCS        // SCS (SparseR1CS) used in gnark/backend/plonk
)
