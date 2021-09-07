package hint

import "hash/fnv"

type ID uint32

// Function represents a function used by the solver to compute value of a hint
// TODO @gbotrel signature of F must match ...
type Function struct {
	ID ID
	F  interface{}
}

// UUID returns a unique ID for a hint function name
func UUID(name string) ID {
	h := fnv.New32a()
	h.Write([]byte(name))
	return ID(h.Sum32())
}

// Reserved UUID that are always injected by the solver
const (
	_ ID = iota
	IsZero
	BinaryDec
)
