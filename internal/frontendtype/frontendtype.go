// Package frontendtype allows to assert frontend type.
package frontendtype

type Type int

const (
	R1CS Type = iota
	SCS
)

// FrontendTyper interface allows to get the frontend type.
// The interfaces should be asserted from the inner builder via the Compiler() method.
//
// It allows to choose the optimal circuit implementation depending on the frontend type.
//
// The user should have a fallback if the interface is not implemented (i.e. test engine).
type FrontendTyper interface {
	// FrontendType returns the frontend type. It allows to choose the optimal circuit
	// implementation depending on the frontend type.
	FrontendType() Type
}
