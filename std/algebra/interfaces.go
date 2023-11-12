package algebra

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type LinesT any
type GroupElementT any
type G1ElementT GroupElementT
type G2ElementT GroupElementT
type GtElementT GroupElementT

// Curve defines group operations on an elliptic curve.
type Curve[FR emulated.FieldParams, G1El G1ElementT] interface {
	// Add adds two points and returns the sum. It does not modify the input
	// points.
	Add(*G1El, *G1El) *G1El

	// AssertIsEqual asserts that two points are equal.
	AssertIsEqual(*G1El, *G1El)

	// Neg negates the points and returns a negated point. It does not modify
	// the input.
	Neg(*G1El) *G1El

	// ScalarMul returns the scalar multiplication of the point by a scalar. It
	// does not modify the inputs.
	ScalarMul(*G1El, *emulated.Element[FR]) *G1El

	// ScalarMulBase returns the scalar multiplication of the curve base point
	// by a scalar. It does not modify the scalar.
	ScalarMulBase(*emulated.Element[FR]) *G1El

	// MultiScalarMul computes the sum ∑ s_i P_i for the input
	// scalars s_i and points P_i. It returns an error if the input lengths
	// mismatch.
	MultiScalarMul([]*G1El, []*emulated.Element[FR]) (*G1El, error)

	// MarshalG1 returns the binary decomposition G1.X || G1.Y. It matches the
	// output of gnark-crypto's Marshal method on G1 points.
	MarshalG1(G1El) []frontend.Variable

	// MarshalScalar returns the binary decomposition of the argument.
	MarshalScalar(emulated.Element[FR]) []frontend.Variable
}

// Pairing allows to compute the bi-linear pairing of G1 and G2 elements.
// Additionally, the interface provides steps used in pairing computation and a
// dedicated optimised pairing check.
type Pairing[G1El G1ElementT, G2El G2ElementT, GtEl GtElementT, L LinesT] interface {
	// MillerLoop computes the Miller loop of the input pairs. It returns error
	// when the inputs are of mismatching length. It does not modify the inputs.
	MillerLoop([]*G1El, []*G2El) (*GtEl, error)

	// MillerLoopFixedQ is the same as MillerLoop but with fixed G2 arguments.
	MillerLoopFixedQ([]*G1El, []*[2]L) (*GtEl, error)

	// FinalExponentiation computes the final step in the pairing. It does not
	// modify the inputs.
	FinalExponentiation(*GtEl, ...*GtEl) *GtEl

	// Pair computes the full pairing of the input pairs. It returns error when
	// the inputs are of mismatching length. It does not modify the inputs.
	Pair([]*G1El, []*G2El) (*GtEl, error)

	// PairFixedQ is the same as Pair but with fixed G2 arguments.
	PairFixedQ([]*G1El, []*[2]L) (*GtEl, error)

	// PairingCheck asserts that the pairing result is 1. It returns an error
	// when the inputs are of mismatching length. It does not modify the inputs.
	PairingCheck([]*G1El, []*G2El) error

	// PairingFixedQCheck is the same as PairingCheck but with fixed G2 arguments.
	PairingFixedQCheck([]*G1El, []*[2]L) error

	// AssertIsEqual asserts the equality of the inputs.
	AssertIsEqual(*GtEl, *GtEl)
}
