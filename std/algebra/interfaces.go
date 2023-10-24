package algebra

import "github.com/consensys/gnark/frontend"

type ScalarT any
type GroupElementT any
type G1ElementT GroupElementT
type G2ElementT GroupElementT
type GtElementT GroupElementT

// Curve defines group operations on an elliptic curve.
type Curve[S ScalarT, G1El G1ElementT] interface {
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
	ScalarMul(*G1El, *S) *G1El

	// ScalarMulBase returns the scalar multiplication of the curve base point
	// by a scalar. It does not modify the scalar.
	ScalarMulBase(*S) *G1El

	// MultiScalarMul computes the sum ∑ s_i P_i for the input
	// scalars s_i and points P_i. It returns an error if the input lengths
	// mismatch.
	MultiScalarMul([]*G1El, []*S) (*G1El, error)

	// MarshalG1 Returns the binary decomposition G1.X || G1.Y. It matches the
	// output of gnark-crypto's Marshal method on G1 points. The method is useful
	// because the curve struct embeds the base field api.
	// nbBitsPerCoordinate specifies the size of the output slice (one frontend.Variable=1 bit).
	MarshalG1(G1El, int) []frontend.Variable

	// MarshalScalar Returns the binary decomposition of the argument. This method
	// is useful because the curve struct embeds the scalar field api.
	// nbBits specifies the size of the output slice (one frontend.Variable=1 bit).
	MarshalScalar(S, int) []frontend.Variable
}

// Pairing allows to compute the bi-linear pairing of G1 and G2 elements.
// Additionally, the interface provides steps used in pairing computation and a
// dedicated optimised pairing check.
type Pairing[G1El G1ElementT, G2El G2ElementT, GtEl GtElementT] interface {
	// MillerLoop computes the Miller loop of the input pairs. It returns error
	// when the inputs are of mismatching length. It does not modify the inputs.
	MillerLoop([]*G1El, []*G2El) (*GtEl, error)

	// FinalExponentiation computes the final step in the pairing. It does not
	// modify the inputs.
	FinalExponentiation(*GtEl) *GtEl

	// Pair computes the full pairing of the input pairs. It returns error when
	// the inputs are of mismatching length. It does not modify the inputs.
	Pair([]*G1El, []*G2El) (*GtEl, error)

	// PairingCheck asserts that the pairing result is 1. It returns an error
	// when the inputs are of mismatching length. It does not modify the inputs.
	PairingCheck([]*G1El, []*G2El) error

	// AssertIsEqual asserts the equality of the inputs.
	AssertIsEqual(*GtEl, *GtEl)
}
