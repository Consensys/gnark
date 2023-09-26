package algebra

// Curve defines group operations on an elliptic curve.
type Curve[Scalar any, GEl any] interface {
	// Add adds two points and returns the sum. It does not modify the input
	// points.
	Add(*GEl, *GEl) *GEl
	// AssertIsEqual asserts that two points are equal.
	AssertIsEqual(*GEl, *GEl)
	// Neg negates the points and returns a negated point. It does not modify
	// the input.
	Neg(*GEl) *GEl
	// ScalarMul returns the scalar multiplication of the point by a scalar. It
	// does not modify the inputs.
	ScalarMul(*GEl, *Scalar) *GEl
	// ScalarMulBase returns the scalar multiplication of the curve base point
	// by a scalar. It does not modify the scalar.
	ScalarMulBase(*Scalar) *GEl
}

// Pairing allows to compute the bi-linear pairing of G1 and G2 elements.
// Additionally, the interface provides steps used in pairing computation and a
// dedicated optimised pairing check.
type Pairing[G1El any, G2El any, GtEl any] interface {
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
}
