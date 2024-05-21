package algebra

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/algopts"
	"github.com/consensys/gnark/std/math/emulated"
)

type GroupElementT any
type G1ElementT GroupElementT
type G2ElementT GroupElementT
type GtElementT GroupElementT

// Curve defines group operations on an elliptic curve.
type Curve[FR emulated.FieldParams, G1El G1ElementT] interface {
	// AddUnified adds _any_ two points and returns the sum. It does not modify the input
	// points.
	AddUnified(*G1El, *G1El) *G1El

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
	//
	// Depending on the implementation the scalar multiplication may be
	// incomplete for zero scalar or point at infinity. To allow the exceptional
	// case use the [algopts.WithCompleteArithmetic] option.
	ScalarMul(*G1El, *emulated.Element[FR], ...algopts.AlgebraOption) *G1El

	// ScalarMulBase returns the scalar multiplication of the curve base point
	// by a scalar. It does not modify the scalar.
	//
	// Depending on the implementation the scalar multiplication may be
	// incomplete for zero scalar. To allow the exceptional case use the
	// [algopts.WithCompleteArithmetic] option.
	ScalarMulBase(*emulated.Element[FR], ...algopts.AlgebraOption) *G1El

	// MultiScalarMul computes the sum ∑ s_i P_i for the input
	// scalars s_i and points P_i. It returns an error if the input lengths
	// mismatch.
	//
	// Depending on the implementation the scalar multiplication may be
	// incomplete for zero scalar or point at infinity. To allow the exceptional
	// case use the [algopts.WithCompleteArithmetic] option.
	MultiScalarMul([]*G1El, []*emulated.Element[FR], ...algopts.AlgebraOption) (*G1El, error)

	// MarshalG1 returns the binary decomposition G1.X || G1.Y. It matches the
	// output of gnark-crypto's Marshal method on G1 points.
	MarshalG1(G1El) []frontend.Variable

	// MarshalScalar returns the binary decomposition of the argument.
	MarshalScalar(emulated.Element[FR]) []frontend.Variable

	// Select sets p1 if b=1, p2 if b=0, and returns it. b must be boolean constrained
	Select(b frontend.Variable, p1 *G1El, p2 *G1El) *G1El

	// Lookup2 performs a 2-bit lookup between p1, p2, p3, p4 based on bits b0  and b1.
	// Returns:
	//   - p1 if b0=0 and b1=0,
	//   - p2 if b0=1 and b1=0,
	//   - p3 if b0=0 and b1=1,
	//   - p4 if b0=1 and b1=1.
	Lookup2(b1 frontend.Variable, b2 frontend.Variable, p1 *G1El, p2 *G1El, p3 *G1El, p4 *G1El) *G1El

	// Mux performs a lookup from the inputs and returns inputs[sel]. It is most
	// efficient for power of two lengths of the inputs, but works for any
	// number of inputs.
	Mux(sel frontend.Variable, inputs ...*G1El) *G1El
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

	// AssertIsOnG1 asserts that the input is on the G1 curve.
	AssertIsOnG1(*G1El)

	// AssertIsOnG2 asserts that the input is on the G2 curve.
	AssertIsOnG2(*G2El)
}
