package emulated

// polyProdCheck represents a polynomial product check in a polynomial
// Represents an element of a polynomial ring over the emulated field.
type Poly[T FieldParams] []*Element[T]

// polyRingMulCheck represents a polynomial product check in a polynomial
// ring. Instead of computing the product and reducing it where called,
// we compute the result using a hint and return it. Result is stored for
// correctness check later to share the verifier challenge computation.
//
// We store the values poly, irr, r, q. They are as follows:
//   - poly - the input polynomials whose product we are checking. Each
//     polynomial is represented as a slice of [Element] coefficients. Elements
//     have to be reduced.
//   - irr - the irreducible polynomial defining the ring, i.e. the modulus for
//     the Euclidean division. Treated as a constant.
//   - r - the product reduced modulo irr, i.e. the remainder. This is the
//     result returned to the caller.
//   - q - the quotient of the product divided by irr.
//
// Given these values, the following holds as an identity of polynomials over
// the emulated field:
//
//	∏_i inputs_i = r + q * mod
//
// For asserting that the previous identity holds, we evaluate both sides at a
// single random challenge point α obtained via commitment to all coefficients.
// If a polynomial f has coefficient elements (f_0, ..., f_n), its evaluation is
//
//	f(α) = ∑_i f_i(α) * α^i,
//
// where each f_i(α) is itself the Schwartz-Zippel evaluation of the limb
// polynomial of the emulated element f_i. The product check then becomes
//
//	∏_i inputs_i(α) = r(α) + q(α) * mod(α),
//
// which can be verified at a single random point.
type polyRingMulCheck[T FieldParams] struct {
	f *Field[T]
	// ∏_i inputs_i = r + q * mod
	inputs []Poly[T] // input polynomials
	mod    Poly[T]   // irreducible polynomial defining the ring
	r      Poly[T]   // remainder
	q      Poly[T]   // quotient
}

