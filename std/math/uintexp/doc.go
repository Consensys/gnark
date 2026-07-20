// Package uintexp implements wrapping u8/u16 arithmetic "in the exponent".
//
// An integer a ∈ [0, 2^k) is encoded as the field element ω^a, where ω is a
// fixed element of multiplicative order 2^k in the native field. The encoding
// is a group isomorphism (Z/2^k, +) ≅ ⟨ω⟩, so a wrapping addition is a single
// field multiplication and the reduction modulo 2^k is free: it is the order
// of the group. This requires the multiplicative group of the native field to
// have 2-adicity at least k, i.e. 2^k | q-1:
//
//	field       | v2(q-1) | u8 | u16
//	------------|---------|----|----
//	KoalaBear   | 24      | ✓  | ✓
//	BabyBear    | 27      | ✓  | ✓
//	BN254 fr    | 28      | ✓  | ✓
//	BLS12-377 fr| 47      | ✓  | ✓
//	BLS12-381 fr| 32      | ✓  | ✓
//	tinyfield   | 1       | ✗  | ✗
//
// [New] returns an error when the 2-adicity is insufficient. The generator ω
// is derived deterministically from the field modulus.
//
// # Costs (R1CS constraints)
//
//	operation           | cost
//	--------------------|--------------------------
//	Add (n inputs)      | n-1
//	AddConstant         | 0 (folds into the LC)
//	Neg / Sub           | 1 / 2
//	Lsh by c            | c (squarings)
//	Select              | 1
//	ValueOf (encode)    | ≈2k (k booleanity + k muls)
//	Value (decode)      | ≈2k (hint + re-encode)
//
// The package pays for conversions at the boundaries and wins inside: it is
// intended for accumulator- and counter-shaped state (running sums, indices,
// lengths) that lives through many dependent additions. For bitwise
// operations (XOR/AND/OR), comparisons, or wide multiplication use
// [github.com/consensys/gnark/std/math/uints] and convert at the boundary
// with [Field.Value] / [Field.ValueOf]. Note also that n-ary additions in
// uints amortize their carry handling, so for a one-shot sum of many values
// uints may be cheaper; the win here is for chains of dependent additions and
// for constant increments.
//
// # Soundness
//
// Values produced by the package are in ⟨ω⟩ by closure. A [Uint] arriving as
// a raw witness is constrained on first use by decoding it with a hint and
// re-encoding the range-checked exponent, which proves both subgroup
// membership and well-formedness. Assign witness values with [Encode].
//
// # Future work
//
// A parity read (LSB of an encoded value) is possible via a witnessed square
// root, but a sound version at width k < v2(q-1) requires k additional
// squarings to pin the witness to the order-2^k subgroup; it is omitted for
// now. Bit decomposition should go through [Field.Value].
//
// NB! The package is experimental and the API may change.
package uintexp
