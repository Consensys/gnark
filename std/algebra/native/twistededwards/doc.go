// Package twistededwards implements the arithmetic of twisted Edwards curves
// in native fields. This uses associated twisted Edwards curves defined over
// the scalar field of the SNARK curves.
//
// The affine formulas in this package are intended for inputs that satisfy the
// twisted Edwards curve equation. The APIs do not implicitly re-check curve
// membership; callers can enforce it with [Curve.AssertIsOnCurve] when needed.
// For on-curve points, [Curve.ScalarMul] is complete for all scalar inputs,
// including zero.
//
// Examples:
// Jubjub, Bandersnatch (a twisted Edwards) is defined over BLS12-381's scalar field
// Baby-Jubjub (a twisted Edwards) is defined over BN254's scalar field
package twistededwards
