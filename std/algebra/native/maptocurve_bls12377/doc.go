// Package maptocurve_bls12377 implements the y-increment map-to-curve gadget
// for the BLS12-377 curve y² = x³ + 1 over its base field (= BW6-761 scalar field).
// Circuits compile over ecc.BW6_761.
//
// Only the y-increment method is provided. The x-increment method is not practical
// for BLS12-377 because its high 2-adicity (S=46) makes the inverse-exclusion
// witness search infeasible.
package maptocurve_bls12377
