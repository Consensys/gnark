// Package maptocurve_grumpkin implements the y-increment map-to-curve gadget
// for the Grumpkin curve y² = x³ - 17 over its base field (= BN254 scalar field).
// Circuits compile over ecc.BN254.
//
// Only the y-increment method is provided. The x-increment method is not practical
// for Grumpkin because its high 2-adicity (S=28) makes the inverse-exclusion
// witness search infeasible.
package maptocurve_grumpkin
