//go:build cuda

// Package p2 is the device-resident ("plonk2-style") orchestration layer for the
// BLS12-381 PLONK prover. It keeps field polynomials resident on the GPU as
// FrVector handles and drives the prove phases over the existing icicle shim,
// modeled on Linea gpu/plonk2 + wnark backend/accelerated/webgpu. See
// gnark-cuda/docs/RESIDENT_PROVER_PLAN.md.
package p2

// Enabled reports whether the device-resident path is compiled in.
const Enabled = true
