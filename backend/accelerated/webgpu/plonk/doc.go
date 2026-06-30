//go:build js && wasm

// Package plonk provides the browser/WASM entry point for an experimental
// WebGPU-accelerated PLONK prover.
//
// Curve-specific proving code lives in subpackages such as bn254, keeping the
// package root as the browser/WASM dispatcher.
package plonk
