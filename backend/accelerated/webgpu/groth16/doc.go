//go:build js && wasm

// Package groth16 provides an experimental browser/WebGPU-accelerated Groth16
// prover surface for wasm targets.
//
// Scope of the current implementation:
//   - circuit compilation, setup, witness assignment, and solver stay native
//     (no WebGPU offload)
//   - Groth16 heavy MSMs are offloaded through a JS bridge to the browser
//     WebGPU runtime in this repository
//   - BSB22 commitment hint, commitment MSM, and PoK MSM work is wired through
//     the same WebGPU bridge
//
// Curve-specific proving code lives in the bn254, bls12-377, and bls12-381
// subpackages, while this package keeps the curve-switching facade. Host
// applications are expected to install the WebGPU bridge from the TS package
// before invoking Prove so the wasm code can call into the browser runtime
// through `syscall/js`.
package groth16
