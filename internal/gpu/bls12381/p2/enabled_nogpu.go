//go:build !cuda

// Package p2 is the device-resident orchestration layer. On non-CUDA builds it
// compiles to a single constant so callers can branch without the GPU toolchain.
package p2

// Enabled reports whether the device-resident path is compiled in.
const Enabled = false
