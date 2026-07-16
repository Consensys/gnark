package snarkjs

import "io"

// VerifyingKey is the interface for verifying keys in the SnarkJS backend.
type VerifyingKey interface {
	ExportVerifyingKey(io.Writer) error
}
