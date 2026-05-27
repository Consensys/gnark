package snarkjs

import (
	"io"
)

// VerifyingKey is the interface for verifying keys in the SnarkJS backend.
type Proof interface {
	ExportProof([]string, io.Writer) error
}
