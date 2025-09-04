package solidity

import "io"

// VerifyingKey is the interface for verifying keys in the Solidity backend.
type VerifyingKey interface {
	NbPublicWitness() int
	ExportSolidity(io.Writer, ...ExportOption) error
	ExportN3Contract(io.Writer, ...ExportOption) error // export n3 contract
}
