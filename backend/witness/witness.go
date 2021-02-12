package witness

import (
	"io"

	witness_bls377 "github.com/consensys/gnark/internal/backend/bls377/witness"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls381/witness"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn256/witness"
	witness_bw761 "github.com/consensys/gnark/internal/backend/bw761/witness"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gurvy"
)

// Witness represents a witness ([]fr.Element)
//
// it's underlying implementation is curve specific (see gnark/internal/witness)
type Witness interface {
	io.WriterTo
	io.ReaderFrom
	FromFullAssignment(frontend.Circuit) error
	FromPublicAssignment(frontend.Circuit) error
}

// New instantiates a curve-typed Witness and returns an interface
// This function exists for serialization purposes
func New(curveID gurvy.ID) Witness {
	var witness Witness
	switch curveID {
	case gurvy.BN256:
		witness = &witness_bn256.Witness{}
	case gurvy.BLS377:
		witness = &witness_bls377.Witness{}
	case gurvy.BLS381:
		witness = &witness_bls381.Witness{}
	case gurvy.BW761:
		witness = &witness_bw761.Witness{}
	default:
		panic("not implemented")
	}
	return witness
}
