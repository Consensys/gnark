package backend

import (
	"io"

	"github.com/consensys/gurvy"
)

type ConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom
	GetNbConstraints() uint64
	GetNbWires() uint64
	GetNbPublicWires() uint64
	GetNbSecretWires() uint64
	SizeFrElement() int
	GetNbCoefficients() int
	GetCurveID() gurvy.ID
}
