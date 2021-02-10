package backend

import (
	"io"

	"github.com/consensys/gurvy"
)

// ConstraintSystem ...
type ConstraintSystem interface {
	io.WriterTo
	io.ReaderFrom

	// GetNbVariables return number of internal, secret and public variables
	GetNbVariables() (internal, secret, public int)
	GetNbConstraints() int
	GetNbCoefficients() int

	CurveID() gurvy.ID
	FrSize() int
}
