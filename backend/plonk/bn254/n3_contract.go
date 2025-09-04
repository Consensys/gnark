package plonk

import (
	"errors"
	"github.com/consensys/gnark/backend/solidity"
	"io"
)

func (vk *VerifyingKey) ExportN3Contract(w io.Writer, exportOpts ...solidity.ExportOption) error {
	return errors.New("not implemented")
}
