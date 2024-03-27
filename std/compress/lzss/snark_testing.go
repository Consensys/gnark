package lzss

import (
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
)

type DecompressionTestCircuit struct {
	C                []frontend.Variable
	D                []frontend.Variable
	Dict             []byte
	CBegin           frontend.Variable
	CLength          frontend.Variable
	DLength          frontend.Variable
	CheckCorrectness bool
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dict := test_vector_utils.ToVariableSlice(lzss.AugmentDict(c.Dict))
	dBack := make([]frontend.Variable, len(c.D)) // TODO Try smaller constants
	if cb, ok := c.CBegin.(int); !ok || cb != 0 {
		c.C = compress.ShiftLeft(api, c.C, c.CBegin)
	}
	dLen, err := Decompress(api, c.C, c.CLength, dBack, dict)
	if err != nil {
		return err
	}
	if c.CheckCorrectness {
		api.AssertIsEqual(c.DLength, dLen)
		for i := range c.D {
			api.AssertIsEqual(c.D[i], dBack[i])
		}
	}
	return nil
}
