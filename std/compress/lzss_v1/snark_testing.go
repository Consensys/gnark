package lzss_v1

import (
	"github.com/consensys/gnark/frontend"
)

type DecompressionTestCircuit struct {
	CPacked          []frontend.Variable
	D                []byte
	CLength          frontend.Variable
	Settings         Settings
	CheckCorrectness bool
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)) // TODO Try smaller constants
	api.Println("maxLen(dBack)", len(dBack))
	cUnpacked, err := Unpack(api, c.CPacked, c.Settings)
	if err != nil {
		return err
	}
	dLen, err := Decompress(api, cUnpacked, dBack, c.CLength, c.Settings)
	if err != nil {
		return err
	}
	if c.CheckCorrectness {
		api.Println("got len", dLen, "expected", len(c.D))
		api.AssertIsEqual(len(c.D), dLen)
		for i := range c.D {
			api.Println("decompressed at", i, "->", dBack[i], "expected", c.D[i], "dBack", dBack[i])
			api.AssertIsEqual(c.D[i], dBack[i])
		}
	}
	return nil
}
