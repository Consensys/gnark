package lzss_v1

import (
	"github.com/consensys/gnark/frontend"
)

type DecompressionTestCircuit struct {
	C        []frontend.Variable
	D        []byte
	Settings Settings
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)*2) // TODO Try smaller constants
	api.Println("maxLen(dBack)", len(dBack))
	dLen, err := Decompress(api, c.C, dBack, c.Settings)
	if err != nil {
		return err
	}
	api.Println("got len", dLen, "expected", len(c.D))
	api.AssertIsEqual(len(c.D), dLen)
	for i := range c.D {
		api.Println("decompressed at", i, "->", dBack[i], "expected", c.D[i], "dBack", dBack[i])
		api.AssertIsEqual(c.D[i], dBack[i])
	}
	return nil
}
