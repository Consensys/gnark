package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress/lzss"
)

func main() {
	p := profile.Start()
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &decompressionCircuit{
		Dict:                make([]frontend.Variable, 128*1024),
		Compressed:          make([]frontend.Variable, 125*1024),
		MaxCompressionRatio: 8,
	})
	if err != nil {
		panic(err)
	}
	p.Stop()
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

type decompressionCircuit struct {
	Dict, Compressed    []frontend.Variable
	CompressedLen       frontend.Variable
	MaxCompressionRatio int
}

func (c *decompressionCircuit) Define(api frontend.API) error {
	d := make([]frontend.Variable, len(c.Compressed)*c.MaxCompressionRatio)
	_, err := lzss.Decompress(api, c.Compressed, c.CompressedLen, d, c.Dict)
	return err
}
