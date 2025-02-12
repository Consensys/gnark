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
	compileDecompressionCircuit(800 * 1024)
	compileDecompressionCircuit(700 * 1024)
}

func compileDecompressionCircuit(decompressedSize int) {
	var nameWithUnit string
	{
		nameWithUnit = "K"
		size := decompressedSize / 1024
		if size >= 1024 {
			nameWithUnit = "M"
			size /= 1024
		}
		nameWithUnit = fmt.Sprintf("%d%s", size, nameWithUnit)
	}

	p := profile.Start(profile.WithPath(nameWithUnit + ".pprof"))
	const compressedSize = 125 * 1024
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &decompressionCircuit{
		Dict:                make([]frontend.Variable, 128*1024),
		Compressed:          make([]frontend.Variable, compressedSize),
		MaxCompressionRatio: float32(decompressedSize) / compressedSize,
	}, frontend.WithCapacity(100000000))
	if err != nil {
		panic(err)
	}
	p.Stop()
	fmt.Println(nameWithUnit, ":", cs.GetNbConstraints(), "constraints")
}

type decompressionCircuit struct {
	Dict, Compressed    []frontend.Variable
	CompressedLen       frontend.Variable
	MaxCompressionRatio float32
}

func (c *decompressionCircuit) Define(api frontend.API) error {
	d := make([]frontend.Variable, int(float32(len(c.Compressed))*c.MaxCompressionRatio))
	fmt.Println("decompressed length", len(d), "bytes")
	_, err := lzss.Decompress(api, c.Compressed, c.CompressedLen, d, c.Dict)
	return err
}
