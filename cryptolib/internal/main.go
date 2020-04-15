package main

import (
	"os"

	"github.com/consensys/gnark/cryptolib/internal/generator"
)

//go:generate go run -tags debug main.go
func main() {

	bls381 := generator.Data{
		Curve: "BLS381",
		Path:  "../signature/eddsa/bls381/",
	}

	bn256 := generator.Data{
		Curve: "BN256",
		Path:  "../signature/eddsa/bn256/",
	}

	data := []generator.Data{bls381, bn256}

	for _, d := range data {
		if err := os.MkdirAll(d.Path, 0700); err != nil {
			panic(err)
		}
		generator.Generate(d)
	}

}
