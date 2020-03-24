package main

import (
	"os"

	"github.com/consensys/gnark/internal/generators/backend/template/generator"
)

// TODO should not be there. Need to factorize code genration boilerplate used in goff, ecc and here
//go:generate go run -tags debug main.go
func main() {

	generic := generator.GenerateData{
		RootPath: "../../../backend/",
		Curve:    "GENERIC",
	}
	bls377 := generator.GenerateData{
		RootPath: "../../../backend/static/bls377/",
		Curve:    "BLS377",
	}
	bls381 := generator.GenerateData{
		RootPath: "../../../backend/static/bls381/",
		Curve:    "BLS381",
	}
	bn256 := generator.GenerateData{
		RootPath: "../../../backend/static/bn256/",
		Curve:    "BN256",
	}
	datas := []generator.GenerateData{generic, bls377, bls381, bn256}

	for _, d := range datas {
		if err := os.MkdirAll(d.RootPath+"groth16", 0700); err != nil {
			panic(err)
		}
		if err := generator.GenerateGroth16(d); err != nil {
			panic(err)
		}
	}

}
