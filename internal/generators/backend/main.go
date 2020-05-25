package main

import (
	"os"

	"github.com/consensys/gnark/internal/generators/backend/template/generator"
)

// TODO should not be there. Need to factorize code genration boilerplate used in goff, ecc and here
//go:generate go run -tags debug main.go
func main() {

	bls377 := generator.GenerateData{
		RootPath: "../../../backend/bls377/",
		Curve:    "BLS377",
	}
	bls381 := generator.GenerateData{
		RootPath: "../../../backend/bls381/",
		Curve:    "BLS381",
	}
	bn256 := generator.GenerateData{
		RootPath: "../../../backend/bn256/",
		Curve:    "BN256",
	}
	// bw6 := generator.GenerateData{
	// 	RootPath: "../../../backend/bw6/",
	// 	Curve:    "BW6",
	// }
	datas := []generator.GenerateData{bls377, bls381, bn256} //, bw6}

	for _, d := range datas {
		if err := os.MkdirAll(d.RootPath+"groth16", 0700); err != nil {
			panic(err)
		}
		if err := generator.GenerateGroth16(d); err != nil {
			panic(err)
		}
	}

}
