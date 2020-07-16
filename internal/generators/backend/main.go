package main

import (
	"os"

	"github.com/consensys/gnark/internal/generators/backend/template/generator"
)

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
	bw761 := generator.GenerateData{
		RootPath: "../../../backend/bw761/",
		Curve:    "BW761",
	}
	datas := []generator.GenerateData{bls377, bls381, bn256, bw761}

	for _, d := range datas {
		if err := os.MkdirAll(d.RootPath+"groth16", 0700); err != nil {
			panic(err)
		}
		if err := generator.GenerateGroth16(d); err != nil {
			panic(err)
		}
		d.RootPath = "../../../backend/r1cs/"
		if err := generator.GenerateR1CSConvertor(d); err != nil {
			panic(err)
		}
	}

}
