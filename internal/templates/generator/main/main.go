package main

import (
	"github.com/consensys/gnark/internal/templates/generator"
)

// TODO should not be there. Need to factorize code genration boilerplate used in goff, ecc and here
//go:generate go run -tags debug main.go
func main() {
	generic := generator.GenerateData{
		"../../../../backend/",
		"GENERIC",
	}
	// bls377 := tData{
	// 	"../../../../backend/bls377/",
	// 	"BLS377",
	// }
	// bls381 := tData{
	// 	"../../../../backend/bls381/",
	// 	"BLS381",
	// }
	// bn256 := tData{
	// 	"../../../../backend/bn256/",
	// 	"BN256",
	// }
	datas := []generator.GenerateData{generic} //, bls377, bls381, bn256}

	for _, d := range datas {
		generator.GenerateGroth16(d)
	}

}
