package main

import (
	"os"

	"github.com/consensys/gnark/cryptolib/internal/generator"
	"github.com/consensys/gnark/cryptolib/internal/template"
)

//go:generate go run -tags debug main.go
func main() {

	// -----------------------------------------------------
	// eddsa files
	eddsabls381 := generator.Data{
		Curve:    "BLS381",
		Path:     "../signature/eddsa/bls381/",
		FileName: "eddsa.go",
		Src:      []string{template.EddsaTemplate},
		Package:  "eddsa",
	}
	eddsabls381Test := generator.Data{
		Curve:    "BLS381",
		Path:     "../signature/eddsa/bls381/",
		FileName: "eddsa_test.go",
		Src:      []string{template.EddsaTest},
		Package:  "eddsa",
	}

	eddsabn256 := generator.Data{
		Curve:    "BN256",
		Path:     "../signature/eddsa/bn256/",
		FileName: "eddsa.go",
		Src:      []string{template.EddsaTemplate},
		Package:  "eddsa",
	}
	eddsabn256Test := generator.Data{
		Curve:    "BN256",
		Path:     "../signature/eddsa/bn256/",
		FileName: "eddsa_test.go",
		Src:      []string{template.EddsaTest},
		Package:  "eddsa",
	}

	// -----------------------------------------------------
	// mimc files
	mimcbn256 := generator.Data{
		Curve:    "BN256",
		Path:     "../hash/mimc/bn256/",
		FileName: "mimc_bn256.go",
		Src:      []string{template.MimcCommon, template.MimcPerCurve, template.Encrypt},
		Package:  "bn256",
	}

	mimcbls381 := generator.Data{
		Curve:    "BLS381",
		Path:     "../hash/mimc/bls381/",
		FileName: "mimc_bls381.go",
		Src:      []string{template.MimcCommon, template.MimcPerCurve, template.Encrypt},
		Package:  "bls381",
	}

	mimcbls377 := generator.Data{
		Curve:    "BLS377",
		Path:     "../hash/mimc/bls377/",
		FileName: "mimc_bls377.go",
		Src:      []string{template.MimcCommon, template.MimcPerCurve, template.Encrypt},
		Package:  "bls377",
	}

	data := []generator.Data{
		eddsabls381,
		eddsabls381Test,
		eddsabn256,
		eddsabn256Test,
		mimcbn256,
		mimcbls381,
		mimcbls377,
	}

	for _, d := range data {
		if err := os.MkdirAll(d.Path, 0700); err != nil {
			panic(err)
		}
		generator.Generate(d)
	}

}
