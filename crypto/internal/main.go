package main

import (
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/consensys/bavard"
)

//go:generate go run main.go eddsa_template.go eddsa_test_template.go mimc_template.go
func main() {

	// -----------------------------------------------------
	// eddsa files
	eddsabls381 := templateData{
		Curve:    "BLS381",
		Path:     "../signature/eddsa/bls381/",
		FileName: "eddsa.go",
		Src:      []string{eddsaTemplate},
		Package:  "eddsa",
	}
	eddsabls381Test := templateData{
		Curve:    "BLS381",
		Path:     "../signature/eddsa/bls381/",
		FileName: "eddsa_test.go",
		Src:      []string{eddsaTestTemplate},
		Package:  "eddsa",
	}

	eddsabn256 := templateData{
		Curve:    "BN256",
		Path:     "../signature/eddsa/bn256/",
		FileName: "eddsa.go",
		Src:      []string{eddsaTemplate},
		Package:  "eddsa",
	}
	eddsabn256Test := templateData{
		Curve:    "BN256",
		Path:     "../signature/eddsa/bn256/",
		FileName: "eddsa_test.go",
		Src:      []string{eddsaTestTemplate},
		Package:  "eddsa",
	}

	// -----------------------------------------------------
	// mimc files
	mimcbn256 := templateData{
		Curve:    "BN256",
		Path:     "../hash/mimc/bn256/",
		FileName: "mimc_bn256.go",
		Src:      []string{mimcCommonTemplate, mimcCurveTemplate, mimcEncryptTemplate},
		Package:  "bn256",
	}

	mimcbls381 := templateData{
		Curve:    "BLS381",
		Path:     "../hash/mimc/bls381/",
		FileName: "mimc_bls381.go",
		Src:      []string{mimcCommonTemplate, mimcCurveTemplate, mimcEncryptTemplate},
		Package:  "bls381",
	}

	mimcbls377 := templateData{
		Curve:    "BLS377",
		Path:     "../hash/mimc/bls377/",
		FileName: "mimc_bls377.go",
		Src:      []string{mimcCommonTemplate, mimcCurveTemplate, mimcEncryptTemplate},
		Package:  "bls377",
	}

	data := []templateData{
		eddsabls381,
		eddsabls381Test,
		eddsabn256,
		eddsabn256Test,
		mimcbn256,
		mimcbls381,
		mimcbls377,
	}

	var wg sync.WaitGroup
	for _, d := range data {
		wg.Add(1)
		go func(d templateData) {
			defer wg.Done()
			if err := os.MkdirAll(d.Path, 0700); err != nil {
				panic(err)
			}
			if err := generate(d); err != nil {
				panic(err)
			}
		}(d)
	}
	wg.Wait()

	// run go fmt on whole directory
	cmd := exec.Command("gofmt", "-s", "-w", "../")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}
}

// templateData meta data for template generation
type templateData struct {
	Curve    string
	Path     string
	FileName string
	Src      []string
	Package  string
}

const copyrightHolder = "ConsenSys Software Inc."

// generate template generator
func generate(d templateData) error {

	if !strings.HasSuffix(d.Path, "/") {
		d.Path += "/"
	}

	if err := bavard.Generate(d.Path+d.FileName, d.Src, d,
		bavard.Package(d.Package),
		bavard.Apache2(copyrightHolder, 2020),
		bavard.GeneratedBy("gnark"),
		bavard.Format(false),
		bavard.Import(false),
	); err != nil {
		return err
	}

	return nil
}
