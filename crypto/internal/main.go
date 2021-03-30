package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
)

var bgen = bavard.NewBatchGenerator(copyrightHolder, "gnark")

const (
	baseDir         = "../"
	copyrightHolder = "ConsenSys Software Inc."
)

// templateData meta data for template generation
type templateData struct {
	Curve    string
	Path     string
	FileName string
	Src      []string
	Package  string
}

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

//go:generate go run main.go mimc_template.go
func main() {

	// mimc files
	mimcbn256 := templateData{
		Curve:    "BN256",
		Path:     "../hash/mimc/bn256/",
		FileName: "mimc_bn256.go",
		Src:      []string{mimcCommonTemplate, mimcEncryptTemplate},
		Package:  "bn256",
	}

	mimcbls381 := templateData{
		Curve:    "BLS381",
		Path:     "../hash/mimc/bls381/",
		FileName: "mimc_bls381.go",
		Src:      []string{mimcCommonTemplate, mimcEncryptTemplate},
		Package:  "bls381",
	}

	mimcbls377 := templateData{
		Curve:    "BLS377",
		Path:     "../hash/mimc/bls377/",
		FileName: "mimc_bls377.go",
		Src:      []string{mimcCommonTemplate, mimcEncryptTemplate},
		Package:  "bls377",
	}

	mimcbw761 := templateData{
		Curve:    "BW761",
		Path:     "../hash/mimc/bw761/",
		FileName: "mimc_bw761.go",
		Src:      []string{mimcCommonTemplate, mimcEncryptTemplate},
		Package:  "bw761",
	}

	data := []templateData{
		mimcbn256,
		mimcbls381,
		mimcbls377,
		mimcbw761,
	}

	var wg sync.WaitGroup
	for _, d := range data {
		wg.Add(1)
		go func(d templateData) {
			defer wg.Done()

			// mimc
			if err := os.MkdirAll(d.Path, 0700); err != nil {
				panic(err)
			}
			if err := generate(d); err != nil {
				panic(err)
			}

			// eddsa
			dir := filepath.Join(baseDir, "signature/eddsa/", d.Package)
			entriesF := []bavard.EntryF{
				{File: filepath.Join(dir, "eddsa.go"), TemplateF: []string{"eddsa.go.tmpl"}},
				{File: filepath.Join(dir, "eddsa_test.go"), TemplateF: []string{"eddsa_test.go.tmpl"}},
				{File: filepath.Join(dir, "marshal.go"), TemplateF: []string{"marshal.go.tmpl"}},
			}
			if err := bgen.GenerateF(d, "eddsa", ".", entriesF...); err != nil {
				panic(err)
			}

			// polynomial commitments
			dir = filepath.Join(baseDir, "polynomial/", d.Package)
			entriesF = []bavard.EntryF{
				{File: filepath.Join(dir, "polynomial.go"), TemplateF: []string{"polynomial.go.tmpl"}},
			}
			if err := bgen.GenerateF(d, d.Package, ".", entriesF...); err != nil {
				panic(err)
			}

			// 1 - mock polynomial commitment
			dir = filepath.Join(baseDir, "polynomial/", d.Package, "/mock_commitment/")
			entriesF = []bavard.EntryF{
				{File: filepath.Join(dir, "digest.go"), TemplateF: []string{"mock_commitment/digest.go.tmpl"}},
				{File: filepath.Join(dir, "proof.go"), TemplateF: []string{"mock_commitment/proof.go.tmpl"}},
				{File: filepath.Join(dir, "proof_single_point.go"), TemplateF: []string{"mock_commitment/proof.single.point.go.tmpl"}},
				{File: filepath.Join(dir, "scheme.go"), TemplateF: []string{"mock_commitment/scheme.go.tmpl"}},
			}
			if err := bgen.GenerateF(d, "mockcommitment", ".", entriesF...); err != nil {
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
