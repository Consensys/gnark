package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
)

var bgen = bavard.NewBatchGenerator(copyrightHolder, 2020, "gnark")

const (
	baseDir         = "../"
	copyrightHolder = "ConsenSys Software Inc."
)

// templateData meta data for template generation
type templateData struct {
	Curve    string
	CurveID  string
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

//go:generate go run main.go
func main() {

	// mimc files
	bn254 := templateData{
		Curve:   "BN254",
		CurveID: "BN254",
		Package: "bn254",
	}

	bls12_381 := templateData{
		Curve:   "BLS12-381",
		CurveID: "BLS12_381",
		Package: "bls12381",
	}

	bls12_377 := templateData{
		Curve:   "BLS12-377",
		CurveID: "BLS12_377",
		Package: "bls12377",
	}

	bw761 := templateData{
		Curve:   "BW6-761",
		CurveID: "BW6_761",
		Package: "bw6761",
	}

	data := []templateData{
		bn254,
		bls12_381,
		bls12_377,
		bw761,
	}

	var wg sync.WaitGroup
	for _, d := range data {
		wg.Add(1)
		go func(d templateData) {
			defer wg.Done()

			// polynomial commitments
			dir := filepath.Join(baseDir, "polynomial/", strings.ToLower(d.Curve))
			entriesF := []bavard.EntryF{
				{File: filepath.Join(dir, "polynomial.go"), TemplateF: []string{"polynomial.go.tmpl"}},
			}
			if err := bgen.GenerateF(d, d.Package, ".", entriesF...); err != nil {
				panic(err)
			}

			// 1 - mock polynomial commitment
			dir = filepath.Join(dir, "/mock_commitment/")
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
