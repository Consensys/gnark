package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/consensys/bavard"
)

const copyrightHolder = "ConsenSys Software Inc."

var bgen = bavard.NewBatchGenerator(copyrightHolder, 2020, "gnark")

//go:generate go run main.go
func main() {

	bls377 := templateData{
		RootPath: "../../../internal/backend/bls377/",
		Curve:    "BLS377",
		CurveID:  "BLS12_377",
	}
	bls381 := templateData{
		RootPath: "../../../internal/backend/bls381/",
		Curve:    "BLS381",
		CurveID:  "BLS12_381",
	}
	bn256 := templateData{
		RootPath: "../../../internal/backend/bn256/",
		Curve:    "BN256",
		CurveID:  "BN254",
	}

	bw761 := templateData{
		RootPath: "../../../internal/backend/bw761/",
		Curve:    "BW761",
		CurveID:  "BW6_761",
	}

	datas := []templateData{bls377, bls381, bn256, bw761}

	const importCurve = "../imports.go.tmpl"

	var wg sync.WaitGroup

	for _, d := range datas {

		wg.Add(1)

		go func(d templateData) {

			defer wg.Done()

			if err := os.MkdirAll(d.RootPath+"groth16", 0700); err != nil {
				panic(err)
			}
			if err := os.MkdirAll(d.RootPath+"plonk", 0700); err != nil {
				panic(err)
			}

			groth16Dir := filepath.Join(d.RootPath, "groth16")
			plonkDir := filepath.Join(d.RootPath, "plonk")
			backendCSDir := filepath.Join(d.RootPath, "cs")
			witnessDir := filepath.Join(d.RootPath, "witness")

			// groth16
			entries := []bavard.EntryF{
				{File: filepath.Join(backendCSDir, "r1cs.go"), TemplateF: []string{"r1cs.go.tmpl", importCurve}},
				{File: filepath.Join(backendCSDir, "r1cs_sparse.go"), TemplateF: []string{"r1cs.sparse.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(backendCSDir, "r1cs_test.go"), TemplateF: []string{"tests/r1cs.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "cs_test", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(witnessDir, "witness.go"), TemplateF: []string{"witness.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "witness", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(groth16Dir, "verify.go"), TemplateF: []string{"groth16/groth16.verify.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "prove.go"), TemplateF: []string{"groth16/groth16.prove.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "setup.go"), TemplateF: []string{"groth16/groth16.setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal.go"), TemplateF: []string{"groth16/groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), TemplateF: []string{"groth16/tests/groth16.marshal.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "groth16", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(groth16Dir, "groth16_test.go"), TemplateF: []string{"groth16/tests/groth16.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "groth16_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			// plonk
			entries = []bavard.EntryF{
				{File: filepath.Join(plonkDir, "verify.go"), TemplateF: []string{"plonk/plonk.verify.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "prove.go"), TemplateF: []string{"plonk/plonk.prove.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "setup.go"), TemplateF: []string{"plonk/plonk.setup.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "plonk", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(plonkDir, "plonk_test.go"), TemplateF: []string{"plonk/tests/plonk.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "plonk_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

		}(d)

	}

	wg.Wait()

	// run go fmt on whole directory
	cmd := exec.Command("gofmt", "-s", "-w", "../../../")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		panic(err)
	}

}

type templateData struct {
	RootPath string
	Curve    string // BLS381, BLS377, BN256, BW761
	CurveID  string
}
