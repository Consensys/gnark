package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
)

const copyrightHolder = "ConsenSys Software Inc."

var bgen = bavard.NewBatchGenerator(copyrightHolder, "gnark")

//go:generate go run main.go
func main() {

	bls377 := templateData{
		RootPath: "../../../internal/backend/bls377/",
		Curve:    "BLS377",
	}
	bls381 := templateData{
		RootPath: "../../../internal/backend/bls381/",
		Curve:    "BLS381",
	}
	bn256 := templateData{
		RootPath: "../../../internal/backend/bn256/",
		Curve:    "BN256",
	}

	bw761 := templateData{
		RootPath: "../../../internal/backend/bw761/",
		Curve:    "BW761",
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

			fftDir := filepath.Join(d.RootPath, "fft")
			groth16Dir := filepath.Join(d.RootPath, "groth16")
			plonkDir := filepath.Join(d.RootPath, "plonk")
			backendR1csDir := filepath.Join(d.RootPath, "r1cs")
			backendPcsDir := filepath.Join(d.RootPath, "pcs")
			witnessDir := filepath.Join(d.RootPath, "witness")
			r1csDir := "../../../backend/r1cs/"
			pcsDir := "../../../backend/pcs/"

			// data generated in backend/
			entries := []bavard.EntryF{
				{
					File:      filepath.Join(r1csDir, "r1cs_"+strings.ToLower(d.Curve)+".go"),
					TemplateF: []string{"r1cs.convertor.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "r1cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(pcsDir, "pcs_"+strings.ToLower(d.Curve)+".go"),
					TemplateF: []string{"pcs.convertor.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "pcs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			// data generated in internal/backend/<curve>/
			entries = []bavard.EntryF{
				{
					File:      filepath.Join(backendR1csDir, "r1cs.go"),
					TemplateF: []string{"r1cs.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "r1cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(backendPcsDir, "pcs.go"),
					TemplateF: []string{"pcs.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "pcs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(witnessDir, "witness.go"),
					TemplateF: []string{"witness.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "witness", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(backendR1csDir, "r1cs_test.go"),
					TemplateF: []string{"tests/r1cs.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "r1cs_test", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(fftDir, "domain_test.go"), TemplateF: []string{"tests/domain.go.tmpl", importCurve}},
				{File: filepath.Join(fftDir, "domain.go"), TemplateF: []string{"domain.go.tmpl", importCurve}},
				{File: filepath.Join(fftDir, "fft_test.go"), TemplateF: []string{"tests/fft.go.tmpl", importCurve}},
				{File: filepath.Join(fftDir, "fft.go"), TemplateF: []string{"fft.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "fft", "./template/fft/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{File: filepath.Join(groth16Dir, "verify.go"), TemplateF: []string{"groth16.verify.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "prove.go"), TemplateF: []string{"groth16.prove.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "setup.go"), TemplateF: []string{"groth16.setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal.go"), TemplateF: []string{"groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), TemplateF: []string{"tests/groth16.marshal.go.tmpl", importCurve}},
			}
			if err := bgen.GenerateF(d, "groth16", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(groth16Dir, "groth16_test.go"),
					TemplateF: []string{"tests/groth16.go.tmpl", importCurve},
				},
			}
			if err := bgen.GenerateF(d, "groth16_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.EntryF{
				{
					File:      filepath.Join(plonkDir, "plonk_test.go"),
					TemplateF: []string{"tests/plonk.go.tmpl"},
				},
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
}
