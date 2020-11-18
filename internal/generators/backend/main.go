package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark/internal/generators/backend/template"
	"github.com/consensys/gnark/internal/generators/backend/template/fft"
	"github.com/consensys/gnark/internal/generators/backend/template/representations"
	"github.com/consensys/gnark/internal/generators/backend/template/zkpschemes"
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
			backendDir := d.RootPath
			r1csDir := "../../../backend/r1cs/"

			entries := []bavard.Entry{
				{Data: d, PackageName: "r1cs", File: filepath.Join(r1csDir, "r1cs_"+strings.ToLower(d.Curve)+".go"), Templates: []string{template.ImportCurve, representations.R1CSConvertor}},
				{Data: d, PackageName: "backend", File: filepath.Join(backendDir, "r1cs.go"), Templates: []string{template.ImportCurve, representations.R1CS}},
				{Data: d, PackageName: "backend_test", File: filepath.Join(backendDir, "r1cs_test.go"), Templates: []string{template.ImportCurve, representations.R1CSTests}},
				{Data: d, PackageName: "fft", File: filepath.Join(fftDir, "domain_test.go"), Templates: []string{template.ImportCurve, fft.DomainTests}},
				{Data: d, PackageName: "fft", File: filepath.Join(fftDir, "domain.go"), Templates: []string{template.ImportCurve, fft.Domain}},
				{Data: d, PackageName: "fft", File: filepath.Join(fftDir, "fft_test.go"), Templates: []string{template.ImportCurve, fft.FFTTests}},
				{Data: d, PackageName: "fft", File: filepath.Join(fftDir, "fft.go"), Templates: []string{template.ImportCurve, fft.FFT}},
				{Data: d, PackageName: "groth16", File: filepath.Join(groth16Dir, "verify.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16Verify}},
				{Data: d, PackageName: "groth16", File: filepath.Join(groth16Dir, "prove.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16Prove}},
				{Data: d, PackageName: "groth16", File: filepath.Join(groth16Dir, "setup.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16Setup}},
				{Data: d, PackageName: "groth16", File: filepath.Join(groth16Dir, "marshal.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16Marshal}},
				{Data: d, PackageName: "groth16", File: filepath.Join(groth16Dir, "marshal_test.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16MarshalTest}},
				{Data: d, PackageName: "groth16_test", File: filepath.Join(groth16Dir, "groth16_test.go"), Templates: []string{template.ImportCurve, zkpschemes.Groth16Tests}},
			}

			if err := bgen.Generate(entries...); err != nil {
				panic(err) // TODO handle
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
