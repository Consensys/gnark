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

			for _, g := range []genOpts{
				{data: d, packageName: "r1cs", dir: r1csDir, file: "r1cs_" + strings.ToLower(d.Curve) + ".go", templates: []string{template.ImportCurve, representations.R1CSConvertor}},
				{data: d, packageName: "backend", dir: backendDir, file: "r1cs.go", templates: []string{template.ImportCurve, representations.R1CS}},
				{data: d, packageName: "backend_test", dir: backendDir, file: "r1cs_test.go", templates: []string{template.ImportCurve, representations.R1CSTests}},
				{data: d, packageName: "fft", dir: fftDir, file: "domain_test.go", templates: []string{template.ImportCurve, fft.DomainTests}},
				{data: d, packageName: "fft", dir: fftDir, file: "domain.go", templates: []string{template.ImportCurve, fft.Domain}},
				{data: d, packageName: "fft", dir: fftDir, file: "fft_test.go", templates: []string{template.ImportCurve, fft.FFTTests}},
				{data: d, packageName: "fft", dir: fftDir, file: "fft.go", templates: []string{template.ImportCurve, fft.FFT}},
				{data: d, packageName: "groth16", dir: groth16Dir, file: "verify.go", templates: []string{template.ImportCurve, zkpschemes.Groth16Verify}},
				{data: d, packageName: "groth16", dir: groth16Dir, file: "prove.go", templates: []string{template.ImportCurve, zkpschemes.Groth16Prove}},
				{data: d, packageName: "groth16", dir: groth16Dir, file: "setup.go", templates: []string{template.ImportCurve, zkpschemes.Groth16Setup}},
				{data: d, packageName: "groth16", dir: groth16Dir, file: "marshal.go", templates: []string{template.ImportCurve, zkpschemes.Groth16Marshal}},
				{data: d, packageName: "groth16", dir: groth16Dir, file: "marshal_test.go", templates: []string{template.ImportCurve, zkpschemes.Groth16MarshalTest}},
				{data: d, packageName: "groth16_test", dir: groth16Dir, file: "groth16_test.go", templates: []string{template.ImportCurve, zkpschemes.Groth16Tests}},
			} {
				generate(g)
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

const copyrightHolder = "ConsenSys Software Inc."

func generate(g genOpts) {
	opts := []func(*bavard.Bavard) error{
		bavard.Apache2(copyrightHolder, 2020),
		bavard.GeneratedBy("gnark"),
		bavard.Format(false),
		bavard.Import(false),
	}
	if g.buildTag != "" {
		opts = append(opts, bavard.BuildTag(g.buildTag))
	}
	file := filepath.Join(g.dir, g.file)

	opts = append(opts, bavard.Package(g.packageName, g.doc))

	if err := bavard.Generate(file, g.templates, g.data, opts...); err != nil {
		panic(err)
	}
}

type genOpts struct {
	file        string
	templates   []string
	buildTag    string
	dir         string
	packageName string
	doc         string
	data        interface{}
}
