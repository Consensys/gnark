package main

import (
	"github.com/consensys/bavard"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
)

const copyrightHolder = "ConsenSys Software Inc."

var bgen = bavard.NewBatchGenerator(copyrightHolder, 2020, "gnark")

//go:generate go run main.go
func main() {

	bls12_377 := templateData{
		RootPath: "../../../internal/backend/bls12-377/",
		Curve:    "BLS12-377",
		CurveID:  "BLS12_377",
	}
	bls12_381 := templateData{
		RootPath: "../../../internal/backend/bls12-381/",
		Curve:    "BLS12-381",
		CurveID:  "BLS12_381",
	}
	bn254 := templateData{
		RootPath: "../../../internal/backend/bn254/",
		Curve:    "BN254",
		CurveID:  "BN254",
	}
	bw6_761 := templateData{
		RootPath: "../../../internal/backend/bw6-761/",
		Curve:    "BW6-761",
		CurveID:  "BW6_761",
	}
	bls24_315 := templateData{
		RootPath: "../../../internal/backend/bls24-315/",
		Curve:    "BLS24-315",
		CurveID:  "BLS24_315",
	}
	bls24_317 := templateData{
		RootPath: "../../../internal/backend/bls24-317/",
		Curve:    "BLS24-317",
		CurveID:  "BLS24_317",
	}
	bw6_633 := templateData{
		RootPath: "../../../internal/backend/bw6-633/",
		Curve:    "BW6-633",
		CurveID:  "BW6_633",
	}
	tiny_field := templateData{
		RootPath:  "../../../internal/tinyfield/",
		Curve:     "tinyfield",
		CurveID:   "UNKNOWN",
		noBackend: true,
	}

	datas := []templateData{
		bls12_377,
		bls12_381,
		bn254,
		bw6_761,
		bls24_315,
		bls24_317,
		bw6_633,
		tiny_field,
	}

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
			if err := os.MkdirAll(d.RootPath+"plonkfri", 0700); err != nil {
				panic(err)
			}

			csDir := filepath.Join(d.RootPath, "cs")
			witnessDir := filepath.Join(d.RootPath, "witness")

			// constraint systems
			entries := []bavard.Entry{
				{File: filepath.Join(csDir, "r1cs.go"), Templates: []string{"r1cs.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "r1cs_sparse.go"), Templates: []string{"r1cs.sparse.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "solution.go"), Templates: []string{"solution.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.Entry{
				{File: filepath.Join(csDir, "r1cs_test.go"), Templates: []string{"tests/r1cs.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "cs_test", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.Entry{
				{File: filepath.Join(witnessDir, "witness.go"), Templates: []string{"witness.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "witness", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			// groth16 & plonk
			if d.noBackend {
				// no backend with just the field defined
				return
			}

			plonkFriDir := filepath.Join(d.RootPath, "plonkfri")
			groth16Dir := filepath.Join(d.RootPath, "groth16")
			plonkDir := filepath.Join(d.RootPath, "plonk")

			if err := os.MkdirAll(groth16Dir, 0700); err != nil {
				panic(err)
			}
			if err := os.MkdirAll(plonkDir, 0700); err != nil {
				panic(err)
			}

			entries = []bavard.Entry{
				{File: filepath.Join(groth16Dir, "verify.go"), Templates: []string{"groth16/groth16.verify.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "prove.go"), Templates: []string{"groth16/groth16.prove.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "setup.go"), Templates: []string{"groth16/groth16.setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "commitment.go"), Templates: []string{"groth16/groth16.commitment.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal.go"), Templates: []string{"groth16/groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), Templates: []string{"groth16/tests/groth16.marshal.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			entries = []bavard.Entry{
				{File: filepath.Join(groth16Dir, "groth16_test.go"), Templates: []string{"groth16/tests/groth16.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "commitment_test.go"), Templates: []string{"groth16/tests/groth16.commitment.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			// plonk
			entries = []bavard.Entry{
				{File: filepath.Join(plonkDir, "verify.go"), Templates: []string{"plonk/plonk.verify.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "prove.go"), Templates: []string{"plonk/plonk.prove.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "setup.go"), Templates: []string{"plonk/plonk.setup.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "marshal.go"), Templates: []string{"plonk/plonk.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(plonkDir, "marshal_test.go"), Templates: []string{"plonk/tests/marshal.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "plonk", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

			entries = []bavard.Entry{
				{File: filepath.Join(plonkDir, "plonk_test.go"), Templates: []string{"plonk/tests/plonk.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "plonk_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err)
			}

			// plonkfri
			entries = []bavard.Entry{
				{File: filepath.Join(plonkFriDir, "verify.go"), Templates: []string{"plonkfri/plonk.verify.go.tmpl", importCurve}},
				{File: filepath.Join(plonkFriDir, "prove.go"), Templates: []string{"plonkfri/plonk.prove.go.tmpl", importCurve}},
				{File: filepath.Join(plonkFriDir, "setup.go"), Templates: []string{"plonkfri/plonk.setup.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "plonkfri", "./template/zkpschemes/", entries...); err != nil {
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
	RootPath  string
	Curve     string
	CurveID   string
	noBackend bool
}
