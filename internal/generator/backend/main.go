package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark-crypto/field/generator"
	"github.com/consensys/gnark-crypto/field/generator/config"
)

const copyrightHolder = "ConsenSys Software Inc."

var bgen = bavard.NewBatchGenerator(copyrightHolder, 2020, "gnark")

//go:generate go run main.go
func main() {

	bls12_377 := templateData{
		RootPath: "../../../backend/{?}/bls12-377/",
		CSPath:   "../../../constraint/bls12-377/",
		Curve:    "BLS12-377",
		CurveID:  "BLS12_377",
	}
	bls12_381 := templateData{
		RootPath: "../../../backend/{?}/bls12-381/",
		CSPath:   "../../../constraint/bls12-381/",
		Curve:    "BLS12-381",
		CurveID:  "BLS12_381",
	}
	bn254 := templateData{
		RootPath: "../../../backend/{?}/bn254/",
		CSPath:   "../../../constraint/bn254/",
		Curve:    "BN254",
		CurveID:  "BN254",
	}
	bw6_761 := templateData{
		RootPath: "../../../backend/{?}/bw6-761/",
		CSPath:   "../../../constraint/bw6-761/",
		Curve:    "BW6-761",
		CurveID:  "BW6_761",
	}
	bls24_315 := templateData{
		RootPath: "../../../backend/{?}/bls24-315/",
		CSPath:   "../../../constraint/bls24-315/",
		Curve:    "BLS24-315",
		CurveID:  "BLS24_315",
	}
	bls24_317 := templateData{
		RootPath: "../../../backend/{?}/bls24-317/",
		CSPath:   "../../../constraint/bls24-317/",
		Curve:    "BLS24-317",
		CurveID:  "BLS24_317",
	}
	bw6_633 := templateData{
		RootPath: "../../../backend/{?}/bw6-633/",
		CSPath:   "../../../constraint/bw6-633/",
		Curve:    "BW6-633",
		CurveID:  "BW6_633",
	}
	tiny_field := templateData{
		RootPath:  "../../../internal/tinyfield/",
		CSPath:    "../../../constraint/tinyfield",
		Curve:     "tinyfield",
		CurveID:   "UNKNOWN",
		noBackend: true,
		NoGKR:     true,
	}

	// autogenerate tinyfield
	tinyfieldConf, err := config.NewFieldConfig("tinyfield", "Element", "0x2f", false)
	if err != nil {
		panic(err)
	}
	if err := generator.GenerateFF(tinyfieldConf, tiny_field.RootPath); err != nil {
		panic(err)
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

			var (
				groth16Dir         = strings.Replace(d.RootPath, "{?}", "groth16", 1)
				groth16MpcSetupDir = filepath.Join(groth16Dir, "mpcsetup")
				plonkDir           = strings.Replace(d.RootPath, "{?}", "plonk", 1)
			)

			if err := os.MkdirAll(groth16Dir, 0700); err != nil {
				panic(err)
			}
			if err := os.MkdirAll(plonkDir, 0700); err != nil {
				panic(err)
			}

			csDir := d.CSPath

			// constraint systems
			entries := []bavard.Entry{
				{File: filepath.Join(csDir, "system.go"), Templates: []string{"system.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "marshal.go"), Templates: []string{"marshal.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "coeff.go"), Templates: []string{"coeff.go.tmpl", importCurve}},
				{File: filepath.Join(csDir, "solver.go"), Templates: []string{"solver.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "cs", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			// gkr backend
			if d.Curve != "tinyfield" {
				entries = []bavard.Entry{{File: filepath.Join(csDir, "gkr.go"), Templates: []string{"gkr.go.tmpl", importCurve}}}
				if err := bgen.Generate(d, "cs", "./template/representations/", entries...); err != nil {
					panic(err)
				}
			}

			entries = []bavard.Entry{
				{File: filepath.Join(csDir, "r1cs_test.go"), Templates: []string{"tests/r1cs.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "cs_test", "./template/representations/", entries...); err != nil {
				panic(err)
			}

			// groth16 & plonk
			if d.noBackend {
				// no backend with just the field defined
				return
			}

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
				{File: filepath.Join(groth16Dir, "marshal.go"), Templates: []string{"groth16/groth16.marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16Dir, "marshal_test.go"), Templates: []string{"groth16/tests/groth16.marshal.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			entries = []bavard.Entry{
				{File: filepath.Join(groth16Dir, "commitment_test.go"), Templates: []string{"groth16/tests/groth16.commitment.go.tmpl", importCurve}},
			}
			if err := bgen.Generate(d, "groth16_test", "./template/zkpschemes/", entries...); err != nil {
				panic(err) // TODO handle
			}

			// groth16 mpcsetup
			entries = []bavard.Entry{
				{File: filepath.Join(groth16MpcSetupDir, "lagrange.go"), Templates: []string{"groth16/mpcsetup/lagrange.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "marshal.go"), Templates: []string{"groth16/mpcsetup/marshal.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "marshal_test.go"), Templates: []string{"groth16/mpcsetup/marshal_test.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "phase1.go"), Templates: []string{"groth16/mpcsetup/phase1.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "phase2.go"), Templates: []string{"groth16/mpcsetup/phase2.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup.go"), Templates: []string{"groth16/mpcsetup/setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup_test.go"), Templates: []string{"groth16/mpcsetup/setup_test.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "utils.go"), Templates: []string{"groth16/mpcsetup/utils.go.tmpl", importCurve}},
			}

			if err := bgen.Generate(d, "mpcsetup", "./template/zkpschemes/", entries...); err != nil {
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
	CSPath    string
	Curve     string
	CurveID   string
	noBackend bool
	NoGKR     bool
}
