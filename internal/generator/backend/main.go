package main

import (
	"fmt"
	"github.com/consensys/gnark-crypto/field/generator/config"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark-crypto/field/generator"
)

const copyrightHolder = "Consensys Software Inc."

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

	data := []templateData{
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

	for _, d := range data {

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
				// solver and proof delegator TODO merge with "backend" below
				entries = []bavard.Entry{{File: filepath.Join(csDir, "gkr.go"), Templates: []string{"gkr.go.tmpl", importCurve}}}
				err := bgen.Generate(d, "cs", "./template/representations/", entries...)
				assertNoError(err)

				curvePackageName := strings.ToLower(d.Curve)

				cfg := gkrConfig{
					FieldDependency: config.FieldDependency{
						ElementType:      "fr.Element",
						FieldPackageName: "fr",
						FieldPackagePath: "github.com/consensys/gnark-crypto/ecc/" + curvePackageName + "/fr",
					},
					GkrPackageRelativePath: "internal/gkr/" + curvePackageName,
					CanUseFFT:              true,
				}

				assertNoError(generateGkrBackend(cfg))
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
				{File: filepath.Join(groth16MpcSetupDir, "phase1.go"), Templates: []string{"groth16/mpcsetup/phase1.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "phase2.go"), Templates: []string{"groth16/mpcsetup/phase2.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup.go"), Templates: []string{"groth16/mpcsetup/setup.go.tmpl", importCurve}},
				{File: filepath.Join(groth16MpcSetupDir, "setup_test.go"), Templates: []string{"groth16/mpcsetup/setup_test.go.tmpl", importCurve}},
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

	wg.Add(1)
	// GKR test vectors
	go func() {
		// generate gkr and sumcheck for small-rational
		cfg := gkrConfig{
			FieldDependency: config.FieldDependency{
				ElementType:      "small_rational.SmallRational",
				FieldPackagePath: "github.com/consensys/gnark/internal/small_rational",
				FieldPackageName: "small_rational",
			},
			GkrPackageRelativePath: "internal/gkr/small_rational",
			CanUseFFT:              false,
			NoGkrTests:             true,
		}
		assertNoError(generateGkrBackend(cfg))

		// generate gkr test vector generator
		cfg.GenerateTestVectors = true
		cfg.OutsideGkrPackage = true

		assertNoError(bgen.Generate(cfg, "gkr", "./template/gkr/",
			bavard.Entry{
				File:      "../../gkr/test_vectors/gkr/gkr-gen-vectors.go",
				Templates: []string{"gkr.test.vectors.gen.go.tmpl", "gkr.test.vectors.go.tmpl"},
			},
		))

		fmt.Println("generating test vectors for gkr and sumcheck")
		cmd := exec.Command("go", "run", "../../gkr/test_vectors")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		assertNoError(cmd.Run())
		wg.Done()
	}()

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

func generateGkrBackend(cfg gkrConfig) error {
	const repoRoot = "../../../"
	packageOutPath := filepath.Join(repoRoot, cfg.GkrPackageRelativePath)

	// test vector utils
	packageDir := filepath.Join(packageOutPath, "test_vector_utils")
	entries := []bavard.Entry{
		{File: filepath.Join(packageDir, "test_vector_utils.go"), Templates: []string{"test_vector_utils.go.tmpl"}},
	}

	if err := bgen.Generate(cfg, "test_vector_utils", "./template/gkr/", entries...); err != nil {
		return err
	}

	// sumcheck backend
	packageDir = filepath.Join(packageOutPath, "sumcheck")
	entries = []bavard.Entry{
		{File: filepath.Join(packageDir, "sumcheck.go"), Templates: []string{"sumcheck.go.tmpl"}},
		{File: filepath.Join(packageDir, "sumcheck_test.go"), Templates: []string{"sumcheck.test.go.tmpl"}},
	}

	if err := bgen.Generate(cfg, "sumcheck", "./template/gkr/", entries...); err != nil {
		return err
	}

	// gkr backend
	packageDir = packageOutPath
	entries = []bavard.Entry{
		{File: filepath.Join(packageDir, "gkr.go"), Templates: []string{"gkr.go.tmpl"}},
		{File: filepath.Join(packageDir, "registry.go"), Templates: []string{"registry.go.tmpl"}},
	}

	if !cfg.NoGkrTests {
		entries = append(entries, bavard.Entry{
			File: filepath.Join(packageDir, "gkr_test.go"), Templates: []string{"gkr.test.go.tmpl", "gkr.test.vectors.go.tmpl"},
		})
	}

	if err := bgen.Generate(cfg, "gkr", "./template/gkr/", entries...); err != nil {
		return err
	}

	return nil
}

type gkrConfig struct {
	config.FieldDependency
	GkrPackageRelativePath  string // the GKR package, relative to the repo root
	TestVectorsRelativePath string // the test vectors, relative to the current package
	CanUseFFT               bool
	OutsideGkrPackage       bool
	GenerateTestVectors     bool
	NoGkrTests              bool
}

func assertNoError(err error) {
	if err != nil {
		panic(err)
	}
}
