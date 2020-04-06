package generator

import (
	"fmt"
	"strings"

	"github.com/consensys/bavard"
	templates "github.com/consensys/gnark/internal/generators/backend/template"
	"github.com/consensys/gnark/internal/generators/backend/template/algorithms"
	"github.com/consensys/gnark/internal/generators/backend/template/representations"
	"github.com/consensys/gnark/internal/generators/backend/template/zkpschemes"
)

type GenerateData struct {
	RootPath string
	Curve    string // GENERIC, BLS381, BLS377, BN256
}

func GenerateGroth16(d GenerateData) error {
	if !strings.HasSuffix(d.RootPath, "/") {
		d.RootPath += "/"
	}
	fmt.Println()
	fmt.Println("generating groth16 backend for ", d.Curve)
	fmt.Println()
	if d.Curve == "GENERIC" {
		return nil
	}

	if d.Curve != "GENERIC" {
		// generate R1CS.go
		src := []string{
			templates.ImportCurve,
			representations.R1CS,
		}
		if err := bavard.Generate(d.RootPath+"r1cs.go", src, d,
			bavard.Package("backend_"+strings.ToLower(d.Curve)),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	// groth16
	{
		// setup
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Setup,
		}
		if err := bavard.Generate(d.RootPath+"groth16/setup.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}
	{
		// prove
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Prove,
		}
		if err := bavard.Generate(d.RootPath+"groth16/prove.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	{
		// verify
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Verify,
		}
		if err := bavard.Generate(d.RootPath+"groth16/verify.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	{
		// generate FFT
		src := []string{
			templates.ImportCurve,
			algorithms.FFT,
		}
		if err := bavard.Generate(d.RootPath+"fft.go", src, d,
			bavard.Package("backend_"+strings.ToLower(d.Curve)),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	if d.Curve == "GENERIC" {
		// export assert only in GENERIC case
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Assert,
		}
		if err := bavard.Generate(d.RootPath+"groth16/assert.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	{
		// tests
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Tests,
			zkpschemes.Groth16Assert,
		}
		if err := bavard.Generate(d.RootPath+"groth16/groth16_test.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}
	{
		// utils
		src := []string{
			templates.ImportCurve,
			zkpschemes.Groth16Assert,
		}
		if err := bavard.Generate(d.RootPath+"groth16/utils.go", src, d,
			bavard.Package("groth16"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}
	return nil
}
