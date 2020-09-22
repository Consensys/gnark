package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark/internal/generators/backend/template"
	"github.com/consensys/gnark/internal/generators/backend/template/algorithms"
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

	for _, d := range datas {
		if err := os.MkdirAll(d.RootPath+"groth16", 0700); err != nil {
			panic(err)
		}
		if err := generateGroth16(d); err != nil {
			panic(err)
		}
		d.RootPath = "../../../backend/r1cs/"
		if err := generateR1CSConvertor(d); err != nil {
			panic(err)
		}
	}

}

type templateData struct {
	RootPath string
	Curve    string // BLS381, BLS377, BN256, BW761
}

func generateR1CSConvertor(d templateData) error {
	if !strings.HasSuffix(d.RootPath, "/") {
		d.RootPath += "/"
	}
	fmt.Println()
	fmt.Println("generating r1cs convertor for ", d.Curve)
	fmt.Println()

	// generate r1cs_curve.go
	src := []string{
		template.ImportCurve,
		representations.R1CSConvertor,
	}
	return bavard.Generate(d.RootPath+"r1cs_"+strings.ToLower(d.Curve)+".go", src, d,
		bavard.Package("r1cs"),
		bavard.Apache2("ConsenSys AG", 2020),
		bavard.GeneratedBy("gnark/internal/generators"),
	)
}

func generateGroth16(d templateData) error {
	if !strings.HasSuffix(d.RootPath, "/") {
		d.RootPath += "/"
	}
	fmt.Println()
	fmt.Println("generating groth16 backend for ", d.Curve)
	fmt.Println()

	// generate R1CS.go
	src := []string{
		template.ImportCurve,
		representations.R1CS,
	}
	if err := bavard.Generate(d.RootPath+"r1cs.go", src, d,
		bavard.Package("backend"),
		bavard.Apache2("ConsenSys AG", 2020),
		bavard.GeneratedBy("gnark/internal/generators"),
	); err != nil {
		return err
	}

	// groth16
	{
		// setup
		src := []string{
			template.ImportCurve,
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
			template.ImportCurve,
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
			template.ImportCurve,
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
			template.ImportCurve,
			algorithms.FFT,
		}
		if err := bavard.Generate(d.RootPath+"fft.go", src, d,
			bavard.Package("backend"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	{
		// generate FFT domain
		src := []string{
			template.ImportCurve,
			algorithms.Domain,
		}
		if err := bavard.Generate(d.RootPath+"domain.go", src, d,
			bavard.Package("backend"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}

	{
		// tests
		src := []string{
			template.ImportCurve,
			zkpschemes.Groth16Tests,
		}
		if err := bavard.Generate(d.RootPath+"groth16/groth16_test.go", src, d,
			bavard.Package("groth16_test"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/internal/generators"),
		); err != nil {
			return err
		}
	}
	return nil
}
