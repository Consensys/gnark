package generator

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"text/template"

	"github.com/consensys/gnark/internal/templates"
	"github.com/consensys/gnark/internal/templates/algorithms"
	"github.com/consensys/gnark/internal/templates/representations"
	"github.com/consensys/gnark/internal/templates/zkpschemes"
)

type GenerateData struct {
	RootPath string
	Curve    string // GENERIC, BLS381, BLS377, BN256
}

func GenerateGroth16(d GenerateData) {
	if !strings.HasSuffix(d.RootPath, "/") {
		d.RootPath += "/"
	}
	{
		// generate R1CS.go
		src := []string{
			templates.Header,
			templates.ImportCurve,
			representations.R1CS,
		}
		if err := generateCode(d.RootPath+"r1cs.go", src, d); err != nil {
			panic(err)
		}
	}

	{
		// generate assignment.go
		src := []string{
			templates.Header,
			templates.ImportCurve,
			representations.Assignment,
		}
		if err := generateCode(d.RootPath+"assignment.go", src, d); err != nil {
			panic(err)
		}
	}

	// groth16
	{
		// setup
		src := []string{
			templates.Header,
			templates.ImportCurve,
			zkpschemes.Groth16Setup,
		}
		if err := generateCode(d.RootPath+"groth16/setup.go", src, d); err != nil {
			panic(err)
		}
	}
	{
		// prove
		src := []string{
			templates.Header,
			templates.ImportCurve,
			zkpschemes.Groth16Prove,
		}
		if err := generateCode(d.RootPath+"groth16/prove.go", src, d); err != nil {
			panic(err)
		}
	}

	{
		// verify
		src := []string{
			templates.Header,
			templates.ImportCurve,
			zkpschemes.Groth16Verify,
		}
		if err := generateCode(d.RootPath+"groth16/verify.go", src, d); err != nil {
			panic(err)
		}
	}

	{
		// generate FFT
		src := []string{
			templates.Header,
			templates.ImportCurve,
			algorithms.FFT,
		}
		if err := generateCode(d.RootPath+"groth16/fft.go", src, d); err != nil {
			panic(err)
		}
	}

	{
		// assert
		src := []string{
			templates.Header,
			templates.ImportCurve,
			zkpschemes.Groth16Assert,
		}
		if err := generateCode(d.RootPath+"groth16/assert.go", src, d); err != nil {
			panic(err)
		}
	}

	{
		// tests
		src := []string{
			templates.Header,
			templates.ImportCurve,
			zkpschemes.Groth16Tests,
		}
		if err := generateCode(d.RootPath+"groth16/groth16_test.go", src, d); err != nil {
			panic(err)
		}
	}

}

// TODO from goff, need factorizing all this code generation business
func generateCode(output string, templates []string, tData GenerateData) error {
	// create output file
	file, err := os.Create(output)
	if err != nil {
		return err
	}
	fmt.Printf("generating %-70s\n", output)

	// parse templates
	tmpl := template.Must(template.New("").
		// Funcs(helpers()).
		Parse(aggregate(templates)))

	// execute template
	if err = tmpl.Execute(file, tData); err != nil {
		file.Close()
		return err
	}
	file.Close()

	// run goformat to prettify output source
	if err := exec.Command("gofmt", "-s", "-w", output).Run(); err != nil {
		return err
	}
	if err := exec.Command("goimports", "-w", output).Run(); err != nil {
		return err
	}
	return nil
}

func aggregate(values []string) string {
	var sb strings.Builder
	for _, v := range values {
		sb.WriteString(v)
	}
	return sb.String()
}
