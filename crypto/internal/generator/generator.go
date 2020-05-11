package generator

import (
	"fmt"
	"strings"

	"github.com/consensys/bavard"
)

// Data meta data for template generation
type Data struct {
	Curve    string
	Path     string
	FileName string
	Src      []string
	Package  string
}

// Generate template generator
func Generate(d Data) error {

	if !strings.HasSuffix(d.Path, "/") {
		d.Path += "/"
	}
	fmt.Println()
	fmt.Println("generating crpyptolib for ", d.Curve)
	fmt.Println()

	if err := bavard.Generate(d.Path+d.FileName, d.Src, d,
		bavard.Package(d.Package),
		bavard.Apache2("ConsenSys AG", 2020),
		bavard.GeneratedBy("gnark/crypto/internal/generator"),
	); err != nil {
		return err
	}

	return nil
}
