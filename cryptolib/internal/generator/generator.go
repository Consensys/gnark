package generator

import (
	"fmt"
	"strings"

	"github.com/consensys/bavard"
	"github.com/consensys/gnark/cryptolib/internal/meta"
	"github.com/consensys/gnark/cryptolib/internal/template"
)

// Generate template generator
func Generate(d meta.Data) error {

	if !strings.HasSuffix(d.Path, "/") {
		d.Path += "/"
	}
	fmt.Println()
	fmt.Println("generating crpyptolib for ", d.Curve)
	fmt.Println()

	{
		// generate eddsa
		src := []string{
			template.EddsaTemplate,
		}
		if err := bavard.Generate(d.Path+"eddsa.go", src, d,
			bavard.Package("eddsa"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/cryptolib/internal/generator"),
		); err != nil {
			return err
		}
	}
	{
		// generate eddsa tests
		src := []string{
			template.EddsaTest,
		}
		if err := bavard.Generate(d.Path+"eddsa_test.go", src, d,
			bavard.Package("eddsa"),
			bavard.Apache2("ConsenSys AG", 2020),
			bavard.GeneratedBy("gnark/cryptolib/internal/generator"),
		); err != nil {
			return err
		}
	}
	return nil
}
