package tmpl

import (
	"os"
	"path/filepath"
	"text/template"

	"github.com/consensys/gnark-crypto/ecc/bn254/fp"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	bn254plonk "github.com/consensys/gnark/backend/plonk/bn254"
)

type ExtendedProof struct {
	bn254plonk.Proof
	Pi []fr.Element
}

func GenerateVerifier(vk bn254plonk.VerifyingKey, proof bn254plonk.Proof, pi []fr.Element, folderOut string) error {

	funcMap := template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"frptr": func(x fr.Element) *fr.Element {
			return &x
		},
		"fpptr": func(x fp.Element) *fp.Element {
			return &x
		},
		"add": func(i, j int) int {
			return i + j
		},
	}

	tf := template.New("t").Funcs(funcMap)

	{
		t, err := tf.Parse(solidityVerifier)
		if err != nil {
			return err
		}
		out := filepath.Join(folderOut, "Verifier.sol")
		fout, err := os.Create(out)
		if err != nil {
			return err
		}
		err = t.Execute(fout, vk)
		if err != nil {
			return err
		}
	}

	{
		t, err := tf.Parse(solidityTestVerifier)
		if err != nil {
			return err
		}
		out := filepath.Join(folderOut, "TestVerifier.sol")
		fout, err := os.Create(out)
		if err != nil {
			return err
		}
		eproof := ExtendedProof{proof, pi}
		err = t.Execute(fout, eproof)
		if err != nil {
			return err
		}
	}

	{
		t, err := tf.Parse(utils)
		if err != nil {
			return err
		}
		out := filepath.Join(folderOut, "Utils.sol")
		fout, err := os.Create(out)
		if err != nil {
			return err
		}
		err = t.Execute(fout, nil)
		if err != nil {
			return err
		}
	}

	return nil
}

func Generate(vk bn254plonk.VerifyingKey, folderOut string) error {

	funcMap := template.FuncMap{
		// The name "inc" is what the function will be called in the template text.
		"inc": func(i int) int {
			return i + 1
		},
		"frptr": func(x fr.Element) *fr.Element {
			return &x
		},
		"fpptr": func(x fp.Element) *fp.Element {
			return &x
		},
		"add": func(i, j int) int {
			return i + j
		},
	}

	tf := template.New("t").Funcs(funcMap)

	{
		t, err := tf.Parse(solidityVerifier)
		if err != nil {
			return err
		}
		out := filepath.Join(folderOut, "Verifier.sol")
		fout, err := os.Create(out)
		if err != nil {
			return err
		}
		err = t.Execute(fout, vk)
		if err != nil {
			return err
		}
	}

	{
		t, err := tf.Parse(utils)
		if err != nil {
			return err
		}
		out := filepath.Join(folderOut, "Utils.sol")
		fout, err := os.Create(out)
		if err != nil {
			return err
		}
		err = t.Execute(fout, nil)
		if err != nil {
			return err
		}
	}

	return nil
}
