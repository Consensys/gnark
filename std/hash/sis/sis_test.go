package sis

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	gsis "github.com/consensys/gnark-crypto/ecc/bn254/fr/sis"
	"github.com/consensys/gnark/frontend"
)

type MulModTest struct {
	P, Q [8]frontend.Variable
}

func printPoly(p []fr.Element) {
	for i := 0; i < len(p); i++ {
		fmt.Printf("%s*x**%d+", p[i].String(), i)
	}
	fmt.Println("")
}

func testMulMod(t *testing.T) {

	// get correct data
	rsis, err := gsis.NewRSis(5, 1, 4, 8)
	if err != nil {
		t.Fatal(err)
	}

	p := make([]fr.Element, 8)
	q := make([]fr.Element, 8)
	_p := make([]fr.Element, 8)
	_q := make([]fr.Element, 8)

	for i := 0; i < 8; i++ {
		p[i].SetRandom()
		q[i].SetRandom()
	}
	copy(_p, p)
	copy(_q, q)

	rsis.Domain.FFT(_p, fft.DIF, true)
	rsis.Domain.FFT(_q, fft.DIF, true)
	rsis.MulMod(_p, _q)

}
