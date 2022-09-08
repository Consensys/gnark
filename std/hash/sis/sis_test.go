package sis

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	gsis "github.com/consensys/gnark-crypto/ecc/bn254/fr/sis"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

type MulModTest struct {
	P    [8]fr.Element
	Q, R [8]frontend.Variable
}

func (circuit *MulModTest) Define(api frontend.API) error {

	r := mulMod(api, circuit.P[:], circuit.Q[:])

	for i := 0; i < len(r); i++ {
		api.AssertIsEqual(r[i], circuit.R[i])
	}

	return nil

}

// func printPoly(p []fr.Element) {
// 	for i := 0; i < len(p); i++ {
// 		fmt.Printf("%s*x**%d+", p[i].String(), i)
// 	}
// 	fmt.Println("")
// }

func TestMulMod(t *testing.T) {

	// get correct data
	rsis, err := gsis.NewRSis(5, 3, 4, 8)
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

	r := rsis.MulMod(_p, _q)

	var witness MulModTest
	for i := 0; i < len(p); i++ {
		witness.P[i] = p[i]
		witness.Q[i] = q[i]
		witness.R[i] = r[i]
	}

	var circuit MulModTest
	for i := 0; i < len(circuit.P); i++ {
		circuit.P[i] = p[i]
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &circuit, frontend.IgnoreUnconstrainedInputs())
	if err != nil {
		t.Fatal(err)
	}

	twitness, err := frontend.NewWitness(&witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
	err = ccs.IsSolved(twitness)
	if err != nil {
		t.Fatal(err)
	}

}
