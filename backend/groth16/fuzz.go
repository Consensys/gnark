//go:build gofuzz
// +build gofuzz

package groth16

import (
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	backend_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/cs"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	backend_bn254 "github.com/consensys/gnark/internal/backend/bn254/cs"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
)

func Fuzz(data []byte) int {
	curves := []ecc.ID{ecc.BN254, ecc.BLS12_381}
	for _, curveID := range curves {
		ccs, nbAssertions := frontend.CsFuzzed(data, curveID)
		_, s, p := ccs.GetNbVariables()
		wSize := s + p - 1
		ccs.SetLoggerOutput(nil)
		switch _r1cs := ccs.(type) {
		case *backend_bls12381.R1CS:
			w := make(witness_bls12381.Witness, wSize)
			// make w random
			err := _r1cs.IsSolved(w)
			if nbAssertions == 0 && err != nil && !strings.Contains(err.Error(), "couldn't solve computational constraint") {
				panic("no assertions, yet solving resulted in an error.")
			}
		case *backend_bn254.R1CS:
			w := make(witness_bn254.Witness, wSize)
			// make w random
			err := _r1cs.IsSolved(w)
			if nbAssertions == 0 && err != nil && !strings.Contains(err.Error(), "couldn't solve computational constraint") {
				panic("no assertions, yet solving resulted in an error.")
			}
		default:
			panic("unrecognized R1CS curve type")
		}
	}
	return 1
}
