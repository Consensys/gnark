// +build gofuzz

package groth16

import (
	"strings"

	"github.com/consensys/gnark/frontend"
	backend_bls381 "github.com/consensys/gnark/internal/backend/bls381/cs"
	witness_bls381 "github.com/consensys/gnark/internal/backend/bls381/witness"
	backend_bn256 "github.com/consensys/gnark/internal/backend/bn256/cs"
	witness_bn256 "github.com/consensys/gnark/internal/backend/bn256/witness"
	"github.com/consensys/gurvy"
)

func Fuzz(data []byte) int {
	curves := []gurvy.ID{gurvy.BN256, gurvy.BLS381}
	for _, curveID := range curves {
		ccs, nbAssertions := frontend.CsFuzzed(data, curveID)
		_, s, p := ccs.GetNbVariables()
		wSize := s + p - 1

		switch _r1cs := ccs.(type) {
		case *backend_bls381.R1CS:
			w := make(witness_bls381.Witness, wSize)
			// make w random
			err := _r1cs.IsSolved(w)
			// TODO inverse can trigger a computational error, WIP
			if nbAssertions == 0 && err != nil && !strings.Contains(err.Error(), "couldn't solve computational constraint") {
				panic("no assertions, yet solving resulted in an error.")
			}
		case *backend_bn256.R1CS:
			w := make(witness_bn256.Witness, wSize)
			// make w random
			err := _r1cs.IsSolved(w)
			// TODO inverse can trigger a computational error, WIP
			if nbAssertions == 0 && err != nil && !strings.Contains(err.Error(), "couldn't solve computational constraint") {
				panic("no assertions, yet solving resulted in an error.")
			}
		default:
			panic("unrecognized R1CS curve type")
		}
	}
	return 1
}
