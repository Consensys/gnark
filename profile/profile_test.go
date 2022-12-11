package profile_test

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/profile"
)

type Circuit struct {
	A frontend.Variable
}

func (circuit *Circuit) Define(api frontend.API) error {
	api.AssertIsEqual(api.Mul(circuit.A, circuit.A), circuit.A)
	return nil
}

func Example() {
	// default options generate gnark.pprof in current dir
	// use pprof as usual (go tool pprof -http=:8080 gnark.pprof) to read the profile file
	// overlapping profiles are allowed (define profiles inside Define or subfunction to profile
	// part of the circuit only)
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &Circuit{})
	p.Stop()

	fmt.Println(p.NbConstraints())
	fmt.Println(p.Top())
	// Output:
	// 2
	// Showing nodes accounting for 2, 100% of 2 total
	//       flat  flat%   sum%        cum   cum%
	//          1 50.00% 50.00%          2   100%  profile_test.(*Circuit).Define profile/profile_test.go:17
	//          1 50.00%   100%          1 50.00%  r1cs.(*builder).AssertIsEqual frontend/cs/r1cs/api_assertions.go:37
}
