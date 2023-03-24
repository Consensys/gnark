package polynomial

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// Univariate encodes a univariate polynomial: a0 + a1X + ... + ad X^d <=> {a0, a1, ... , ad}
type Univariate struct {
	Coefficients []frontend.Variable
}

// NewUnivariate is the default constructor
func NewUnivariate(coeffs []frontend.Variable) Univariate {
	return Univariate{Coefficients: coeffs}
}

// AllocateUnivariate returns an empty multilinear with a given size
func AllocateUnivariate(degree int) Univariate {
	univariates := make([]frontend.Variable, degree+1)
	for i := range univariates {
		univariates[i] = 0
	}
	return NewUnivariate(univariates)
}

// Assign value to a previously allocated univariate
func (u *Univariate) Assign(coeffs []fr.Element) {
	if len(coeffs) != len(u.Coefficients) {
		panic(fmt.Sprintf("Inconsistent assignment for univariate poly %v != %v", len(coeffs), len(u.Coefficients)))
	}
	for i, c := range coeffs {
		u.Coefficients[i] = c
	}
}

// Eval returns p(x)
func (u *Univariate) Eval(cs frontend.API, x frontend.Variable) (res frontend.Variable) {

	res = frontend.Variable(0)
	aux := frontend.Variable(0)

	for i := len(u.Coefficients) - 1; i >= 0; i-- {
		if i != len(u.Coefficients)-1 {
			res = cs.Mul(aux, x)
		}
		aux = cs.Add(res, u.Coefficients[i])
	}

	// TODO why mul by 1 ?
	return cs.Mul(aux, 1)
}

// ZeroAndOne returns p(0) + p(1)
func (u *Univariate) ZeroAndOne(cs frontend.API) frontend.Variable {

	// coeffsInterface is required for cs.Add(a, b, coeffsInterface[1:]...) to be accepted.
	coeffsInterface := make([]frontend.Variable, len(u.Coefficients))
	copy(coeffsInterface, u.Coefficients)

	res := cs.Add(u.Coefficients[0], u.Coefficients[0], coeffsInterface[1:]...)

	return res
}
