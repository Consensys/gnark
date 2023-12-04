package polynomial

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

var minFoldScaledLogSize = 16

// Univariate defines a univariate polynomial by its coefficients.
type Univariate[FR emulated.FieldParams] []*emulated.Element[FR]

// TODO: give better package doc to Multilinear

// Multilinear defines a multivariate multilinear polynomial by its term
// coefficients.
type Multilinear[FR emulated.FieldParams] []*emulated.Element[FR]

type Polynomial[FR emulated.FieldParams] struct {
	api frontend.API
	f   *emulated.Field[FR]
}

func FromSlice[FR emulated.FieldParams](in []emulated.Element[FR]) []*emulated.Element[FR] {
	r := make([]*emulated.Element[FR], len(in))
	for i := range in {
		r[i] = &in[i]
	}
	return r
}

func New[FR emulated.FieldParams](api frontend.API) (*Polynomial[FR], error) {
	f, err := emulated.NewField[FR](api)
	if err != nil {
		return nil, fmt.Errorf("new emulated field: %w", err)
	}
	return &Polynomial[FR]{
		api: api,
		f:   f,
	}, nil
}

func (p *Polynomial[FR]) EvalUnivariate(P Univariate[FR], at *emulated.Element[FR]) *emulated.Element[FR] {
	res := p.f.Zero()
	for i := len(P) - 1; i > 0; i-- {
		res = p.f.Add(res, P[i])
		res = p.f.Mul(res, at)
	}
	res = p.f.Add(res, P[0])
	return res
}

func (p *Polynomial[FR]) EvalMultilinear(M Multilinear[FR], at []*emulated.Element[FR]) (*emulated.Element[FR], error) {
	var s *emulated.Element[FR]
	scaleCorrectionFactor := p.f.One()
	for len(M) > 1 {
		if len(M) >= minFoldScaledLogSize {
			M, s = p.foldScaled(M, at[0])
			scaleCorrectionFactor = p.f.Mul(scaleCorrectionFactor, s)
		} else {
			M = p.fold(M, at[0])
		}
		at = at[1:]
	}
	if len(at) != 0 {
		return nil, fmt.Errorf("incompatible evaluation vector size")
	}
	return p.f.Mul(M[0], scaleCorrectionFactor), nil
}

func (p *Polynomial[FR]) fold(M Multilinear[FR], at *emulated.Element[FR]) Multilinear[FR] {
	mid := len(M) / 2
	R := make([]*emulated.Element[FR], mid)
	for j := range R {
		diff := p.f.Sub(M[mid+j], M[j])
		diffAt := p.f.Mul(diff, at)
		R[j] = p.f.Add(M[j], diffAt)
	}
	return R
}

func (p *Polynomial[FR]) foldScaled(M Multilinear[FR], at *emulated.Element[FR]) (Multilinear[FR], *emulated.Element[FR]) {
	denom := p.f.Sub(p.f.One(), at)
	coeff := p.f.Div(at, denom)
	mid := len(M) / 2
	R := make([]*emulated.Element[FR], mid)
	for j := range R {
		tmp := p.f.Mul(M[j], coeff)
		R[j] = p.f.Add(M[j], tmp)
	}
	return R, denom
}

func (p *Polynomial[FR]) computeDeltaAtNaive(at *emulated.Element[FR], vLen int) []*emulated.Element[FR] {
	deltaAt := make([]*emulated.Element[FR], vLen)
	atMinus := make([]*emulated.Element[FR], vLen)
	for i := range atMinus {
		atMinus[i] = p.f.Sub(at, p.f.NewElement(i))
	}
	factInv := p.invNegFactorial(vLen - 1)
	factInvE := p.f.NewElement(factInv)

	for i := range deltaAt {
		deltaAt[i] = factInvE
		for j := range atMinus {
			if i != j {
				deltaAt[i] = p.f.Mul(deltaAt[i], atMinus[j])
			}
		}
		if i+1 < len(deltaAt) {
			factInv = p.adjustFactorial(factInv, i, vLen)
			factInvE = p.f.NewElement(factInv)
		}
	}
	return deltaAt
}

func (p *Polynomial[FR]) InterpolateLDE(at *emulated.Element[FR], values []*emulated.Element[FR]) *emulated.Element[FR] {
	deltaAt := p.computeDeltaAtNaive(at, len(values))
	res := p.f.Zero()
	for i, c := range values {
		tmp := p.f.Mul(c, deltaAt[i])
		res = p.f.Add(res, tmp)
	}
	return res
}

func (p *Polynomial[FR]) EvalEqual(x, y []*emulated.Element[FR]) *emulated.Element[FR] {
	eq := p.f.One()
	one := p.f.One()
	for i := range x {
		next := p.f.Mul(x[i], y[i])
		next = p.f.Add(next, next)
		next = p.f.Add(next, one)
		next = p.f.Sub(next, x[i])
		next = p.f.Sub(next, y[i])
		eq = p.f.Mul(eq, next)
	}
	return eq
}

// negFactorial returns 1/(-n)(-n+1)...(-2)(-1)
func (p *Polynomial[FR]) invNegFactorial(n int) *big.Int {
	var fr FR

	res := -1
	for i := 2; i <= n; i++ {
		res *= -i
	}
	denom := big.NewInt(int64(res))
	return new(big.Int).ModInverse(denom, fr.Modulus())
}

func (p *Polynomial[FR]) adjustFactorial(factInv *big.Int, i int, vLen int) *big.Int {
	var fr FR
	nom := big.NewInt(int64(i + 1 - vLen))
	nom.Mul(nom, factInv)
	denom := big.NewInt(int64(i + 1))
	denom.ModInverse(denom, fr.Modulus())
	nom.Mul(nom, denom)
	nom.Mod(nom, fr.Modulus())
	return nom
}