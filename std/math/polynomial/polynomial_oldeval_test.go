package polynomial

import (
	"fmt"

	"github.com/consensys/gnark/std/math/emulated"
)

// evalMultilinearOld evaluates a multilinear polynomial at a given point.
// This is the old version of the function, which is kept for comparison purposes.
func (p *Polynomial[FR]) evalMultilinearOld(M Multilinear[FR], at []*emulated.Element[FR]) (*emulated.Element[FR], error) {
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
	return p.f.Mul(&M[0], scaleCorrectionFactor), nil
}

func (p *Polynomial[FR]) fold(M Multilinear[FR], at *emulated.Element[FR]) Multilinear[FR] {
	mid := len(M) / 2
	R := make([]emulated.Element[FR], mid)
	for j := range R {
		diff := p.f.Sub(&M[mid+j], &M[j])
		diffAt := p.f.Mul(diff, at)
		R[j] = *p.f.Add(&M[j], diffAt)
	}
	return R
}

func (p *Polynomial[FR]) foldScaled(M Multilinear[FR], at *emulated.Element[FR]) (Multilinear[FR], *emulated.Element[FR]) {
	denom := p.f.Sub(p.f.One(), at)
	coeff := p.f.Div(at, denom)
	mid := len(M) / 2
	R := make([]emulated.Element[FR], mid)
	for j := range R {
		tmp := p.f.Mul(&M[mid+j], coeff)
		R[j] = *p.f.Add(&M[j], tmp)
	}
	return R, denom
}
