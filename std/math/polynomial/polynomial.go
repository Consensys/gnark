package polynomial

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

var minFoldScaledLogSize = 16

// TODO: add also a type for the evaluation form of univariate polynomial.

// Univariate defines a univariate polynomial by its coefficients.
type Univariate[FR emulated.FieldParams] []emulated.Element[FR]

// TODO: give better package doc to Multilinear

// Multilinear defines a multivariate multilinear polynomial by its term
// coefficients.
type Multilinear[FR emulated.FieldParams] []emulated.Element[FR]

func valueOf[FR emulated.FieldParams](univ []*big.Int) []emulated.Element[FR] {
	ret := make([]emulated.Element[FR], len(univ))
	for i := range univ {
		r := emulated.ValueOf[FR](univ[i])
		ret[i] = r
	}
	return ret
}

// ValueOfUnivariate assigns [Univariate] variable.
func ValueOfUnivariate[FR emulated.FieldParams](univ []*big.Int) Univariate[FR] {
	return valueOf[FR](univ)
}

// ValueOfMultilinear assigns [Multilinear] variable.
func ValueOfMultilinear[FR emulated.FieldParams](ml []*big.Int) Multilinear[FR] {
	return valueOf[FR](ml)
}

// PlaceholderMultilinear returns empty variable for allocating variables during
// circuit compilation.
func PlaceholderMultilinear[FR emulated.FieldParams](nbVars int) Multilinear[FR] {
	return make(Multilinear[FR], 1<<nbVars)
}

// PlaceholderUnivariate returns empty variable for allocating variables during
// circuit compilation.
func PlaceholderUnivariate[FR emulated.FieldParams](length int) Univariate[FR] {
	return make(Univariate[FR], length)
}

// Polynomial is a non-native polynomial evaluator.
type Polynomial[FR emulated.FieldParams] struct {
	api frontend.API
	f   *emulated.Field[FR]
}

// FromSlice maps slice of emulated element values to their references.
func FromSlice[FR emulated.FieldParams](in []emulated.Element[FR]) []*emulated.Element[FR] {
	r := make([]*emulated.Element[FR], len(in))
	for i := range in {
		r[i] = &in[i]
	}
	return r
}

// FromSliceReferences maps slice of emulated element references to their values.
func FromSliceReferences[FR emulated.FieldParams](in []*emulated.Element[FR]) []emulated.Element[FR] {
	r := make([]emulated.Element[FR], len(in))
	for i := range in {
		r[i] = *in[i]
	}
	return r
}

// New returns new polynomial evaluator.
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

// EvalUnivariate evaluates univariate polynomial at a point at. It returns the
// evaluation. The method does not mutate the inputs.
func (p *Polynomial[FR]) EvalUnivariate(P Univariate[FR], at *emulated.Element[FR]) *emulated.Element[FR] {
	res := p.f.Zero()
	for i := len(P) - 1; i > 0; i-- {
		res = p.f.Add(res, &P[i])
		res = p.f.Mul(res, at)
	}
	res = p.f.Add(res, &P[0])
	return res
}

// EvalMultilinear evaluates multilinear polynomial at variable values at. It
// returns the evaluation. The method does not mutate the inputs.
func (p *Polynomial[FR]) EvalMultilinear(at []*emulated.Element[FR], M Multilinear[FR]) (*emulated.Element[FR], error) {
	ret, err := p.EvalMultilinearMany(at, M)
	if err != nil {
		return nil, err
	}
	return ret[0], nil
}

// EvalMultilinearMany evaluates multilinear polynomials at variable values at. It
// returns the evaluations. The method does not mutate the inputs.
//
// The method allows to share computations of computing the coefficients of the
// multilinear polynomials at the given evaluation points.
func (p *Polynomial[FR]) EvalMultilinearMany(at []*emulated.Element[FR], M ...Multilinear[FR]) ([]*emulated.Element[FR], error) {
	lenM := len(M[0])
	for i := range M {
		if len(M[i]) != lenM {
			return nil, fmt.Errorf("incompatible multilinear polynomial sizes")
		}
	}
	mlelems := make([][]*emulated.Element[FR], len(M))
	for i := range M {
		mlelems[i] = FromSlice(M[i])
	}
	if bits.OnesCount(uint(lenM)) != 1 {
		return nil, fmt.Errorf("multilinear polynomial length must be a power of 2")
	}
	nbExpvars := bits.Len(uint(lenM)) - 1
	if len(at) != nbExpvars {
		return nil, fmt.Errorf("incompatible evaluation vector size")
	}
	split1 := nbExpvars / 2
	nbSplit1Elems := 1 << split1
	split2 := nbExpvars - split1
	nbSplit2Elems := 1 << split2
	partialMLEval1 := p.partialMultilinearEval(at[:split1])
	partialMLEval2 := p.partialMultilinearEval(at[split1:])
	sums := make([]*emulated.Element[FR], len(M))
	for k := range mlelems {
		partialSums := make([]*emulated.Element[FR], nbSplit2Elems)
		for i := range partialSums {
			b := make([]*emulated.Element[FR], nbSplit1Elems)
			for j := range b {
				b[j] = mlelems[k][i+j*nbSplit2Elems]
			}
			partialSums[i] = p.innerProduct(b, partialMLEval1)
		}
		sums[k] = p.innerProduct(partialSums, partialMLEval2)
	}
	return sums, nil
}

func (p *Polynomial[FR]) partialMultilinearEval(at []*emulated.Element[FR]) []*emulated.Element[FR] {
	if len(at) == 0 {
		return []*emulated.Element[FR]{p.f.One()}
	}
	res := []*emulated.Element[FR]{p.f.Sub(p.f.One(), at[len(at)-1]), at[len(at)-1]}
	at = at[:len(at)-1]
	for len(at) > 0 {
		newRes := make([]*emulated.Element[FR], len(res)*2)
		x := at[len(at)-1]
		for j := range res {
			resX := p.f.Mul(res[j], x)
			newRes[j] = p.f.Sub(res[j], resX)
			newRes[j+len(res)] = resX
		}
		res = newRes
		at = at[:len(at)-1]
	}
	return res
}

func (p *Polynomial[FR]) innerProduct(a, b []*emulated.Element[FR]) *emulated.Element[FR] {
	if len(a) != len(b) {
		panic(fmt.Sprintf("incompatible sizes: %d and %d", len(a), len(b)))
	}
	muls := make([]*emulated.Element[FR], len(a))
	for i := range a {
		muls[i] = p.f.MulNoReduce(a[i], b[i])
	}
	res := p.f.Sum(muls...)
	return res
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

// InterpolateLDE returns the polynomial obtained by interpolating values at
// evaluation point at.
func (p *Polynomial[FR]) InterpolateLDE(at *emulated.Element[FR], values []*emulated.Element[FR]) *emulated.Element[FR] {
	deltaAt := p.computeDeltaAtNaive(at, len(values))
	res := p.f.Zero()
	for i, c := range values {
		tmp := p.f.Mul(c, deltaAt[i])
		res = p.f.Add(res, tmp)
	}
	return res
}

// EvalEquals returns the evaluation
//
//	eq(x, y) = \prod (1-x)*(1-y) + x*y,
//
// which for binary inputs x and y equals 1 only if x = y and 0 otherwise.
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
