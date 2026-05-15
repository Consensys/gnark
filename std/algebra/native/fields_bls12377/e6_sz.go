package fields_bls12377

import (
	"fmt"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/frontend"
)

// Schwartz-Zippel based E6 multiplication/squaring for SCS.
//
// P(X) = X^6 + 5 is the irreducible polynomial for Fp6 over Fp.
// Product degree: 10. Soundness: 10/p ≈ 2^{-373}.
//
// The exact SCS cost depends on commitment inputs and batching; see the
// constraint-count tests for current numbers.

// towerToMonomial6 reorders tower-basis E6 coefficients to monomial-basis.
//
// Tower basis: {1, u, v, uv, v², uv²} where u²=-5, v³=u.
// With v=X: u=X³.
//
//	tower[0]=1   → X⁰   tower[1]=u   → X³
//	tower[2]=v   → X¹   tower[3]=uv  → X⁴
//	tower[4]=v²  → X²   tower[5]=uv² → X⁵
func towerToMonomial6(t [6]frontend.Variable) [6]frontend.Variable {
	return [6]frontend.Variable{t[0], t[2], t[4], t[1], t[3], t[5]}
}

func e6Coeffs(e *E6) [6]frontend.Variable {
	return [6]frontend.Variable{
		e.B0.A0, e.B0.A1, e.B1.A0, e.B1.A1, e.B2.A0, e.B2.A1,
	}
}

func assignE6(e *E6, v []frontend.Variable) {
	e.B0.A0, e.B0.A1 = v[0], v[1]
	e.B1.A0, e.B1.A1 = v[2], v[3]
	e.B2.A0, e.B2.A1 = v[4], v[5]
}

// mulBy01E6SZHint computes c = a * sparse(c0, c1, 0) in Fp6 and the quotient q
// such that a(X)*b(X) = q(X)*(X^6+5) + c(X) in Fp[X].
// inputs: 10 (6 for a in tower, 2 for c0, 2 for c1)
// outputs: 11 (6 for c in tower, 5 for q in monomial)
func mulBy01E6SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 10 {
		return fmt.Errorf("mulBy01E6SZHint: expected 10 inputs, got %d", len(inputs))
	}
	if len(outputs) != 11 {
		return fmt.Errorf("mulBy01E6SZHint: expected 11 outputs, got %d", len(outputs))
	}

	var a, b, c bls12377.E6
	setNativeE6(&a, inputs[:6])
	b.B0.A0.SetBigInt(inputs[6])
	b.B0.A1.SetBigInt(inputs[7])
	b.B1.A0.SetBigInt(inputs[8])
	b.B1.A1.SetBigInt(inputs[9])
	// b.B2 = 0
	c.Mul(&a, &b)

	getNativeE6(&c, outputs[:6])

	q := e6SZQuotient(e6TowerToMonomialFpElement(&a), e6TowerToMonomialFpElement(&b))
	for i := 0; i < 5; i++ {
		q[i].BigInt(outputs[6+i])
	}
	return nil
}

// mulE6SZHint computes c = a*b in Fp6 and quotient q such that
// a(X)*b(X) = q(X)*(X^6+5) + c(X).
func mulE6SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 12 {
		return fmt.Errorf("mulE6SZHint: expected 12 inputs, got %d", len(inputs))
	}
	if len(outputs) != 11 {
		return fmt.Errorf("mulE6SZHint: expected 11 outputs, got %d", len(outputs))
	}

	var a, b, c bls12377.E6
	setNativeE6(&a, inputs[:6])
	setNativeE6(&b, inputs[6:])
	c.Mul(&a, &b)

	getNativeE6(&c, outputs[:6])

	q := e6SZQuotient(e6TowerToMonomialFpElement(&a), e6TowerToMonomialFpElement(&b))
	for i := 0; i < 5; i++ {
		q[i].BigInt(outputs[6+i])
	}
	return nil
}

// squareE6SZHint computes c = a² in Fp6 and the quotient q such that
// a(X)² = q(X)*(X^6+5) + c(X) in Fp[X].
func squareE6SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 6 {
		return fmt.Errorf("squareE6SZHint: expected 6 inputs, got %d", len(inputs))
	}
	if len(outputs) != 11 {
		return fmt.Errorf("squareE6SZHint: expected 11 outputs, got %d", len(outputs))
	}

	var a, c bls12377.E6
	setNativeE6(&a, inputs)
	c.Square(&a)

	getNativeE6(&c, outputs[:6])

	aMono := e6TowerToMonomialFpElement(&a)
	q := e6SZQuotient(aMono, aMono)
	for i := 0; i < 5; i++ {
		q[i].BigInt(outputs[6+i])
	}
	return nil
}

func e6SZQuotient(aMono, bMono [6]fp.Element) [5]fp.Element {
	var prod [11]fp.Element
	for i := 0; i < 6; i++ {
		for j := 0; j < 6; j++ {
			var t fp.Element
			t.Mul(&aMono[i], &bMono[j])
			prod[i+j].Add(&prod[i+j], &t)
		}
	}

	var five fp.Element
	five.SetUint64(5)
	var q [5]fp.Element
	// Compute q such that a*b = c + q*(X^6+5).
	for i := 4; i >= 0; i-- {
		q[i].Set(&prod[i+6])
		var t fp.Element
		t.Mul(&q[i], &five)
		prod[i].Sub(&prod[i], &t)
	}
	return q
}

func setNativeE6(dst *bls12377.E6, inputs []*big.Int) {
	dst.B0.A0.SetBigInt(inputs[0])
	dst.B0.A1.SetBigInt(inputs[1])
	dst.B1.A0.SetBigInt(inputs[2])
	dst.B1.A1.SetBigInt(inputs[3])
	dst.B2.A0.SetBigInt(inputs[4])
	dst.B2.A1.SetBigInt(inputs[5])
}

func getNativeE6(src *bls12377.E6, outputs []*big.Int) {
	src.B0.A0.BigInt(outputs[0])
	src.B0.A1.BigInt(outputs[1])
	src.B1.A0.BigInt(outputs[2])
	src.B1.A1.BigInt(outputs[3])
	src.B2.A0.BigInt(outputs[4])
	src.B2.A1.BigInt(outputs[5])
}

func e6TowerToMonomialFpElement(e *bls12377.E6) [6]fp.Element {
	// permutation: [t[0], t[2], t[4], t[1], t[3], t[5]]
	return [6]fp.Element{e.B0.A0, e.B1.A0, e.B2.A0, e.B0.A1, e.B1.A1, e.B2.A1}
}
