package fields_bls12377

import (
	"fmt"
	"math/big"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fp"
	"github.com/consensys/gnark/frontend"
)

// Schwartz-Zippel based E12 multiplication for SCS.
//
// Instead of computing c = a * b via the Karatsuba tower (~264 SCS gates),
// the prover witnesses c and a quotient polynomial q via a hint, then verifies:
//
//	a(r) * b(r) = q(r) * P(r) + c(r)   in Fp
//
// where P(X) = X^12 + 5 is the irreducible polynomial for Fp12 over Fp, and r
// is a Fiat-Shamir challenge from multicommit.WithCommitment.
//
// BLS12-377's base field is ~377 bits, so a single Fp evaluation point gives
// ~372 bits of soundness (deg(a*b)/p = 22/p ≈ 2^{-372}), well above 128 bits.
//
// The exact SCS cost depends on commitment inputs and batching; see the
// constraint-count tests for current numbers.

// towerToMonomial12 reorders tower-basis coefficients to monomial-basis.
//
// Tower basis: {1, u, v, uv, v², uv², w, uw, vw, uvw, v²w, uv²w}
// where u²=-5, v³=u, w²=v. With w=X: u=X⁶, v=X², w=X.
//
//	tower[0]=1     → X⁰    tower[6]=w     → X¹
//	tower[2]=v     → X²    tower[8]=vw    → X³
//	tower[4]=v²    → X⁴    tower[10]=v²w  → X⁵
//	tower[1]=u     → X⁶    tower[7]=uw    → X⁷
//	tower[3]=uv    → X⁸    tower[9]=uvw   → X⁹
//	tower[5]=uv²   → X¹⁰   tower[11]=uv²w → X¹¹
func towerToMonomial12(t [12]frontend.Variable) [12]frontend.Variable {
	return [12]frontend.Variable{
		t[0], t[6], t[2], t[8], t[4], t[10],
		t[1], t[7], t[3], t[9], t[5], t[11],
	}
}

// e12Coeffs returns the 12 tower-basis coefficients of an E12 element.
func e12Coeffs(e *E12) [12]frontend.Variable {
	return [12]frontend.Variable{
		e.C0.B0.A0, e.C0.B0.A1, e.C0.B1.A0, e.C0.B1.A1, e.C0.B2.A0, e.C0.B2.A1,
		e.C1.B0.A0, e.C1.B0.A1, e.C1.B1.A0, e.C1.B1.A1, e.C1.B2.A0, e.C1.B2.A1,
	}
}

// assignE12 sets the 12 tower-basis coefficients of an E12 element.
func assignE12(e *E12, v []frontend.Variable) {
	e.C0.B0.A0, e.C0.B0.A1 = v[0], v[1]
	e.C0.B1.A0, e.C0.B1.A1 = v[2], v[3]
	e.C0.B2.A0, e.C0.B2.A1 = v[4], v[5]
	e.C1.B0.A0, e.C1.B0.A1 = v[6], v[7]
	e.C1.B1.A0, e.C1.B1.A1 = v[8], v[9]
	e.C1.B2.A0, e.C1.B2.A1 = v[10], v[11]
}

// mulBy034E12SZHint computes c = a * sparse(1,0,0,c3,c4,0) in Fp12 and the
// quotient q such that a(X)*b(X) = q(X)*(X^12+5) + c(X) in Fp[X].
//
// inputs:  16 big.Ints (12 for a in tower, 2 for c3, 2 for c4)
// outputs: 23 big.Ints (12 for c in tower, 11 for q in monomial)
func mulBy034E12SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 16 {
		return fmt.Errorf("mulBy034E12SZHint: expected 16 inputs, got %d", len(inputs))
	}
	if len(outputs) != 23 {
		return fmt.Errorf("mulBy034E12SZHint: expected 23 outputs, got %d", len(outputs))
	}

	var a, b, c bls12377.E12
	setNativeE12(&a, inputs[:12])
	// b = (1, 0, 0, c3, c4, 0) in tower form
	b.C0.B0.SetOne()
	b.C1.B0.A0.SetBigInt(inputs[12])
	b.C1.B0.A1.SetBigInt(inputs[13])
	b.C1.B1.A0.SetBigInt(inputs[14])
	b.C1.B1.A1.SetBigInt(inputs[15])
	c.Mul(&a, &b)

	getNativeE12(&c, outputs[:12])

	q := e12SZQuotient(e12TowerToMonomialFpElement(&a), e12TowerToMonomialFpElement(&b))
	for i := 0; i < 11; i++ {
		q[i].BigInt(outputs[12+i])
	}
	return nil
}

// mulE12SZHint computes c = a*b in Fp12 and the quotient q such that
// a(X)*b(X) = q(X)*(X^12+5) + c(X) in Fp[X].
//
// inputs:  24 big.Ints (12 for a, 12 for b, both in tower basis)
// outputs: 23 big.Ints (12 for c in tower basis, 11 for q in monomial basis)
func mulE12SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 24 {
		return fmt.Errorf("mulE12SZHint: expected 24 inputs, got %d", len(inputs))
	}
	if len(outputs) != 23 {
		return fmt.Errorf("mulE12SZHint: expected 23 outputs, got %d", len(outputs))
	}

	var a, b, c bls12377.E12
	setNativeE12(&a, inputs[:12])
	setNativeE12(&b, inputs[12:])
	c.Mul(&a, &b)

	// output c in tower basis (first 12 outputs)
	getNativeE12(&c, outputs[:12])

	q := e12SZQuotient(e12TowerToMonomialFpElement(&a), e12TowerToMonomialFpElement(&b))
	// output q in monomial basis (last 11 outputs)
	for i := 0; i < 11; i++ {
		q[i].BigInt(outputs[12+i])
	}
	return nil
}

// squareE12SZHint computes c = a² in Fp12 and the quotient q such that
// a(X)² = q(X)*(X^12+5) + c(X) in Fp[X].
//
// inputs:  12 big.Ints (a in tower basis)
// outputs: 23 big.Ints (12 for c in tower basis, 11 for q in monomial basis)
func squareE12SZHint(_ *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	if len(inputs) != 12 {
		return fmt.Errorf("squareE12SZHint: expected 12 inputs, got %d", len(inputs))
	}
	if len(outputs) != 23 {
		return fmt.Errorf("squareE12SZHint: expected 23 outputs, got %d", len(outputs))
	}

	var a, c bls12377.E12
	setNativeE12(&a, inputs)
	c.Square(&a)

	getNativeE12(&c, outputs[:12])

	aMono := e12TowerToMonomialFpElement(&a)
	q := e12SZQuotient(aMono, aMono)
	for i := 0; i < 11; i++ {
		q[i].BigInt(outputs[12+i])
	}
	return nil
}

func e12SZQuotient(aMono, bMono [12]fp.Element) [11]fp.Element {
	var prod [23]fp.Element
	for i := 0; i < 12; i++ {
		for j := 0; j < 12; j++ {
			var t fp.Element
			t.Mul(&aMono[i], &bMono[j])
			prod[i+j].Add(&prod[i+j], &t)
		}
	}

	var five fp.Element
	five.SetUint64(5)
	var q [11]fp.Element
	// Compute q such that a*b = c + q*(X^12+5).
	for i := 10; i >= 0; i-- {
		q[i].Set(&prod[i+12])
		var t fp.Element
		t.Mul(&q[i], &five)
		prod[i].Sub(&prod[i], &t)
	}
	return q
}

func setNativeE12(dst *bls12377.E12, inputs []*big.Int) {
	dst.C0.B0.A0.SetBigInt(inputs[0])
	dst.C0.B0.A1.SetBigInt(inputs[1])
	dst.C0.B1.A0.SetBigInt(inputs[2])
	dst.C0.B1.A1.SetBigInt(inputs[3])
	dst.C0.B2.A0.SetBigInt(inputs[4])
	dst.C0.B2.A1.SetBigInt(inputs[5])
	dst.C1.B0.A0.SetBigInt(inputs[6])
	dst.C1.B0.A1.SetBigInt(inputs[7])
	dst.C1.B1.A0.SetBigInt(inputs[8])
	dst.C1.B1.A1.SetBigInt(inputs[9])
	dst.C1.B2.A0.SetBigInt(inputs[10])
	dst.C1.B2.A1.SetBigInt(inputs[11])
}

func getNativeE12(src *bls12377.E12, outputs []*big.Int) {
	src.C0.B0.A0.BigInt(outputs[0])
	src.C0.B0.A1.BigInt(outputs[1])
	src.C0.B1.A0.BigInt(outputs[2])
	src.C0.B1.A1.BigInt(outputs[3])
	src.C0.B2.A0.BigInt(outputs[4])
	src.C0.B2.A1.BigInt(outputs[5])
	src.C1.B0.A0.BigInt(outputs[6])
	src.C1.B0.A1.BigInt(outputs[7])
	src.C1.B1.A0.BigInt(outputs[8])
	src.C1.B1.A1.BigInt(outputs[9])
	src.C1.B2.A0.BigInt(outputs[10])
	src.C1.B2.A1.BigInt(outputs[11])
}

// e12TowerToMonomialFpElement converts tower-basis E12 to monomial-basis elements.
func e12TowerToMonomialFpElement(e *bls12377.E12) [12]fp.Element {
	// permutation: mono[degree] = tower[index]
	return [12]fp.Element{
		e.C0.B0.A0, e.C1.B0.A0, e.C0.B1.A0, e.C1.B1.A0, e.C0.B2.A0, e.C1.B2.A0,
		e.C0.B0.A1, e.C1.B0.A1, e.C0.B1.A1, e.C1.B1.A1, e.C0.B2.A1, e.C1.B2.A1,
	}
}
