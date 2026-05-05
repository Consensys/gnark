package fields_bls12377

import (
	"fmt"
	"math/big"
	"sync"

	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/multicommit"
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
// Gate cost: ~49 SCS gates per multiplication (vs ~264 for Karatsuba).

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

// e12MulCheck stores one deferred a*b=c check in monomial form.
type e12MulCheck struct {
	a, b, c    [12]frontend.Variable // monomial coefficients (degree 11)
	q          [11]frontend.Variable // quotient monomial coefficients (degree 10)
	isSquare   bool                  // if true, b is ignored and a(r)² is checked
	bSparseIdx []int                 // if non-nil, only these indices of b are nonzero variables
	bConstIdx  []int                 // indices of b that are constants (e.g., 1)
}

// e12SZChecker accumulates E12 multiplication checks and resolves them
// in a single deferred callback using a shared Fiat-Shamir challenge.
type e12SZChecker struct {
	checks []e12MulCheck
}

var (
	e12szMu       sync.Mutex
	e12szCheckers = map[frontend.Compiler]*e12SZChecker{}
)

func getE12SZChecker(api frontend.API) *e12SZChecker {
	compiler := api.Compiler()

	e12szMu.Lock()
	ch, ok := e12szCheckers[compiler]
	if ok {
		e12szMu.Unlock()
		return ch
	}
	ch = &e12SZChecker{}
	e12szCheckers[compiler] = ch
	e12szMu.Unlock()

	compiler.Defer(func(api frontend.API) error {
		defer func() {
			e12szMu.Lock()
			delete(e12szCheckers, compiler)
			e12szMu.Unlock()
		}()
		return ch.resolve(api)
	})
	return ch
}

func (ch *e12SZChecker) addCheck(a, b, c [12]frontend.Variable, q [11]frontend.Variable) {
	ch.checks = append(ch.checks, e12MulCheck{a: a, b: b, c: c, q: q, isSquare: false})
}

func (ch *e12SZChecker) addSquareCheck(a, c [12]frontend.Variable, q [11]frontend.Variable) {
	ch.checks = append(ch.checks, e12MulCheck{a: a, c: c, q: q, isSquare: true})
}

// addSparseCheck registers a check where b has only some nonzero coefficients.
// sparseVarIdx: indices of b that are circuit variables
// sparseConstIdx: indices of b that are known constants (e.g., index 0 = 1 for MulBy034)
func (ch *e12SZChecker) addSparseCheck(a, b, c [12]frontend.Variable, q [11]frontend.Variable, sparseVarIdx, sparseConstIdx []int) {
	ch.checks = append(ch.checks, e12MulCheck{
		a: a, b: b, c: c, q: q,
		bSparseIdx: sparseVarIdx, bConstIdx: sparseConstIdx,
	})
}

// resolve performs all accumulated checks using a single commitment challenge.
func (ch *e12SZChecker) resolve(api frontend.API) error {
	if len(ch.checks) == 0 {
		return nil
	}

	var toCommit []frontend.Variable
	for i := range ch.checks {
		toCommit = append(toCommit, ch.checks[i].c[:]...)
		toCommit = append(toCommit, ch.checks[i].q[:]...)
	}

	// BLS12-377 is a large field — use plain WithCommitment (single Fp challenge).
	// Soundness: 22/p ≈ 2^{-372}.
	multicommit.WithCommitment(api, func(api frontend.API, commitment frontend.Variable) error {
		r := commitment

		// Precompute r², ..., r¹² (11 gates, shared across all checks)
		rPow := make([]frontend.Variable, 13)
		rPow[0] = frontend.Variable(1)
		rPow[1] = r
		for i := 2; i <= 12; i++ {
			rPow[i] = api.Mul(rPow[i-1], r)
		}

		// P(r) = r^12 + 5
		pEval := api.Add(rPow[12], 5)

		// Batching coefficient: r^23 ensures non-overlapping degree ranges (deg(e_i)=22)
		alpha := api.Mul(rPow[12], rPow[11]) // r^23

		lhsAcc := frontend.Variable(0)
		rhsAcc := frontend.Variable(0)
		alphaPow := frontend.Variable(1)

		for i := range ch.checks {
			chk := &ch.checks[i]

			aEval := evalAtPowers12(api, chk.a[:], rPow)
			var abEval frontend.Variable
			if chk.isSquare {
				abEval = api.Mul(aEval, aEval)
			} else if chk.bSparseIdx != nil {
				// sparse b: only evaluate nonzero terms
				bEval := evalSparse12(api, chk.b[:], rPow, chk.bSparseIdx, chk.bConstIdx)
				abEval = api.Mul(aEval, bEval)
			} else {
				bEval := evalAtPowers12(api, chk.b[:], rPow)
				abEval = api.Mul(aEval, bEval)
			}
			cEval := evalAtPowers12(api, chk.c[:], rPow)
			qEval := evalAtPowers12(api, chk.q[:], rPow)
			qpEval := api.Mul(qEval, pEval)
			rhs := api.Add(qpEval, cEval)

			lhsAcc = api.Add(lhsAcc, api.Mul(alphaPow, abEval))
			rhsAcc = api.Add(rhsAcc, api.Mul(alphaPow, rhs))

			if i < len(ch.checks)-1 {
				alphaPow = api.Mul(alphaPow, alpha)
			}
		}

		api.AssertIsEqual(lhsAcc, rhsAcc)
		return nil
	}, toCommit...)

	return nil
}

// evalAtPowers12 evaluates coeffs[0] + coeffs[1]*r + ... + coeffs[n-1]*r^(n-1)
// using precomputed powers.
func evalAtPowers12(api frontend.API, coeffs []frontend.Variable, rPow []frontend.Variable) frontend.Variable {
	result := coeffs[0]
	for i := 1; i < len(coeffs); i++ {
		result = api.Add(result, api.Mul(coeffs[i], rPow[i]))
	}
	return result
}

// evalSparse12 evaluates a polynomial where only some coefficients are nonzero.
// varIdx: indices with circuit variable coefficients (multiplication gate required)
// constIdx: indices with constant coefficients (scalar multiplication, no gate in SCS)
func evalSparse12(api frontend.API, coeffs []frontend.Variable, rPow []frontend.Variable, varIdx, constIdx []int) frontend.Variable {
	var result frontend.Variable = 0
	for _, i := range constIdx {
		result = api.Add(result, api.Mul(coeffs[i], rPow[i]))
	}
	for _, i := range varIdx {
		result = api.Add(result, api.Mul(coeffs[i], rPow[i]))
	}
	return result
}

// mulBy034E12SZHint computes c = a * sparse(1,0,0,c3,c4,0) in Fp12.
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

	aMono := e12TowerToMonomialBigInt(&a)
	bMono := e12TowerToMonomialBigInt(&b)

	p := bls12377.ID.BaseField()
	var prod [23]big.Int
	for i := 0; i < 12; i++ {
		for j := 0; j < 12; j++ {
			var t big.Int
			t.Mul(&aMono[i], &bMono[j])
			prod[i+j].Add(&prod[i+j], &t)
			prod[i+j].Mod(&prod[i+j], p)
		}
	}

	five := big.NewInt(5)
	var q [11]big.Int
	for i := 10; i >= 0; i-- {
		q[i].Set(&prod[i+12])
		q[i].Mod(&q[i], p)
		var t big.Int
		t.Mul(&q[i], five)
		prod[i].Sub(&prod[i], &t)
		prod[i].Mod(&prod[i], p)
	}

	for i := 0; i < 11; i++ {
		outputs[12+i].Set(&q[i])
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

	// convert a, b to monomial form for polynomial multiplication
	aMono := e12TowerToMonomialBigInt(&a)
	bMono := e12TowerToMonomialBigInt(&b)

	// polynomial multiply: prod = aMono * bMono (degree 22, 23 coefficients)
	p := bls12377.ID.BaseField()
	var prod [23]big.Int
	for i := 0; i < 12; i++ {
		for j := 0; j < 12; j++ {
			var t big.Int
			t.Mul(&aMono[i], &bMono[j])
			prod[i+j].Add(&prod[i+j], &t)
			prod[i+j].Mod(&prod[i+j], p)
		}
	}

	// divide by P(X) = X^12 + 5 (monic degree 12)
	// q[i] = prod[i+12] for i = 10..0, then fold: prod[i] += prod[i+12]*(-5)
	five := big.NewInt(5)
	var q [11]big.Int
	for i := 10; i >= 0; i-- {
		q[i].Set(&prod[i+12])
		q[i].Mod(&q[i], p)
		// subtract q[i] * 5 from prod[i] (since P = X^12 + 5, constant term is +5)
		var t big.Int
		t.Mul(&q[i], five)
		prod[i].Sub(&prod[i], &t)
		prod[i].Mod(&prod[i], p)
	}

	// output q in monomial basis (last 11 outputs)
	for i := 0; i < 11; i++ {
		outputs[12+i].Set(&q[i])
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

	aMono := e12TowerToMonomialBigInt(&a)

	p := bls12377.ID.BaseField()
	var prod [23]big.Int
	for i := 0; i < 12; i++ {
		for j := 0; j < 12; j++ {
			var t big.Int
			t.Mul(&aMono[i], &aMono[j])
			prod[i+j].Add(&prod[i+j], &t)
			prod[i+j].Mod(&prod[i+j], p)
		}
	}

	five := big.NewInt(5)
	var q [11]big.Int
	for i := 10; i >= 0; i-- {
		q[i].Set(&prod[i+12])
		q[i].Mod(&q[i], p)
		var t big.Int
		t.Mul(&q[i], five)
		prod[i].Sub(&prod[i], &t)
		prod[i].Mod(&prod[i], p)
	}

	for i := 0; i < 11; i++ {
		outputs[12+i].Set(&q[i])
	}
	return nil
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

// e12TowerToMonomialBigInt converts tower-basis E12 to monomial-basis big.Ints.
func e12TowerToMonomialBigInt(e *bls12377.E12) [12]big.Int {
	var tower [12]big.Int
	e.C0.B0.A0.BigInt(&tower[0])
	e.C0.B0.A1.BigInt(&tower[1])
	e.C0.B1.A0.BigInt(&tower[2])
	e.C0.B1.A1.BigInt(&tower[3])
	e.C0.B2.A0.BigInt(&tower[4])
	e.C0.B2.A1.BigInt(&tower[5])
	e.C1.B0.A0.BigInt(&tower[6])
	e.C1.B0.A1.BigInt(&tower[7])
	e.C1.B1.A0.BigInt(&tower[8])
	e.C1.B1.A1.BigInt(&tower[9])
	e.C1.B2.A0.BigInt(&tower[10])
	e.C1.B2.A1.BigInt(&tower[11])
	// permutation: mono[degree] = tower[index]
	return [12]big.Int{
		tower[0], tower[6], tower[2], tower[8], tower[4], tower[10],
		tower[1], tower[7], tower[3], tower[9], tower[5], tower[11],
	}
}
