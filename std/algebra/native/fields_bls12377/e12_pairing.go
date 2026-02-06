package fields_bls12377

import (
	"github.com/consensys/gnark/frontend"
)

// nSquareKarabina2345 repeated compressed cyclotmic square
func (e *E12) nSquareKarabina2345(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareKarabina2345(api, *e)
	}
	e.DecompressKarabina2345(api, *e)
}

// nSquareKarabina12345 repeated compressed cyclotmic square
func (e *E12) nSquareKarabina12345(api frontend.API, n int) {
	for i := 0; i < n; i++ {
		e.CyclotomicSquareKarabina12345(api, *e)
	}
	e.DecompressKarabina12345(api, *e)
}

// Square034 squares a sparse element in Fp12
func (e *E12) Square034(api frontend.API, x E12) *E12 {
	var c0, c2, c3 E6

	c0.B0.Sub(api, x.C0.B0, x.C1.B0)
	c0.B1.Neg(api, x.C1.B1)

	c3.B0 = x.C0.B0
	c3.B1.Neg(api, x.C1.B0)
	c3.B2.Neg(api, x.C1.B1)

	c2.Mul0By01(api, x.C0.B0, x.C1.B0, x.C1.B1)
	c3.MulBy01(api, c0.B0, c0.B1)
	c3.B0.Add(api, c3.B0, c2.B0)
	c3.B1.Add(api, c3.B1, c2.B1)
	e.C1.B0.MulByFp(api, c2.B0, 2)
	e.C1.B1.MulByFp(api, c2.B1, 2)

	e.C0.B0 = c3.B0
	e.C0.B1.Add(api, c3.B1, c2.B0)
	e.C0.B2.Add(api, c3.B2, c2.B1)

	return e
}

// MulBy034 multiplication by sparse element
func (e *E12) MulBy034(api frontend.API, c3, c4 E2) *E12 {

	var d E6

	a := e.C0
	b := e.C1

	b.MulBy01(api, c3, c4)
	c3.A0 = api.Add(1, c3.A0)
	d.Add(api, e.C0, e.C1)
	d.MulBy01(api, c3, c4)

	e.C1.Add(api, a, b).Neg(api, e.C1).Add(api, e.C1, d)
	e.C0.MulByNonResidue(api, b).Add(api, e.C0, a)

	return e
}

// Mul034By034 multiplication of sparse element (1,0,0,c3,c4,0) by sparse element (1,0,0,d3,d4,0)
func Mul034By034(api frontend.API, d3, d4, c3, c4 E2) *[5]E2 {
	var tmp, x00, x3, x4, x04, x03, x34 E2
	x3.Mul(api, c3, d3)
	x4.Mul(api, c4, d4)
	x04.Add(api, c4, d4)
	x03.Add(api, c3, d3)
	tmp.Add(api, c3, c4)
	x34.Add(api, d3, d4).
		Mul(api, x34, tmp).
		Sub(api, x34, x3).
		Sub(api, x34, x4)

	x00.MulByNonResidue(api, x4)
	x00.A0 = api.Add(x00.A0, 1)

	return &[5]E2{x00, x3, x34, x03, x04}
}

func Mul01234By034(api frontend.API, x [5]E2, z3, z4 E2) *E12 {
	var a, b, z1, z0 E6
	c0 := &E6{B0: x[0], B1: x[1], B2: x[2]}
	a.B0.A0 = api.Add(z3.A0, 1)
	a.B0.A1 = z3.A1
	a.B1 = z4
	a.B2.A0 = 0
	a.B2.A1 = 0
	b.B0.Add(api, c0.B0, x[3])
	b.B1.Add(api, c0.B1, x[4])
	b.B2 = c0.B2
	b.MulBy01(api, a.B0, a.B1)
	c := *Mul01By01(api, z3, z4, x[3], x[4])
	z1.Sub(api, b, *c0)
	z1.Sub(api, z1, c)
	z0.MulByNonResidue(api, c)
	z0.Add(api, z0, *c0)
	return &E12{
		C0: z0,
		C1: z1,
	}
}

func (e *E12) MulBy01234(api frontend.API, x [5]E2) *E12 {
	var a, b, c, z1, z0 E6
	c0 := &E6{B0: x[0], B1: x[1], B2: x[2]}
	a.Add(api, e.C0, e.C1)
	b.B0.Add(api, x[0], x[3])
	b.B1.Add(api, x[1], x[4])
	b.B2 = x[2]
	a.Mul(api, a, b)
	b.Mul(api, e.C0, *c0)
	c = e.C1
	c.MulBy01(api, x[3], x[4])
	z1.Sub(api, a, b)
	z1.Sub(api, z1, c)
	z0.MulByNonResidue(api, c)
	z0.Add(api, z0, b)

	e.C0 = z0
	e.C1 = z1
	return e
}

// ExpX0 compute e1^X0, where X0=0x8508c00000000001
func (e *E12) ExpX0(api frontend.API, e1 E12) *E12 {

	res := e1

	res.nSquareKarabina2345(api, 5)
	res.Mul(api, res, e1)
	x33 := res
	res.nSquareKarabina2345(api, 7)
	res.Mul(api, res, x33)
	res.nSquareKarabina2345(api, 4)
	res.Mul(api, res, e1)
	res.CyclotomicSquare(api, res)
	res.Mul(api, res, e1)
	res.nSquareKarabina2345(api, 46)
	res.Mul(api, res, e1)

	*e = res

	return e

}

// ExpX0Minus1Square computes e1^((X0-1)^2), where X0=0x8508c00000000001
func (e *E12) ExpX0Minus1Square(api frontend.API, e1 E12) *E12 {

	var t0, t1, t2, t3, res E12

	res = e1
	res.nSquareKarabina12345(api, 3)
	t0.CyclotomicSquare(api, res)
	t2.Mul(api, e1, t0)
	res.Mul(api, res, t2)
	t0.Mul(api, e1, res)
	t1.CyclotomicSquare(api, t0)
	t1.Mul(api, t2, t1)
	t3 = t1
	t3.nSquareKarabina2345(api, 7)
	t2.Mul(api, t2, t3)
	t2.nSquareKarabina2345(api, 11)
	t1.Mul(api, t1, t2)
	t0.Mul(api, t0, t1)
	t0.nSquareKarabina2345(api, 7)
	res.Mul(api, res, t0)
	res.nSquareKarabina12345(api, 3)
	e.Mul(api, e1, res)
	e.nSquareKarabina2345(api, 92)

	return e

}

// ExpU compute e1^U, where U=(X0-1)^2/3 and X0=0x8508c00000000001
func (e *E12) ExpU(api frontend.API, e1 E12) *E12 {

	var t0, t1, t2, t3 E12
	t0.CyclotomicSquare(api, e1)
	e.Mul(api, e1, t0)
	t0.Mul(api, t0, *e)
	t1.CyclotomicSquare(api, t0)
	t2.Mul(api, e1, t1)
	t1.CyclotomicSquare(api, t2)
	t1.Mul(api, e1, t1)
	t3.CyclotomicSquare(api, t1)
	t3.nSquareKarabina2345(api, 7)
	t2.Mul(api, t2, t3)
	t2.nSquareKarabina2345(api, 6)
	t1.Mul(api, t1, t2)
	t1.nSquareKarabina2345(api, 4)
	t0.Mul(api, t0, t1)
	t0.nSquareKarabina2345(api, 4)
	t0.Mul(api, e1, t0)
	t0.nSquareKarabina2345(api, 6)
	e.Mul(api, *e, t0)
	e.nSquareKarabina2345(api, 92)

	return e
}

// Torus-based arithmetic for cyclotomic subgroup
// The torus T₆ represents elements of the cyclotomic subgroup of E12 using E6
// For x in cyclotomic subgroup: x = (1 + y·w) / (1 - y·w) where y ∈ E6

// TorusSquare computes the square in torus representation
// Input: y ∈ E6 representing x ∈ T₆
// Output: y' ∈ E6 representing x² ∈ T₆
// Formula: y' = 2y / (1 + y²·v) where v is the cubic non-residue
func TorusSquare(api frontend.API, y E6, hint E6) E6 {
	// Compute numerator: 2y
	var num E6
	num.Double(api, y)

	// Compute y²
	var ySq E6
	ySq.Square(api, y)

	// Compute denominator: 1 + y²·v
	var denom E6
	denom.MulByNonResidue(api, ySq)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusMul computes multiplication in torus representation
// Input: y1, y2 ∈ E6 representing x1, x2 ∈ T₆
// Output: y' ∈ E6 representing x1·x2 ∈ T₆
// Formula: y' = (y1 + y2) / (1 + y1·y2·v)
func TorusMul(api frontend.API, y1, y2 E6, hint E6) E6 {
	// Compute numerator: y1 + y2
	var num E6
	num.Add(api, y1, y2)

	// Compute y1·y2
	var prod E6
	prod.Mul(api, y1, y2)

	// Compute denominator: 1 + y1·y2·v
	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusMulBy01 computes multiplication by sparse element (y0, y1, 0) in torus
// This is used for line multiplication where the line projects to (-c3, -c4, 0)
func TorusMulBy01(api frontend.API, y E6, l0, l1 E2, hint E6) E6 {
	// Sparse element: (l0, l1, 0)
	var sparse E6
	sparse.B0 = l0
	sparse.B1 = l1
	// B2 is zero - must be explicit circuit zero
	sparse.B2.A0 = 0
	sparse.B2.A1 = 0

	// Compute numerator: y + sparse
	var num E6
	num.Add(api, y, sparse)

	// Compute y · sparse using MulBy01
	var prod E6
	prod = y
	prod.MulBy01(api, l0, l1)

	// Compute denominator: 1 + prod·v
	var denom E6
	denom.MulByNonResidue(api, prod)
	denom.B0.A0 = api.Add(denom.B0.A0, 1)

	// Verify: hint · denom = num
	var check E6
	check.Mul(api, hint, denom)
	check.AssertIsEqual(api, num)

	return hint
}

// TorusSquareWithHint computes the square in torus representation using hints
func TorusSquareWithHint(api frontend.API, y E6) E6 {
	// Get hint for result
	res, err := api.NewHint(torusSquareHint, 6,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusSquare(api, y, hint)
}

// TorusMulWithHint computes multiplication of two dense elements in torus using hints
func TorusMulWithHint(api frontend.API, y1, y2 E6) E6 {
	// Get hint for result
	res, err := api.NewHint(torusMulHint, 6,
		y1.B0.A0, y1.B0.A1, y1.B1.A0, y1.B1.A1, y1.B2.A0, y1.B2.A1,
		y2.B0.A0, y2.B0.A1, y2.B1.A0, y2.B1.A1, y2.B2.A0, y2.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusMul(api, y1, y2, hint)
}

// TorusMulBy01WithHint computes multiplication by sparse element using hints
func TorusMulBy01WithHint(api frontend.API, y E6, l0, l1 E2) E6 {
	// Get hint for result
	res, err := api.NewHint(torusMulBy01Hint, 6,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1,
		l0.A0, l0.A1, l1.A0, l1.A1)
	if err != nil {
		panic(err)
	}
	var hint E6
	hint.B0.A0 = res[0]
	hint.B0.A1 = res[1]
	hint.B1.A0 = res[2]
	hint.B1.A1 = res[3]
	hint.B2.A0 = res[4]
	hint.B2.A1 = res[5]

	return TorusMulBy01(api, y, l0, l1, hint)
}

// TorusDecompressWithHint converts torus representation back to E12 using hints
func TorusDecompressWithHint(api frontend.API, y E6) E12 {
	// Get hint for result
	res, err := api.NewHint(torusDecompressHint, 12,
		y.B0.A0, y.B0.A1, y.B1.A0, y.B1.A1, y.B2.A0, y.B2.A1)
	if err != nil {
		panic(err)
	}
	var hint E12
	hint.C0.B0.A0 = res[0]
	hint.C0.B0.A1 = res[1]
	hint.C0.B1.A0 = res[2]
	hint.C0.B1.A1 = res[3]
	hint.C0.B2.A0 = res[4]
	hint.C0.B2.A1 = res[5]
	hint.C1.B0.A0 = res[6]
	hint.C1.B0.A1 = res[7]
	hint.C1.B1.A0 = res[8]
	hint.C1.B1.A1 = res[9]
	hint.C1.B2.A0 = res[10]
	hint.C1.B2.A1 = res[11]

	return TorusDecompress(api, y, hint)
}

// TorusDecompress converts torus representation back to E12
// Input: y ∈ E6 representing x ∈ T₆
// Output: x ∈ E12 where x = (1 + y·w) / (1 - y·w)
// Verification: x · (1 - y·w) = (1 + y·w)
func TorusDecompress(api frontend.API, y E6, hint E12) E12 {
	// Verify: hint · (1 - y·w) = (1 + y·w)
	// (a + b·w) · (1 - y·w) = a - b·y·v + (b - a·y)·w
	// Should equal (1 + y·w), so:
	// a - b·y·v = 1
	// b - a·y = y

	// Compute hint.C0 - hint.C1·y·v
	var tmp E6
	tmp.Mul(api, hint.C1, y)
	tmp.MulByNonResidue(api, tmp)

	var lhs0 E6
	lhs0.Sub(api, hint.C0, tmp)

	// Compute hint.C1 - hint.C0·y
	var tmp2 E6
	tmp2.Mul(api, hint.C0, y)

	var lhs1 E6
	lhs1.Sub(api, hint.C1, tmp2)

	// Check lhs0 = 1
	var one E6
	one.SetOne()
	lhs0.AssertIsEqual(api, one)

	// Check lhs1 = y
	lhs1.AssertIsEqual(api, y)

	return hint
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method follows Section 4 of [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (e *E12) AssertFinalExponentiationIsOne(api frontend.API) {
	res, err := api.NewHint(finalExpHint, 18, e.C0.B0.A0, e.C0.B0.A1, e.C0.B1.A0, e.C0.B1.A1, e.C0.B2.A0, e.C0.B2.A1, e.C1.B0.A0, e.C1.B0.A1, e.C1.B1.A0, e.C1.B1.A1, e.C1.B2.A0, e.C1.B2.A1)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	var residueWitness, t0, t1 E12
	var scalingFactor E6
	residueWitness.assign(res[:12])
	// constrain cubicNonResiduePower to be in Fp6
	scalingFactor.B0.A0 = res[12]
	scalingFactor.B0.A1 = res[13]
	scalingFactor.B1.A0 = res[14]
	scalingFactor.B1.A1 = res[15]
	scalingFactor.B2.A0 = res[16]
	scalingFactor.B2.A1 = res[17]

	// Check that  x * scalingFactor == residueWitness^(q-u)
	// where u=0x8508c00000000001 is the BLS12-377 seed,
	// and residueWitness, scalingFactor from the hint.
	t0.Frobenius(api, residueWitness)
	// exponentiation by u
	t1.ExpX0(api, residueWitness)
	t0.DivUnchecked(api, t0, t1)

	t1.C0.Mul(api, e.C0, scalingFactor)
	t1.C1.Mul(api, e.C1, scalingFactor)

	t0.AssertIsEqual(api, t1)
}
