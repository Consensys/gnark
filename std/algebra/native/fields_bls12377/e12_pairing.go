package fields_bls12377

import "github.com/consensys/gnark/frontend"

// MulBy034 multiplication by sparse element
func (e *E12) MulBy034(api frontend.API, c3, c4 E2) *E12 {

	var d E6

	a := e.C0
	b := e.C1

	b.MulBy01(api, c3, c4)

	c3.Add(api, E2{A0: 1, A1: 0}, c3)
	d.Add(api, e.C0, e.C1)
	d.MulBy01(api, c3, c4)

	e.C1.Add(api, a, b).Neg(api, e.C1).Add(api, e.C1, d)
	e.C0.MulByNonResidue(api, b).Add(api, e.C0, a)

	return e
}

// Mul034By034 multiplication of sparse element (1,0,0,c3,c4,0) by sparse element (1,0,0,d3,d4,0)
func (e *E12) Mul034By034(api frontend.API, d3, d4, c3, c4 E2) *E12 {
	var one, tmp, x3, x4, x04, x03, x34 E2
	one.SetOne()
	x3.Mul(api, c3, d3)
	x4.Mul(api, c4, d4)
	x04.Add(api, c4, d4)
	x03.Add(api, c3, d3)
	tmp.Add(api, c3, c4)
	x34.Add(api, d3, d4).
		Mul(api, x34, tmp).
		Sub(api, x34, x3).
		Sub(api, x34, x4)

	e.C0.B0.MulByNonResidue(api, x4).
		Add(api, e.C0.B0, one)
	e.C0.B1 = x3
	e.C0.B2 = x34
	e.C1.B0 = x03
	e.C1.B1 = x04
	e.C1.B2.SetZero()

	return e
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls12377, so the exponent is supposed to be hardcoded
// and on 64 bits.
func (e *E12) Expt(api frontend.API, e1 E12, exponent uint64) *E12 {

	res := e1

	res.nSquareCompressed(api, 5)
	res.Decompress(api, res)
	res.Mul(api, res, e1)
	x33 := res
	res.nSquareCompressed(api, 7)
	res.Decompress(api, res)
	res.Mul(api, res, x33)
	res.nSquareCompressed(api, 4)
	res.Decompress(api, res)
	res.Mul(api, res, e1)
	res.CyclotomicSquare(api, res)
	res.Mul(api, res, e1)
	res.nSquareCompressed(api, 46)
	res.Decompress(api, res)
	res.Mul(api, res, e1)

	*e = res

	return e

}
