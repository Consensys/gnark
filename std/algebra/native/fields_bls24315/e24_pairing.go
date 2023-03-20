package fields_bls24315

import "github.com/consensys/gnark/frontend"

// MulBy034 multiplication by sparse element
func (e *E24) MulBy034(api frontend.API, c3, c4 E4) *E24 {

	var d E12
	var one E4
	one.SetOne()

	a := e.D0
	b := e.D1

	b.MulBy01(api, c3, c4)

	c3.Add(api, one, c3)
	d.Add(api, e.D0, e.D1)
	d.MulBy01(api, c3, c4)

	e.D1.Add(api, a, b).Neg(api, e.D1).Add(api, e.D1, d)
	e.D0.MulByNonResidue(api, b).Add(api, e.D0, a)

	return e
}

// Mul034By034 multiplication of sparse element (1,0,0,c3,c4,0) by sparse element (1,0,0,d3,d4,0)
func (e *E24) Mul034By034(api frontend.API, d3, d4, c3, c4 E4) *E24 {
	var one, tmp, x3, x4, x04, x03, x34 E4
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

	e.D0.C0.MulByNonResidue(api, x4).
		Add(api, e.D0.C0, one)
	e.D0.C1 = x3
	e.D0.C2 = x34
	e.D1.C0 = x03
	e.D1.C1 = x04
	e.D1.C2.SetZero()

	return e
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls24315, so the exponent is supposed to be hardcoded and on 32 bits.
func (e *E24) Expt(api frontend.API, x E24, exponent uint64) *E24 {

	xInv := E24{}
	res := x
	xInv.Conjugate(api, x)

	res.nSquare(api, 2)
	res.Mul(api, res, xInv)
	res.nSquareCompressed(api, 8)
	res.Decompress(api, res)
	res.Mul(api, res, xInv)
	res.nSquare(api, 2)
	res.Mul(api, res, x)
	res.nSquareCompressed(api, 20)
	res.Decompress(api, res)
	res.Mul(api, res, xInv)
	res.Conjugate(api, res)

	*e = res

	return e
}
