package fields_bls24315

import "github.com/consensys/gnark/frontend"

// Square034 squares a sparse element in Fp24
func (e *E24) Square034(api frontend.API, x E24) *E24 {
	var c0, c2, c3 E12

	c0.C0.Sub(api, x.D0.C0, x.D1.C0)
	c0.C1.Neg(api, x.D1.C1)
	c0.C2 = E4{E2{0, 0}, E2{0, 0}}

	c3.C0 = x.D0.C0
	c3.C1.Neg(api, x.D1.C0)
	c3.C2.Neg(api, x.D1.C1)

	c2.Mul0By01(api, x.D0.C0, x.D1.C0, x.D1.C1)
	c3.MulBy01(api, c0.C0, c0.C1).Add(api, c3, c2)
	e.D1.C0.Add(api, c2.C0, c2.C0)
	e.D1.C1.Add(api, c2.C1, c2.C1)

	e.D0.C0 = c3.C0
	e.D0.C1.Add(api, c3.C1, c2.C0)
	e.D0.C2.Add(api, c3.C2, c2.C1)

	return e
}

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
func Mul034By034(api frontend.API, d3, d4, c3, c4 E4) *[5]E4 {
	var one, tmp, x00, x3, x4, x04, x03, x34 E4
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

	x00.MulByNonResidue(api, x4).
		Add(api, x00, one)

	return &[5]E4{x00, x3, x34, x03, x04}
}

// Expt compute e1**exponent, where the exponent is hardcoded
// This function is only used for the final expo of the pairing for bls24315, so the exponent is supposed to be hardcoded and on 32 bits.
func (e *E24) Expt(api frontend.API, x E24) *E24 {

	xInv := E24{}
	res := x
	xInv.Conjugate(api, x)

	res.nSquare(api, 2)
	res.Mul(api, res, xInv)
	res.nSquareKarabina2345(api, 8)
	res.DecompressKarabina2345(api, res)
	res.Mul(api, res, xInv)
	res.nSquare(api, 2)
	res.Mul(api, res, x)
	res.nSquareKarabina2345(api, 20)
	res.DecompressKarabina2345(api, res)
	res.Mul(api, res, xInv)
	res.Conjugate(api, res)

	*e = res

	return e
}
