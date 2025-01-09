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

func (e *E12) MulBy01234(api frontend.API, x [5]E2) *E12 {
	var a, c, z1, z0 E6
	c0 := E6{A0: x[0].A0, A1: x[1].A0, A2: x[2].A0, A3: x[0].A1, A4: x[1].A1, A5: x[2].A1}
	a.Add(api, e.C0, e.C1)
	var b0, b1 E2
	b0.Add(api, x[0], x[3])
	b1.Add(api, x[1], x[4])
	b2 := x[2]
	b := E6{A0: b0.A0, A1: b1.A0, A2: b2.A0, A3: b0.A1, A4: b1.A1, A5: b2.A1}
	a.Mul(api, a, b)
	b.Mul(api, e.C0, c0)
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
