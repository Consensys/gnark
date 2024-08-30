package fields_bw6761

import (
	"math/big"

	"github.com/consensys/gnark/std/math/emulated"
)

func (e Ext6) nSquareKarabina12345(z *E6, n int) *E6 {
	for i := 0; i < n; i++ {
		z = e.CyclotomicSquareKarabina12345(z)
	}
	z = e.DecompressKarabina12345(z)
	return z
}

// ExpX0Minus1 set z to z^{x₀-1} in E6 and return z
// x₀-1 = 9586122913090633728
func (e Ext6) ExpX0Minus1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 5)
	result = e.Mul(result, z)
	z33 := e.Copy(result)
	result = e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, z33)
	result = e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)

	return result
}

// ExpX0Minus1Square set z to z^{(x₀-1)²} in E6 and return z
// (x₀-1)² = 91893752504881257682351033800651177984
func (e Ext6) ExpX0Minus1Square(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 3)
	t0 := e.nSquareKarabina12345(result, 1)
	t2 := e.Mul(z, t0)
	result = e.Mul(result, t2)
	t0 = e.Mul(z, result)
	t1 := e.nSquareKarabina12345(t0, 1)
	t1 = e.Mul(t2, t1)
	t3 := e.nSquareKarabina12345(t1, 7)
	t2 = e.Mul(t2, t3)
	t2 = e.nSquareKarabina12345(t2, 11)
	t1 = e.Mul(t1, t2)
	t0 = e.Mul(t0, t1)
	t0 = e.nSquareKarabina12345(t0, 7)
	result = e.Mul(result, t0)
	result = e.nSquareKarabina12345(result, 3)
	result = e.Mul(z, result)
	result = e.nSquareKarabina12345(result, 92)

	return result

}

// ExpX0Plus1 set z to z^(x₀+1) in E6 and return z
// x₀+1 = 9586122913090633730
func (e Ext6) ExpX0Plus1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	t := e.nSquareKarabina12345(result, 1)
	result = e.nSquareKarabina12345(t, 4)
	result = e.Mul(result, z)
	z33 := e.Copy(result)
	result = e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, z33)
	result = e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)
	result = e.Mul(result, t)

	return result
}

// ExptMinus1Div3 set z to z^(x₀-1)/3 in E6 and return z
// (x₀-1)/3 = 3195374304363544576
func (e Ext6) ExptMinus1Div3(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 2)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)
	t0 := e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, t0)
	result = e.nSquareKarabina12345(result, 5)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)

	return result
}

// ExpC1 set z to z^C1 in E6 and return z
// ht, hy = 13, 9
// C1 = (ht+hy)/2 = 11
func (e Ext6) ExpC1(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	result = e.nSquareKarabina12345(result, 2)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)

	return result
}

// ExpC2 set z to z^C2 in E6 and return z
// ht, hy = 13, 9
// C2 = (ht**2+3*hy**2)/4 = 103
func (e Ext6) ExpC2(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.nSquareKarabina12345(z, 1)
	result = e.Mul(result, z)
	t0 := e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, t0)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)

	return result
}

// MulBy023 multiplies z by an E6 sparse element of the form
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
func (e *Ext6) MulBy023(z *E6, c0, c1 *baseEl) *E6 {
	z = e.Reduce(z)

	a := e.fp.Mul(&z.A0, c0)
	b := e.fp.Mul(&z.A2, c1)
	tmp := e.fp.Add(&z.A2, &z.A4)
	a0 := e.fp.Mul(c1, tmp)
	a0 = e.fp.Sub(b, a0)
	a0 = e.fp.MulConst(a0, big.NewInt(4))
	a0 = e.fp.Add(a0, a)
	a2 := e.fp.Mul(&z.A4, c0)
	a2 = e.fp.Add(a2, b)
	a1 := e.fp.Add(c0, c1)
	tmp = e.fp.Add(&z.A0, &z.A2)
	a1 = e.fp.Mul(a1, tmp)
	a1 = e.fp.Sub(a1, a)
	a1 = e.fp.Sub(a1, b)

	b0 := e.fp.MulConst(&z.A5, big.NewInt(4))
	b2 := e.fp.Neg(&z.A3)
	b1 := e.fp.Neg(&z.A1)

	one := e.fp.One()
	d := e.fp.Add(c1, one)

	zC10 := e.fp.Add(&z.A1, &z.A0)
	zC11 := e.fp.Add(&z.A3, &z.A2)
	zC12 := e.fp.Add(&z.A5, &z.A4)

	a = e.fp.Mul(zC10, c0)
	b = e.fp.Mul(zC11, d)
	tmp = e.fp.Add(zC11, zC12)
	t0 := e.fp.Mul(d, tmp)
	t0 = e.fp.Sub(b, t0)
	t0 = e.fp.MulConst(t0, big.NewInt(4))
	t0 = e.fp.Add(t0, a)
	t2 := e.fp.Mul(zC12, c0)
	t2 = e.fp.Add(t2, b)
	t1 := e.fp.Add(c0, d)
	tmp = e.fp.Add(zC10, zC11)
	t1 = e.fp.Mul(t1, tmp)
	t1 = e.fp.Sub(t1, a)
	t1 = e.fp.Sub(t1, b)

	zC10 = e.fp.Sub(t0, a0)
	zC11 = e.fp.Sub(t1, a1)
	zC12 = e.fp.Sub(t2, a2)

	zC10 = e.fp.Add(zC10, b0)
	zC11 = e.fp.Add(zC11, b1)
	zC12 = e.fp.Add(zC12, b2)

	zC00 := e.fp.Add(a0, e.fp.MulConst(b2, big.NewInt(4)))
	zC01 := e.fp.Sub(a1, b0)
	zC02 := e.fp.Sub(a2, b1)

	return &E6{
		A0: *zC00,
		A1: *zC10,
		A2: *zC01,
		A3: *zC11,
		A4: *zC02,
		A5: *zC12,
	}

}

//	Mul023By023 multiplies two E6 sparse element of the form:
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
//
// and
//
//	E6{A0: c0, A1: 0, A2: c1, A3: 1,  A4: 0,  A5: 0}
func (e Ext6) Mul023By023(d0, d1, c0, c1 *baseEl) [5]*baseEl {
	x0 := e.fp.Mul(c0, d0)
	x1 := e.fp.Mul(c1, d1)
	x04 := e.fp.Add(c0, d0)
	tmp := e.fp.Add(c0, c1)
	x01 := e.fp.Add(d0, d1)
	x01 = e.fp.Mul(x01, tmp)
	tmp = e.fp.Add(x0, x1)
	x01 = e.fp.Sub(x01, tmp)
	x14 := e.fp.Add(c1, d1)

	minusFour := emulated.ValueOf[emulated.BW6761Fp]("6891450384315732539396789682275657542479668912536150109513790160209623422243491736087683183289411687640864567753786613451161759120554247759349511699125301598951605099378508850372543631423596795951899700429969112842764913119068295") // -4 % p
	zC0B0 := e.fp.Add(x0, &minusFour)

	return [5]*baseEl{zC0B0, x01, x04, x1, x14}
}

// MulBy02345 multiplies z by an E6 sparse element of the form
//
//	E6{A0: y0, A1: 0, A2: y1, A3: y2, A4: y3, A5: y4},
//	}
func (e *Ext6) MulBy02345(z *E6, x [5]*baseEl) *E6 {
	a0 := e.fp.Add(&z.A0, &z.A1)
	a1 := e.fp.Add(&z.A2, &z.A3)
	a2 := e.fp.Add(&z.A4, &z.A5)

	b1 := e.fp.Add(x[1], x[2])
	b2 := e.fp.Add(x[3], x[4])

	t0 := e.fp.Mul(a0, x[0])
	t1 := e.fp.Mul(a1, b1)
	t2 := e.fp.Mul(a2, b2)
	c0 := e.fp.Add(a1, a2)
	tmp := e.fp.Add(b1, b2)
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(c0, t1)
	c0 = e.fp.Sub(t2, c0)
	c0 = e.fp.MulConst(c0, big.NewInt(4))
	tmp = e.fp.Add(a0, a2)
	c2 := e.fp.Add(x[0], b2)
	c2 = e.fp.Mul(c2, tmp)
	c2 = e.fp.Sub(c2, t0)
	c2 = e.fp.Sub(c2, t2)
	c1 := e.fp.Add(a0, a1)
	tmp = e.fp.Add(x[0], b1)
	c1 = e.fp.Mul(c1, tmp)
	c1 = e.fp.Sub(c1, t0)
	c1 = e.fp.Sub(c1, t1)
	t2 = e.mulFpByNonResidue(e.fp, t2)
	a0 = e.fp.Add(c0, t0)
	a1 = e.fp.Add(c1, t2)
	a2 = e.fp.Add(c2, t1)

	t0 = e.fp.Mul(&z.A0, x[0])
	t1 = e.fp.Mul(&z.A2, x[1])
	t2 = e.fp.Mul(&z.A4, x[3])
	c0 = e.fp.Add(&z.A2, &z.A4)
	tmp = e.fp.Add(x[1], x[3])
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(c0, t1)
	c0 = e.fp.Sub(t2, c0)
	c0 = e.fp.MulConst(c0, big.NewInt(4))
	tmp = e.fp.Add(&z.A0, &z.A4)
	c2 = e.fp.Add(x[0], x[3])
	c2 = e.fp.Mul(c2, tmp)
	c2 = e.fp.Sub(c2, t0)
	c2 = e.fp.Sub(c2, t2)
	c1 = e.fp.Add(&z.A0, &z.A2)
	tmp = e.fp.Add(x[0], x[1])
	c1 = e.fp.Mul(c1, tmp)
	c1 = e.fp.Sub(c1, t0)
	c1 = e.fp.Sub(c1, t1)
	t2 = e.mulFpByNonResidue(e.fp, t2)
	b0 := e.fp.Add(c0, t0)
	b1 = e.fp.Add(c1, t2)
	b2 = e.fp.Add(c2, t1)

	t1 = e.fp.Mul(&z.A3, x[2])
	t2 = e.fp.Mul(&z.A5, x[4])
	c0 = e.fp.Add(&z.A3, &z.A5)
	tmp = e.fp.Add(x[2], x[4])
	c0 = e.fp.Mul(c0, tmp)
	c0 = e.fp.Sub(c0, t1)
	c0 = e.fp.Sub(t2, c0)
	c0 = e.fp.MulConst(c0, big.NewInt(4))
	c1 = e.fp.Add(&z.A1, &z.A3)
	c1 = e.fp.Mul(c1, x[2])
	c1 = e.fp.Sub(c1, t1)
	tmp = e.mulFpByNonResidue(e.fp, t2)
	c1 = e.fp.Add(c1, tmp)
	tmp = e.fp.Add(&z.A1, &z.A5)
	c2 = e.fp.Mul(x[4], tmp)
	c2 = e.fp.Sub(c2, t2)
	c2 = e.fp.Add(c2, t1)

	tmp = e.fp.Add(b0, c0)
	z10 := e.fp.Sub(a0, tmp)
	tmp = e.fp.Add(b1, c1)
	z11 := e.fp.Sub(a1, tmp)
	tmp = e.fp.Add(b2, c2)
	z12 := e.fp.Sub(a2, tmp)

	z00 := e.mulFpByNonResidue(e.fp, c2)
	z00 = e.fp.Add(z00, b0)
	z01 := e.fp.Add(c0, b1)
	z02 := e.fp.Add(c1, b2)

	return &E6{
		A0: *z00,
		A1: *z10,
		A2: *z01,
		A3: *z11,
		A4: *z02,
		A5: *z12,
	}
}

// AssertFinalExponentiationIsOne checks that a Miller function output x lies in the
// same equivalence class as the reduced pairing. This replaces the final
// exponentiation step in-circuit.
// The method is adapted from Section 4 of [On Proving Pairings] paper by A. Novakovic and L. Eagen.
//
// [On Proving Pairings]: https://eprint.iacr.org/2024/640.pdf
func (e Ext6) AssertFinalExponentiationIsOne(x *E6) {
	res, err := e.fp.NewHint(finalExpHint, 6, &x.A0, &x.A1, &x.A2, &x.A3, &x.A4, &x.A5)
	if err != nil {
		// err is non-nil only for invalid number of inputs
		panic(err)
	}

	residueWitness := E6{
		A0: *res[0],
		A1: *res[1],
		A2: *res[2],
		A3: *res[3],
		A4: *res[4],
		A5: *res[5],
	}

	// Check that  x == residueWitness^λ
	// where λ = u^3-u^2+1 - (u+1)p, with u the BW6-761 seed
	// and residueWitness from the hint.

	// exponentiation by U1=u^3-u^2+1
	t0 := e.ExpByU1(&residueWitness)
	// exponentiation by U2=u+1
	t1 := e.ExpByU2(&residueWitness)

	t1 = e.Frobenius(t1)
	t0 = e.DivUnchecked(t0, t1)

	e.AssertIsEqual(t0, x)
}

// ExpByU2 set z to z^(x₀+1) in E12 and return z
// x₀+1 = 9586122913090633730
func (e Ext6) ExpByU2(z *E6) *E6 {
	z = e.Reduce(z)
	result := e.Copy(z)
	t := e.nSquareKarabina12345(result, 1)
	result = e.nSquareKarabina12345(t, 4)
	result = e.Mul(result, z)
	z33 := e.Copy(result)
	result = e.nSquareKarabina12345(result, 7)
	result = e.Mul(result, z33)
	result = e.nSquareKarabina12345(result, 4)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 1)
	result = e.Mul(result, z)
	result = e.nSquareKarabina12345(result, 46)
	result = e.Mul(result, t)

	return result
}

// ExpByU1 set z to z^(x₀^3-x₀^2+1) in E12 and return z
// x₀^3-x₀^2+1 = 880904806456922042166256752416502360965158762994674434049
func (e Ext6) ExpByU1(x *E6) *E6 {
	t5 := e.nSquareKarabina12345(x, 1)
	z := e.Mul(x, t5)
	t0 := e.nSquareKarabina12345(z, 1)
	t6 := e.Mul(x, t0)
	t8 := e.Mul(x, t6)
	t7 := e.Mul(t5, t8)
	t9 := e.Mul(t0, t8)
	t3 := e.Mul(z, t9)
	t2 := e.Mul(x, t3)
	t1 := e.Mul(t6, t2)
	t0 = e.Mul(t8, t1)
	t4 := e.nSquareKarabina12345(t0, 1)
	t4 = e.Mul(z, t4)
	t8 = e.Mul(t8, t4)
	t2 = e.Mul(t2, t8)
	t9 = e.Mul(t9, t2)
	t5 = e.Mul(t5, t9)
	t10 := e.Mul(t0, t9)
	t10 = e.nSquareKarabina12345(t10, 6)
	t9 = e.Mul(t9, t10)
	t9 = e.nSquareKarabina12345(t9, 10)
	t8 = e.Mul(t8, t9)
	t8 = e.nSquareKarabina12345(t8, 10)
	t8 = e.Mul(t5, t8)
	t7 = e.Mul(t7, t8)
	t7 = e.nSquareKarabina12345(t7, 4)
	t6 = e.Mul(t6, t7)
	t6 = e.nSquareKarabina12345(t6, 11)
	t5 = e.Mul(t5, t6)
	t5 = e.nSquareKarabina12345(t5, 3)
	t5 = e.Mul(z, t5)
	t5 = e.nSquareKarabina12345(t5, 17)
	t4 = e.Mul(t4, t5)
	t4 = e.nSquareKarabina12345(t4, 7)
	t3 = e.Mul(t3, t4)
	t3 = e.nSquareKarabina12345(t3, 11)
	t2 = e.Mul(t2, t3)
	t2 = e.nSquareKarabina12345(t2, 7)
	t1 = e.Mul(t1, t2)
	t1 = e.nSquareKarabina12345(t1, 3)
	t1 = e.Mul(x, t1)
	t1 = e.nSquareKarabina12345(t1, 35)
	t1 = e.Mul(t0, t1)
	t1 = e.nSquareKarabina12345(t1, 7)
	t0 = e.Mul(t0, t1)
	t0 = e.nSquareKarabina12345(t0, 5)
	z = e.Mul(z, t0)
	z = e.nSquareKarabina12345(z, 46)
	z = e.Mul(x, z)

	return z
}
