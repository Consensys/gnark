package fields_bn254

import "github.com/consensys/gnark/frontend"

func (e Ext12) Expt(api frontend.API, x *E12) *E12 {
	t3 := e.CyclotomicSquare(x)
	t5 := e.CyclotomicSquare(t3)
	result := e.CyclotomicSquare(t5)
	t0 := e.CyclotomicSquare(result)
	t2 := e.Mul(x, t0)
	t0 = e.Mul(t3, t2)
	t1 := e.Mul(x, t0)
	t4 := e.Mul(result, t2)
	t6 := e.CyclotomicSquare(t2)
	t1 = e.Mul(t0, t1)
	t0 = e.Mul(t3, t1)
	t6 = e.NCycloSquareCompressed(t6, 6)
	t6 = e.DecompressKarabina(api, t6)
	t5 = e.Mul(t5, t6)
	t5 = e.Mul(t4, t5)
	t5 = e.NCycloSquareCompressed(t5, 7)
	t5 = e.DecompressKarabina(api, t5)
	t4 = e.Mul(t4, t5)
	t4 = e.NCycloSquareCompressed(t4, 8)
	t4 = e.DecompressKarabina(api, t4)
	t4 = e.Mul(t0, t4)
	t3 = e.Mul(t3, t4)
	t3 = e.NCycloSquareCompressed(t3, 6)
	t3 = e.DecompressKarabina(api, t3)
	t2 = e.Mul(t2, t3)
	t2 = e.NCycloSquareCompressed(t2, 8)
	t2 = e.DecompressKarabina(api, t2)
	t2 = e.Mul(t0, t2)
	t2 = e.NCycloSquareCompressed(t2, 6)
	t2 = e.DecompressKarabina(api, t2)
	t2 = e.Mul(t0, t2)
	t2 = e.NCycloSquareCompressed(t2, 10)
	t2 = e.DecompressKarabina(api, t2)
	t1 = e.Mul(t1, t2)
	t1 = e.NCycloSquareCompressed(t1, 6)
	t1 = e.DecompressKarabina(api, t1)
	t0 = e.Mul(t0, t1)
	z := e.Mul(result, t0)
	return z
}

func (e Ext12) MulBy034(z *E12, c0, c3, c4 *E2) *E12 {
	a := e.Ext6.MulByE2(&z.C0, c0)
	b := e.Ext6.MulBy01(&z.C1, c3, c4)
	c0 = e.Ext2.Add(c0, c3)
	d := e.Ext6.Add(&z.C0, &z.C1)
	d = e.Ext6.MulBy01(d, c0, c4)
	z1 := e.Ext6.Add(a, b)
	z1 = e.Neg(z1)
	z1 = e.Ext6.Add(z1, d)
	z0 := e.MulByNonResidue(b)
	z0 = e.Ext6.Add(z0, a)
	return &E12{
		C0: *z0,
		C1: *z1,
	}
}

func (e Ext12) MulBy034by034(d0, d3, d4, c0, c3, c4 *E2) *E12 {
	x0 := e.Ext2.Mul(c0, d0)
	x3 := e.Ext2.Mul(c3, d3)
	x4 := e.Ext2.Mul(c4, d4)
	tmp := e.Ext2.Add(c0, c4)
	x04 := e.Ext2.Add(d0, d4)
	x04 = e.Ext2.Mul(x04, tmp)
	x04 = e.Ext2.Sub(x04, x0)
	x04 = e.Ext2.Sub(x04, x4)
	tmp = e.Ext2.Add(c0, c3)
	x03 := e.Ext2.Add(d0, d3)
	x03 = e.Ext2.Mul(x03, tmp)
	x03 = e.Ext2.Sub(x03, x0)
	x03 = e.Ext2.Sub(x03, x3)
	tmp = e.Ext2.Add(c3, c4)
	x34 := e.Ext2.Add(d3, d4)
	x34 = e.Ext2.Mul(x34, tmp)
	x34 = e.Ext2.Sub(x34, x3)
	x34 = e.Ext2.Sub(x34, x4)
	z00 := e.Ext2.MulByNonResidue(x4)
	z00 = e.Ext2.Add(z00, x0)
	z01 := x3
	z02 := x34
	z10 := x03
	z11 := x04
	z12 := e.Ext2.Zero()
	return &E12{
		C0: E6{
			B0: *z00,
			B1: *z01,
			B2: *z02,
		},
		C1: E6{
			B0: *z10,
			B1: *z11,
			B2: *z12,
		},
	}
}
