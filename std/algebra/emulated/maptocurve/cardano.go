package maptocurve

// Cardano solver for P-256 (secp256r1): solves x³ − 3x + c = 0 over Fp.
// Used by the y-increment hint to recover x from y on curves with a ≠ 0.
//
// Requires q ≡ 3 mod 4 (for Fp2 = Fp[u]/(u²+1)) and q ≡ 4 mod 9 (for Fp cbrt).

import (
	"math/big"

	fp "github.com/consensys/gnark-crypto/ecc/secp256r1/fp"
)

// --- Fp2 = Fp[u]/(u²+1) arithmetic ---

// e2 is a degree-two extension of fp.Element: A0 + A1·u, u² = -1.
type e2 struct {
	A0, A1 fp.Element
}

func (z *e2) setZero() *e2  { z.A0.SetZero(); z.A1.SetZero(); return z }
func (z *e2) setOne() *e2   { z.A0.SetOne(); z.A1.SetZero(); return z }
func (z *e2) set(x *e2) *e2 { z.A0 = x.A0; z.A1 = x.A1; return z }
func (z *e2) equal(x *e2) bool {
	return z.A0.Equal(&x.A0) && z.A1.Equal(&x.A1)
}
func (z *e2) isZero() bool { return z.A0.IsZero() && z.A1.IsZero() }

func (z *e2) neg(x *e2) *e2 {
	z.A0.Neg(&x.A0)
	z.A1.Neg(&x.A1)
	return z
}

func (z *e2) mulByElement(x *e2, y *fp.Element) *e2 {
	z.A0.Mul(&x.A0, y)
	z.A1.Mul(&x.A1, y)
	return z
}

// mul sets z = x·y using Karatsuba.
func (z *e2) mul(x, y *e2) *e2 {
	var a, b, c fp.Element
	a.Add(&x.A0, &x.A1)
	b.Add(&y.A0, &y.A1)
	a.Mul(&a, &b)
	b.Mul(&x.A0, &y.A0)
	c.Mul(&x.A1, &y.A1)
	z.A1.Sub(&a, &b).Sub(&z.A1, &c)
	z.A0.Sub(&b, &c)
	return z
}

// square sets z = x².
func (z *e2) square(x *e2) *e2 {
	var a, b fp.Element
	a.Add(&x.A0, &x.A1)
	b.Sub(&x.A0, &x.A1)
	a.Mul(&a, &b)
	b.Mul(&x.A0, &x.A1).Double(&b)
	z.A0.Set(&a)
	z.A1.Set(&b)
	return z
}

// inverse sets z = 1/x via norm: N(x) = x0² + x1².
func (z *e2) inverse(x *e2) *e2 {
	var t0, t1 fp.Element
	t0.Square(&x.A0)
	t1.Square(&x.A1)
	t0.Add(&t0, &t1)
	t1.Inverse(&t0)
	z.A0.Mul(&x.A0, &t1)
	z.A1.Mul(&x.A1, &t1).Neg(&z.A1)
	return z
}

// exp sets z = x^k using square-and-multiply.
func (z *e2) exp(x e2, k *big.Int) *e2 {
	if k.IsUint64() && k.Uint64() == 0 {
		return z.setOne()
	}
	e := k
	if k.Sign() == -1 {
		x.inverse(&x)
		e = new(big.Int).Neg(k)
	}
	z.setOne()
	b := e.Bytes()
	for i := 0; i < len(b); i++ {
		w := b[i]
		for j := 0; j < 8; j++ {
			z.square(z)
			if (w & (0b10000000 >> j)) != 0 {
				z.mul(z, &x)
			}
		}
	}
	return z
}

// sqrt sets z = √x in Fp2 using Scott §6.3, valid for q ≡ 3 mod 4.
func (z *e2) sqrt(x *e2) *e2 {
	var a1, alpha, x0, minusOne e2
	minusOne.setOne().neg(&minusOne)

	a1.expBySqrtHelper(x)
	alpha.square(&a1).mul(&alpha, x)
	x0.mul(x, &a1)

	if alpha.equal(&minusOne) {
		c := x0.A0
		z.A0.Neg(&x0.A1)
		z.A1.Set(&c)
		return z
	}
	var b e2
	b.setOne()
	b.A0.Add(&b.A0, &alpha.A0)
	b.A1.Add(&b.A1, &alpha.A1)
	b.exp(b, &sqrtExp2P256).mul(&b, &x0)
	return z.set(&b)
}

var sqrtExp2P256 big.Int

func init() {
	q := fp.Modulus()
	sqrtExp2P256.Sub(q, big.NewInt(1))
	sqrtExp2P256.Rsh(&sqrtExp2P256, 1)
}

// expBySqrtHelper sets z = x^{(q-3)/4} in Fp2.
// (q-3)/4 = 0x3fffffffc00000004000000000000000000000003fffffffffffffffffffffff
// Addition chain: cost 264 = 253 sq + 11 mul.
func (z *e2) expBySqrtHelper(x *e2) *e2 {
	var t0, t1, t2, t3, t4, t5, t6, t7, t8 e2

	t0.square(x)
	t1.mul(x, &t0)
	t2.square(&t1)
	t3.mul(x, &t2)
	t4.square(&t3)
	t4.square(&t4)
	t4.square(&t4)
	t5.mul(&t3, &t4)
	t8.square(&t5)
	for k := 0; k < 5; k++ {
		t8.square(&t8)
	}
	t8.mul(&t8, &t5)
	t6.square(&t8)
	t6.square(&t6)
	t6.square(&t6)
	t6.mul(&t6, &t3)
	t7.square(&t6)
	t7.mul(&t7, x)
	t8.square(&t7)
	for k := 0; k < 15; k++ {
		t8.square(&t8)
	}
	t8.mul(&t8, &t7)
	for k := 0; k < 15; k++ {
		t8.square(&t8)
	}
	t5.mul(&t6, &t8)
	for k := 0; k < 17; k++ {
		t8.square(&t8)
	}
	t8.mul(&t8, x)
	for k := 0; k < 143; k++ {
		t8.square(&t8)
	}
	t8.mul(&t8, &t5)
	for k := 0; k < 47; k++ {
		t8.square(&t8)
	}
	z.mul(&t5, &t8)
	return z
}

// cbrtE2 sets z = ∛x in Fp2 using the algebraic torus T₂(Fp).
func (z *e2) cbrt(x *e2) *e2 {
	if x.A1.IsZero() {
		if x.A0.Cbrt(&x.A0) == nil {
			return nil
		}
		z.A0.Set(&x.A0)
		z.A1.SetZero()
		return z
	}

	if x.A0.IsZero() {
		var negA1 fp.Element
		negA1.Neg(&x.A1)
		if negA1.Cbrt(&negA1) == nil {
			return nil
		}
		z.A0.SetZero()
		z.A1.Set(&negA1)
		return z.cbrtVerify(x)
	}

	var x0sq, x1sq, norm fp.Element
	x0sq.Square(&x.A0)
	x1sq.Square(&x.A1)
	norm.Add(&x0sq, &x1sq)

	m, normInv, ok := cbrtAndNormInverse(&norm)
	if !ok {
		return nil
	}

	// τ = 2·(A0² − A1²)/N
	var tau fp.Element
	tau.Sub(&x0sq, &x1sq)
	tau.Double(&tau)
	tau.Mul(&tau, &normInv)

	sigma := lucasV(&tau)

	// z₀ = A0/(m·(σ−1)), z₁ = A1/(m·(σ+1))
	var one, d0, d1, d0d1, d0d1Inv fp.Element
	one.SetOne()
	d0.Sub(&sigma, &one)
	d0.Mul(&m, &d0)
	d1.Add(&sigma, &one)
	d1.Mul(&m, &d1)

	d0d1.Mul(&d0, &d1)
	d0d1Inv.Inverse(&d0d1)

	z.A0.Mul(&d1, &d0d1Inv).Mul(&z.A0, &x.A0)
	z.A1.Mul(&d0, &d0d1Inv).Mul(&z.A1, &x.A1)

	return z.cbrtVerify(x)
}

func (z *e2) cbrtVerify(x *e2) *e2 {
	var c e2
	c.square(z).mul(&c, z)
	if !c.equal(x) {
		return nil
	}
	return z
}

func cbrtAndNormInverse(norm *fp.Element) (m, normInv fp.Element, ok bool) {
	var t, t2, t4, t8, t9, n2, n3 fp.Element
	expByCbrtHelper(&t, norm)
	t2.Square(&t)
	t4.Square(&t2)
	t8.Square(&t4)
	t9.Mul(&t8, &t)
	n2.Square(norm)
	n3.Mul(&n2, norm)
	m.Mul(&t8, &n3)
	normInv.Mul(&t9, &n2)

	var c fp.Element
	c.Square(&m).Mul(&c, &m)
	if !c.Equal(norm) {
		return m, normInv, false
	}
	return m, normInv, true
}

// lucasExponent is e = 3⁻¹ mod (q+1) as little-endian uint64 limbs.
var lucasExponent = [4]uint64{
	12297829382473034411,
	6148914692668172970,
	6148914691236517205,
	6148914689804861440,
}

func lucasV(alpha *fp.Element) fp.Element {
	var v0, v1, two, prod fp.Element
	two.SetUint64(2)
	v0.Set(alpha)
	v1.Square(alpha).Sub(&v1, &two)

	for i := 253; i >= 1; i-- {
		bit := (lucasExponent[i/64] >> uint(i%64)) & 1
		prod.Mul(&v0, &v1).Sub(&prod, alpha)
		if bit == 0 {
			v1.Set(&prod)
			v0.Square(&v0).Sub(&v0, &two)
		} else {
			v0.Set(&prod)
			v1.Square(&v1).Sub(&v1, &two)
		}
	}
	v0.Mul(&v0, &v1).Sub(&v0, alpha)
	return v0
}

// expByCbrtHelper sets z = x^{(q−4)/9} in Fp.
// Addition chain: cost 278 = 265 sq + 13 mul.
func expByCbrtHelper(z, x *fp.Element) {
	var t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10 fp.Element
	var t11, t12, t13, t14, t15, t16, t17, t18, t19 fp.Element

	t0.Square(x)
	t1.Square(&t0)
	t2.Mul(&t0, &t1)
	t3.Mul(x, &t2)
	t4.Mul(&t1, &t3)
	t5.Mul(&t3, &t4)
	t6.Square(&t5)
	t7.Mul(&t5, &t6)
	t8.Square(&t7)
	t8.Square(&t8)
	t9.Mul(&t2, &t8)
	t10.Mul(&t4, &t8)

	t11.Square(&t10)
	t11.Mul(&t11, &t10)
	t11.Mul(&t11, &t9)

	t12.Square(&t11)
	t12.Mul(&t12, &t5)

	t13.Mul(&t11, &t12)
	t14.Mul(&t12, &t13)
	t15.Mul(&t13, &t14)

	t16.Square(&t15)
	t16.Mul(&t16, &t15)
	t16.Mul(&t16, &t4)

	t17.Mul(&t0, &t16)
	t18.Mul(&t15, &t17)
	t19.Mul(&t0, &t18)

	t8.Set(&t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t18)
	for k := 0; k < 16; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t16)
	for k := 0; k < 16; k++ {
		t8.Square(&t8)
	}

	t8.Mul(&t17, &t8)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)

	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}

	t8.Mul(&t19, &t8)
	for k := 0; k < 15; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t14)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)

	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}
	t8.Mul(&t8, &t19)
	for k := 0; k < 18; k++ {
		t8.Square(&t8)
	}

	t8.Mul(&t19, &t8)
	for k := 0; k < 11; k++ {
		t8.Square(&t8)
	}
	z.Mul(&t8, &t10)
}

// omega returns a primitive cube root of unity in Fp.
func omega() fp.Element {
	return omegaP256
}

var omegaP256 fp.Element

func init() {
	q := fp.Modulus()
	exp := new(big.Int).Sub(q, big.NewInt(1))
	exp.Div(exp, big.NewInt(3))
	var one fp.Element
	one.SetOne()
	for i := int64(2); ; i++ {
		var g, w fp.Element
		g.SetInt64(i)
		w.Exp(g, exp)
		if !w.Equal(&one) {
			omegaP256 = w
			break
		}
	}
}

// cardanoRootsP256 returns all roots in Fp of x³ − 3x + c = 0.
func cardanoRootsP256(c fp.Element) []fp.Element {
	var a fp.Element
	a.SetInt64(-3)

	var zero fp.Element

	// Δ = −4a³ − 27c²
	var a3, neg4a3, k27c2, delta fp.Element
	a3.Square(&a).Mul(&a3, &a)
	neg4a3.Mul(&a3, new(fp.Element).SetInt64(4)).Neg(&neg4a3)
	k27c2.Square(&c).Mul(&k27c2, new(fp.Element).SetInt64(27))
	delta.Sub(&neg4a3, &k27c2)

	// disc_D = c²/4 + a³/27
	var inv4, inv27, discD fp.Element
	inv4.SetInt64(4)
	inv4.Inverse(&inv4)
	inv27.SetInt64(27)
	inv27.Inverse(&inv27)
	discD.Square(&c).Mul(&discD, &inv4)
	var a3over27 fp.Element
	a3over27.Mul(&a3, &inv27)
	discD.Add(&discD, &a3over27)

	// −c/2
	var inv2, negCHalf fp.Element
	inv2.SetInt64(2)
	inv2.Inverse(&inv2)
	negCHalf.Mul(&c, &inv2).Neg(&negCHalf)

	om := omega()
	var om2 fp.Element
	om2.Square(&om)
	var one fp.Element
	one.SetOne()
	zetas := [3]fp.Element{one, om, om2}

	// Case 1: Δ = 0
	if delta.Equal(&zero) {
		var invA, r0, r1 fp.Element
		invA.Inverse(&a)
		r0.Mul(&c, &invA).Mul(&r0, new(fp.Element).SetInt64(3))
		var twoA fp.Element
		twoA.Double(&a)
		r1.Inverse(&twoA).Mul(&r1, &c).Mul(&r1, new(fp.Element).SetInt64(3)).Neg(&r1)
		return []fp.Element{r0, r1}
	}

	// Case 2: Δ non-square → one real root via Fp2
	if delta.Legendre() == -1 {
		var discDE2, D e2
		discDE2.A0 = discD
		D.sqrt(&discDE2)

		w := e2{A0: negCHalf, A1: D.A1}
		if w.isZero() {
			w.A1.Neg(&D.A1)
		}

		var u e2
		u.cbrt(&w)

		for _, zeta := range zetas {
			var cand e2
			cand.mulByElement(&u, &zeta)
			var inv e2
			inv.inverse(&cand)
			var rRe, rIm fp.Element
			rRe.Add(&cand.A0, &inv.A0)
			rIm.Add(&cand.A1, &inv.A1)
			if rIm.Equal(&zero) {
				return []fp.Element{rRe}
			}
		}
		return []fp.Element{} // should not happen
	}

	// Case 3: Δ square → 0 or 3 roots in Fp
	var DFq, wFq fp.Element
	DFq.Sqrt(&discD)
	wFq.Add(&negCHalf, &DFq)
	if wFq.Equal(&zero) {
		wFq.Sub(&negCHalf, &DFq)
	}

	var uFq fp.Element
	if uFq.Cbrt(&wFq) == nil {
		return []fp.Element{}
	}

	var invU, r0, r1, r2, t1, t2 fp.Element
	invU.Inverse(&uFq)
	r0.Add(&uFq, &invU)
	t1.Mul(&om, &uFq)
	t2.Mul(&om2, &invU)
	r1.Add(&t1, &t2)
	t1.Mul(&om2, &uFq)
	t2.Mul(&om, &invU)
	r2.Add(&t1, &t2)
	return []fp.Element{r0, r1, r2}
}
