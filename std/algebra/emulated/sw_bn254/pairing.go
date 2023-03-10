package sw_bn254

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/emulated/fields_bn254"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	*fields_bn254.Ext12
}

type GTEl = fields_bn254.E12

func NewGTEl(v bn254.GT) GTEl {
	return GTEl{
		C0: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C0.B2.A1),
			},
		},
		C1: fields_bn254.E6{
			B0: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B0.A1),
			},
			B1: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B1.A1),
			},
			B2: fields_bn254.E2{
				A0: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A0),
				A1: emulated.ValueOf[emulated.BN254Fp](v.C1.B2.A1),
			},
		},
	}
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		Ext12: fields_bn254.NewExt12(ba),
	}, nil
}

func (pr Pairing) DoubleStep(api frontend.API, p *g2Projective) (*g2Projective, *lineEvaluation) {
	// var t1, A, B, C, D, E, EE, F, G, H, I, J, K fptower.E2
	A := pr.Ext2.Mul(&p.X, &p.Y)               // A.Mul(&p.x, &p.y)
	A = pr.Ext2.Halve(A)                       // A.Halve()
	B := pr.Ext2.Square(&p.Y)                  // B.Square(&p.y)
	C := pr.Ext2.Square(&p.Z)                  // C.Square(&p.z)
	D := pr.Ext2.Double(C)                     // D.Double(&C).
	D = pr.Ext2.Add(D, C)                      // 	Add(&D, &C)
	E := pr.Ext2.MulBybTwistCurveCoeff(api, D) // E.MulBybTwistCurveCoeff(&D)
	F := pr.Ext2.Double(E)                     // F.Double(&E).
	F = pr.Ext2.Add(F, E)                      // 	Add(&F, &E)
	G := pr.Ext2.Add(B, F)                     // G.Add(&B, &F)
	G = pr.Ext2.Halve(G)                       // G.Halve()
	H := pr.Ext2.Add(&p.Y, &p.Z)               // H.Add(&p.y, &p.z).
	H = pr.Ext2.Square(H)                      // 	Square(&H)
	t1 := pr.Ext2.Add(B, C)                    // t1.Add(&B, &C)
	H = pr.Ext2.Sub(H, t1)                     // H.Sub(&H, &t1)
	I := pr.Ext2.Sub(E, B)                     // I.Sub(&E, &B)
	J := pr.Ext2.Square(&p.X)                  // J.Square(&p.x)
	EE := pr.Ext2.Square(E)                    // EE.Square(&E)
	K := pr.Ext2.Double(EE)                    // K.Double(&EE).
	K = pr.Ext2.Add(K, EE)                     // 	Add(&K, &EE)
	px := pr.Ext2.Sub(B, F)                    // p.x.Sub(&B, &F).
	px = pr.Ext2.Mul(px, A)                    // 	Mul(&p.x, &A)
	py := pr.Ext2.Square(G)                    // p.y.Square(&G).
	py = pr.Ext2.Sub(py, K)                    // 	Sub(&p.y, &K)
	pz := pr.Ext2.Mul(B, H)                    // p.z.Mul(&B, &H)
	ev0 := pr.Ext2.Neg(H)                      // evaluations.r0.Neg(&H)
	ev1 := pr.Ext2.Double(J)                   // evaluations.r1.Double(&J).
	ev1 = pr.Ext2.Add(ev1, J)                  // 	Add(&evaluations.r1, &J)
	ev2 := I                                   // evaluations.r2.Set(&I)
	return &g2Projective{
			X: *px,
			Y: *py,
			Z: *pz,
		},
		&lineEvaluation{
			r0: *ev0,
			r1: *ev1,
			r2: *ev2,
		}
}

func (pr Pairing) affineToProjective(Q *G2Affine) *g2Projective {
	// TODO: check point at infinity? We do not filter them in the Miller Loop neither.
	// if Q.X.IsZero() && Q.Y.IsZero() {
	// 	p.z.SetZero()
	// 	p.x.SetOne()
	// 	p.y.SetOne()
	// 	return p
	// }
	pz := pr.Ext2.One()   // p.z.SetOne()
	px := &Q.X            // p.x.Set(&Q.X)
	py := &Q.Y            // p.y.Set(&Q.Y)
	return &g2Projective{ // return p
		X: *px,
		Y: *py,
		Z: *pz,
	}
}

func (pr Pairing) NegAffine(a *G2Affine) *G2Affine {
	px := &a.X              // p.X = a.X
	py := pr.Ext2.Neg(&a.Y) // p.Y.Neg(&a.Y)
	return &G2Affine{       // return p
		X: *px,
		Y: *py,
	}
}

func (pr Pairing) AddStep(p *g2Projective, a *G2Affine) (*g2Projective, *lineEvaluation) {
	// var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J fptower.E2
	Y2Z1 := pr.Ext2.Mul(&a.Y, &p.Z) // Y2Z1.Mul(&a.Y, &p.z)
	O := pr.Ext2.Sub(&p.Y, Y2Z1)    // O.Sub(&p.y, &Y2Z1)
	X2Z1 := pr.Ext2.Mul(&a.X, &p.Z) // X2Z1.Mul(&a.X, &p.z)
	L := pr.Ext2.Sub(&p.X, X2Z1)    // L.Sub(&p.x, &X2Z1)
	C := pr.Ext2.Square(O)          // C.Square(&O)
	D := pr.Ext2.Square(L)          // D.Square(&L)
	E := pr.Ext2.Mul(L, D)          // E.Mul(&L, &D)
	F := pr.Ext2.Mul(&p.Z, C)       // F.Mul(&p.z, &C)
	G := pr.Ext2.Mul(&p.X, D)       // G.Mul(&p.x, &D)
	t0 := pr.Ext2.Double(G)         // t0.Double(&G)
	H := pr.Ext2.Add(E, F)          // H.Add(&E, &F).
	H = pr.Ext2.Sub(H, t0)          // 	Sub(&H, &t0)
	t1 := pr.Ext2.Mul(&p.Y, E)      // t1.Mul(&p.y, &E)
	px := pr.Ext2.Mul(L, H)         // p.x.Mul(&L, &H)
	py := pr.Ext2.Sub(G, H)         // p.y.Sub(&G, &H).
	py = pr.Ext2.Mul(py, O)         // 	Mul(&p.y, &O).
	py = pr.Ext2.Sub(py, t1)        // 	Sub(&p.y, &t1)
	pz := pr.Ext2.Mul(E, &p.Z)      // p.z.Mul(&E, &p.z)
	t2 := pr.Ext2.Mul(L, &a.Y)      // t2.Mul(&L, &a.Y)
	J := pr.Ext2.Mul(&a.X, O)       // J.Mul(&a.X, &O).
	J = pr.Ext2.Sub(J, t2)          // 	Sub(&J, &t2)
	ev0 := L                        // evaluations.r0.Set(&L)
	ev1 := pr.Ext2.Neg(O)           // evaluations.r1.Neg(&O)
	ev2 := J                        // evaluations.r2.Set(&J)
	return &g2Projective{
			X: *px,
			Y: *py,
			Z: *pz,
		}, &lineEvaluation{
			r0: *ev0,
			r1: *ev1,
			r2: *ev2,
		}
}

type lineEvaluation struct {
	r0 fields_bn254.E2
	r1 fields_bn254.E2
	r2 fields_bn254.E2
}

var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

func (pr Pairing) MillerLoop(api frontend.API, p []*G1Affine, q []*G2Affine) (*GTEl, error) {
	n := len(p)
	if n == 0 || n != len(q) {
		return nil, fmt.Errorf("invalid inputs sizes")
	}

	// TODO: we have omitted filtering for infinity points.

	// projective points for Q
	qProj := make([]*g2Projective, n) // qProj := make([]g2Proj, n)
	qNeg := make([]*G2Affine, n)      // qNeg := make([]G2Affine, n)
	for k := 0; k < n; k++ {
		qProj[k] = pr.affineToProjective(q[k]) // qProj[k].FromAffine(&q[k])
		qNeg[k] = pr.NegAffine(q[k])           // qNeg[k].Neg(&q[k])
	}

	var l, l0 *lineEvaluation
	result := pr.Ext12.One() // var tmp, result GTEl

	// i == len(loopCounter) - 2
	for k := 0; k < n; k++ {
		qProj[k], l = pr.DoubleStep(api, qProj[k])              // qProj[k].DoubleStep(&l)
		l.r0 = *pr.Ext12.Ext2.MulByElement(&l.r0, &p[k].Y)      // l.r0.MulByElement(&l.r0, &p[k].Y)
		l.r1 = *pr.Ext12.Ext2.MulByElement(&l.r1, &p[k].X)      // l.r1.MulByElement(&l.r1, &p[k].X)
		result = pr.Ext12.MulBy034(result, &l.r0, &l.r1, &l.r2) // result.MulBy034(&l.r0, &l.r1, &l.r2)
	}

	for i := len(loopCounter) - 3; i >= 0; i-- {
		result = pr.Ext12.Square(result) // result.Square(&result)

		for k := 0; k < n; k++ {
			qProj[k], l = pr.DoubleStep(api, qProj[k])         // qProj[k].DoubleStep(&l)
			l.r0 = *pr.Ext12.Ext2.MulByElement(&l.r0, &p[k].Y) // l.r0.MulByElement(&l.r0, &p[k].Y)
			l.r1 = *pr.Ext12.Ext2.MulByElement(&l.r1, &p[k].X) // l.r1.MulByElement(&l.r1, &p[k].X)

			if loopCounter[i] == 1 {
				qProj[k], l0 = pr.AddStep(qProj[k], q[k])                                  // qProj[k].AddMixedStep(&l0, &q[k])
				l0.r0 = *pr.Ext12.Ext2.MulByElement(&l0.r0, &p[k].Y)                       // l0.r0.MulByElement(&l0.r0, &p[k].Y)
				l0.r1 = *pr.Ext12.Ext2.MulByElement(&l0.r1, &p[k].X)                       // l0.r1.MulByElement(&l0.r1, &p[k].X)
				tmp := pr.Ext12.MulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Ext12.Mul(result, tmp)                                         // result.Mul(&result, &tmp)
			} else if loopCounter[i] == -1 {
				qProj[k], l0 = pr.AddStep(qProj[k], qNeg[k])                               // qProj[k].AddMixedStep(&l0, &qNeg[k])
				l0.r0 = *pr.Ext12.Ext2.MulByElement(&l0.r0, &p[k].Y)                       // l0.r0.MulByElement(&l0.r0, &p[k].Y)
				l0.r1 = *pr.Ext12.Ext2.MulByElement(&l0.r1, &p[k].X)                       // l0.r1.MulByElement(&l0.r1, &p[k].X)
				tmp := pr.Ext12.MulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.Ext12.Mul(result, tmp)                                         //result.Mul(&result, &tmp)
			} else {
				result = pr.Ext12.MulBy034(result, &l.r0, &l.r1, &l.r2) // result.MulBy034(&l.r0, &l.r1, &l.r2)
			}
		}
	}

	Q1, Q2 := new(G2Affine), new(G2Affine) // var Q1, Q2 G2Affine
	for k := 0; k < n; k++ {
		//Q1 = π(Q)
		// TODO(ivokub): define phi(Q) in G2 instead of doing manually?
		Q1.X = *pr.Ext12.Ext2.Conjugate(&q[k].X)            // Q1.X.Conjugate(&q[k].X).MulByNonResidue1Power2(&Q1.X)
		Q1.X = *pr.Ext12.Ext2.MulByNonResidue1Power2(&Q1.X) // Q1.X.Conjugate(&q[k].X).MulByNonResidue1Power2(&Q1.X)
		Q1.Y = *pr.Ext12.Ext2.Conjugate(&q[k].Y)            // Q1.Y.Conjugate(&q[k].Y).MulByNonResidue1Power3(&Q1.Y)
		Q1.Y = *pr.Ext12.Ext2.MulByNonResidue1Power3(&Q1.Y) // Q1.Y.Conjugate(&q[k].Y).MulByNonResidue1Power3(&Q1.Y)

		// Q2 = -π²(Q)
		Q2.X = *pr.Ext12.Ext2.MulByNonResidue2Power2(&q[k].X) // Q2.X.MulByNonResidufields_bn254.E2Power2(&q[k].X)
		Q2.Y = *pr.Ext12.Ext2.MulByNonResidue2Power3(&q[k].Y) // Q2.Y.MulByNonResidufields_bn254.E2Power3(&q[k].Y).Neg(&Q2.Y)
		Q2.Y = *pr.Ext12.Ext2.Neg(&Q2.Y)                      // Q2.Y.MulByNonResidufields_bn254.E2Power3(&q[k].Y).Neg(&Q2.Y)

		qProj[k], l0 = pr.AddStep(qProj[k], Q1)              // qProj[k].AddMixedStep(&l0, &Q1)
		l0.r0 = *pr.Ext12.Ext2.MulByElement(&l0.r0, &p[k].Y) // l0.r0.MulByElement(&l0.r0, &p[k].Y)
		l0.r1 = *pr.Ext12.Ext2.MulByElement(&l0.r1, &p[k].X) // l0.r1.MulByElement(&l0.r1, &p[k].X)

		qProj[k], l = pr.AddStep(qProj[k], Q2)                                     // qProj[k].AddMixedStep(&l, &Q2)
		l.r0 = *pr.Ext12.Ext2.MulByElement(&l.r0, &p[k].Y)                         // l.r0.MulByElement(&l.r0, &p[k].Y)
		l.r1 = *pr.Ext12.Ext2.MulByElement(&l.r1, &p[k].X)                         // l.r1.MulByElement(&l.r1, &p[k].X)
		tmp := pr.Ext12.MulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
		result = pr.Ext12.Mul(result, tmp)                                         // result.Mul(&result, &tmp)
	}

	return result, nil
}

func (pr Pairing) FinalExponentiation(api frontend.API, e *GTEl) *GTEl {
	// var result GT
	// result.Set(z)
	var t [4]*GTEl // var t [4]GT

	// easy part
	t[0] = pr.Ext12.Conjugate(e)
	t[0] = pr.Ext12.DivUnchecked(api, *t[0], *e)
	result := pr.Ext12.FrobeniusSquare(t[0])
	result = pr.Ext12.Mul(result, t[0])

	//hard part
	t[0] = pr.Ext12.Expt(api, result)
	t[0] = pr.Ext12.Conjugate(t[0])
	t[0] = pr.Ext12.CyclotomicSquare(t[0])
	t[2] = pr.Ext12.Expt(api, t[0])
	t[2] = pr.Ext12.Conjugate(t[2])
	t[1] = pr.Ext12.CyclotomicSquare(t[2])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[2] = pr.Ext12.Mul(t[2], result)
	t[1] = pr.Ext12.Expt(api, t[2])
	t[1] = pr.Ext12.CyclotomicSquare(t[1])
	t[1] = pr.Ext12.Mul(t[1], t[2])
	t[1] = pr.Ext12.Conjugate(t[1])
	t[3] = pr.Ext12.Conjugate(t[1])
	t[1] = pr.Ext12.CyclotomicSquare(t[0])
	t[1] = pr.Ext12.Mul(t[1], result)
	t[1] = pr.Ext12.Conjugate(t[1])
	t[1] = pr.Ext12.Mul(t[1], t[3])
	t[0] = pr.Ext12.Mul(t[0], t[1])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[3] = pr.Ext12.FrobeniusSquare(t[1])
	t[2] = pr.Ext12.Mul(t[2], t[3])
	t[3] = pr.Ext12.Conjugate(result)
	t[3] = pr.Ext12.Mul(t[3], t[0])
	t[1] = pr.Ext12.FrobeniusCube(t[3])
	t[2] = pr.Ext12.Mul(t[2], t[1])
	t[1] = pr.Ext12.Frobenius(t[0])
	t[1] = pr.Ext12.Mul(t[1], t[2])

	return t[1]
}

func (pr Pairing) Pair(api frontend.API, P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(api, P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(api, res)
	return res, nil
}

func (pr Pairing) AssertIsEqual(x, y *GTEl) {
	pr.Ext12.AssertIsEqual(x, y)
}
