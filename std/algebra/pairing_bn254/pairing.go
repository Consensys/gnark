package pairing_bn254

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/emulated"
)

type Pairing struct {
	*ext12
}

func NewPairing(api frontend.API) (*Pairing, error) {
	ba, err := emulated.NewField[emulated.BN254Fp](api)
	if err != nil {
		return nil, fmt.Errorf("new base api: %w", err)
	}
	return &Pairing{
		ext12: newExt12(ba),
	}, nil
}

func (pr Pairing) doubleStep(p *g2Projective) (*g2Projective, *lineEvaluation) {
	// var t1, A, B, C, D, E, EE, F, G, H, I, J, K fptower.E2
	A := pr.ext2.mul(&p.X, &p.Y)          // A.Mul(&p.x, &p.y)
	A = pr.ext2.halve(A)                  // A.Halve()
	B := pr.ext2.square(&p.Y)             // B.Square(&p.y)
	C := pr.ext2.square(&p.Z)             // C.Square(&p.z)
	D := pr.ext2.double(C)                // D.Double(&C).
	D = pr.ext2.add(D, C)                 // 	Add(&D, &C)
	E := pr.ext2.mulBybTwistCurveCoeff(D) // E.MulBybTwistCurveCoeff(&D)
	F := pr.ext2.double(E)                // F.Double(&E).
	F = pr.ext2.add(F, E)                 // 	Add(&F, &E)
	G := pr.ext2.add(B, F)                // G.Add(&B, &F)
	G = pr.ext2.halve(G)                  // G.Halve()
	H := pr.ext2.add(&p.Y, &p.Z)          // H.Add(&p.y, &p.z).
	H = pr.ext2.square(H)                 // 	Square(&H)
	t1 := pr.ext2.add(B, C)               // t1.Add(&B, &C)
	H = pr.ext2.sub(H, t1)                // H.Sub(&H, &t1)
	I := pr.ext2.sub(E, B)                // I.Sub(&E, &B)
	J := pr.ext2.square(&p.X)             // J.Square(&p.x)
	EE := pr.ext2.square(E)               // EE.Square(&E)
	K := pr.ext2.double(EE)               // K.Double(&EE).
	K = pr.ext2.add(K, EE)                // 	Add(&K, &EE)
	px := pr.ext2.sub(B, F)               // p.x.Sub(&B, &F).
	px = pr.ext2.mul(px, A)               // 	Mul(&p.x, &A)
	py := pr.ext2.square(G)               // p.y.Square(&G).
	py = pr.ext2.sub(py, K)               // 	Sub(&p.y, &K)
	pz := pr.ext2.mul(B, H)               // p.z.Mul(&B, &H)
	ev0 := pr.ext2.neg(H)                 // evaluations.r0.Neg(&H)
	ev1 := pr.ext2.double(J)              // evaluations.r1.Double(&J).
	ev1 = pr.ext2.add(ev1, J)             // 	Add(&evaluations.r1, &J)
	ev2 := I                              // evaluations.r2.Set(&I)
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
	pz := pr.ext2.one()   // p.z.SetOne()
	px := &Q.X            // p.x.Set(&Q.X)
	py := &Q.Y            // p.y.Set(&Q.Y)
	return &g2Projective{ // return p
		X: *px,
		Y: *py,
		Z: *pz,
	}
}

func (pr Pairing) negAffine(a *G2Affine) *G2Affine {
	px := &a.X              // p.X = a.X
	py := pr.ext2.neg(&a.Y) // p.Y.Neg(&a.Y)
	return &G2Affine{       // return p
		X: *px,
		Y: *py,
	}
}

func (pr Pairing) addStep(p *g2Projective, a *G2Affine) (*g2Projective, *lineEvaluation) {
	// var Y2Z1, X2Z1, O, L, C, D, E, F, G, H, t0, t1, t2, J fptower.E2
	Y2Z1 := pr.ext2.mul(&a.Y, &p.Z) // Y2Z1.Mul(&a.Y, &p.z)
	O := pr.ext2.sub(&p.Y, Y2Z1)    // O.Sub(&p.y, &Y2Z1)
	X2Z1 := pr.ext2.mul(&a.X, &p.Z) // X2Z1.Mul(&a.X, &p.z)
	L := pr.ext2.sub(&p.X, X2Z1)    // L.Sub(&p.x, &X2Z1)
	C := pr.ext2.square(O)          // C.Square(&O)
	D := pr.ext2.square(L)          // D.Square(&L)
	E := pr.ext2.mul(L, D)          // E.Mul(&L, &D)
	F := pr.ext2.mul(&p.Z, C)       // F.Mul(&p.z, &C)
	G := pr.ext2.mul(&p.X, D)       // G.Mul(&p.x, &D)
	t0 := pr.ext2.double(G)         // t0.Double(&G)
	H := pr.ext2.add(E, F)          // H.Add(&E, &F).
	H = pr.ext2.sub(H, t0)          // 	Sub(&H, &t0)
	t1 := pr.ext2.mul(&p.Y, E)      // t1.Mul(&p.y, &E)
	px := pr.ext2.mul(L, H)         // p.x.Mul(&L, &H)
	py := pr.ext2.sub(G, H)         // p.y.Sub(&G, &H).
	py = pr.ext2.mul(py, O)         // 	Mul(&p.y, &O).
	py = pr.ext2.sub(py, t1)        // 	Sub(&p.y, &t1)
	pz := pr.ext2.mul(E, &p.Z)      // p.z.Mul(&E, &p.z)
	t2 := pr.ext2.mul(L, &a.Y)      // t2.Mul(&L, &a.Y)
	J := pr.ext2.mul(&a.X, O)       // J.Mul(&a.X, &O).
	J = pr.ext2.sub(J, t2)          // 	Sub(&J, &t2)
	ev0 := L                        // evaluations.r0.Set(&L)
	ev1 := pr.ext2.neg(O)           // evaluations.r1.Neg(&O)
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
	r0 e2
	r1 e2
	r2 e2
}

var loopCounter = [66]int8{
	0, 0, 0, 1, 0, 1, 0, -1, 0, 0, -1,
	0, 0, 0, 1, 0, 0, -1, 0, -1, 0, 0,
	0, 1, 0, -1, 0, 0, 0, 0, -1, 0, 0,
	1, 0, -1, 0, 0, 1, 0, 0, 0, 0, 0,
	-1, 0, 0, -1, 0, 1, 0, -1, 0, 0, 0,
	-1, 0, -1, 0, 0, 0, 1, 0, -1, 0, 1,
}

func (pr Pairing) MillerLoop(p []*G1Affine, q []*G2Affine) (*GTEl, error) {
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
		qNeg[k] = pr.negAffine(q[k])           // qNeg[k].Neg(&q[k])
	}

	var l, l0 *lineEvaluation
	result := pr.ext12.one() // var tmp, result GTEl

	// i == len(loopCounter) - 2
	for k := 0; k < n; k++ {
		qProj[k], l = pr.doubleStep(qProj[k])                   // qProj[k].DoubleStep(&l)
		l.r0 = *pr.ext12.ext2.mulByElement(&l.r0, &p[k].Y)      // l.r0.MulByElement(&l.r0, &p[k].Y)
		l.r1 = *pr.ext12.ext2.mulByElement(&l.r1, &p[k].X)      // l.r1.MulByElement(&l.r1, &p[k].X)
		result = pr.ext12.mulBy034(result, &l.r0, &l.r1, &l.r2) // result.MulBy034(&l.r0, &l.r1, &l.r2)
	}

	for i := len(loopCounter) - 3; i >= 0; i-- {
		result = pr.ext12.square(result) // result.Square(&result)

		for k := 0; k < n; k++ {
			qProj[k], l = pr.doubleStep(qProj[k])              // qProj[k].DoubleStep(&l)
			l.r0 = *pr.ext12.ext2.mulByElement(&l.r0, &p[k].Y) // l.r0.MulByElement(&l.r0, &p[k].Y)
			l.r1 = *pr.ext12.ext2.mulByElement(&l.r1, &p[k].X) // l.r1.MulByElement(&l.r1, &p[k].X)

			if loopCounter[i] == 1 {
				qProj[k], l0 = pr.addStep(qProj[k], q[k])                                  // qProj[k].AddMixedStep(&l0, &q[k])
				l0.r0 = *pr.ext12.ext2.mulByElement(&l0.r0, &p[k].Y)                       // l0.r0.MulByElement(&l0.r0, &p[k].Y)
				l0.r1 = *pr.ext12.ext2.mulByElement(&l0.r1, &p[k].X)                       // l0.r1.MulByElement(&l0.r1, &p[k].X)
				tmp := pr.ext12.mulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.ext12.mul(result, tmp)                                         // result.Mul(&result, &tmp)
			} else if loopCounter[i] == -1 {
				qProj[k], l0 = pr.addStep(qProj[k], qNeg[k])                               // qProj[k].AddMixedStep(&l0, &qNeg[k])
				l0.r0 = *pr.ext12.ext2.mulByElement(&l0.r0, &p[k].Y)                       // l0.r0.MulByElement(&l0.r0, &p[k].Y)
				l0.r1 = *pr.ext12.ext2.mulByElement(&l0.r1, &p[k].X)                       // l0.r1.MulByElement(&l0.r1, &p[k].X)
				tmp := pr.ext12.mulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
				result = pr.ext12.mul(result, tmp)                                         //result.Mul(&result, &tmp)
			} else {
				result = pr.ext12.mulBy034(result, &l.r0, &l.r1, &l.r2) // result.MulBy034(&l.r0, &l.r1, &l.r2)
			}
		}
	}

	Q1, Q2 := new(G2Affine), new(G2Affine) // var Q1, Q2 G2Affine
	for k := 0; k < n; k++ {
		//Q1 = π(Q)
		// TODO(ivokub): define phi(Q) in G2 instead of doing manually?
		Q1.X = *pr.ext12.ext2.conjugate(&q[k].X)            // Q1.X.Conjugate(&q[k].X).MulByNonResidue1Power2(&Q1.X)
		Q1.X = *pr.ext12.ext2.mulByNonResidue1Power2(&Q1.X) // Q1.X.Conjugate(&q[k].X).MulByNonResidue1Power2(&Q1.X)
		Q1.Y = *pr.ext12.ext2.conjugate(&q[k].Y)            // Q1.Y.Conjugate(&q[k].Y).MulByNonResidue1Power3(&Q1.Y)
		Q1.Y = *pr.ext12.ext2.mulByNonResidue1Power3(&Q1.Y) // Q1.Y.Conjugate(&q[k].Y).MulByNonResidue1Power3(&Q1.Y)

		// Q2 = -π²(Q)
		Q2.X = *pr.ext12.ext2.mulByNonResidue2Power2(&q[k].X) // Q2.X.MulByNonResidue2Power2(&q[k].X)
		Q2.Y = *pr.ext12.ext2.mulByNonResidue2Power3(&q[k].Y) // Q2.Y.MulByNonResidue2Power3(&q[k].Y).Neg(&Q2.Y)
		Q2.Y = *pr.ext12.ext2.neg(&Q2.Y)                      // Q2.Y.MulByNonResidue2Power3(&q[k].Y).Neg(&Q2.Y)

		qProj[k], l0 = pr.addStep(qProj[k], Q1)              // qProj[k].AddMixedStep(&l0, &Q1)
		l0.r0 = *pr.ext12.ext2.mulByElement(&l0.r0, &p[k].Y) // l0.r0.MulByElement(&l0.r0, &p[k].Y)
		l0.r1 = *pr.ext12.ext2.mulByElement(&l0.r1, &p[k].X) // l0.r1.MulByElement(&l0.r1, &p[k].X)

		qProj[k], l = pr.addStep(qProj[k], Q2)                                     // qProj[k].AddMixedStep(&l, &Q2)
		l.r0 = *pr.ext12.ext2.mulByElement(&l.r0, &p[k].Y)                         // l.r0.MulByElement(&l.r0, &p[k].Y)
		l.r1 = *pr.ext12.ext2.mulByElement(&l.r1, &p[k].X)                         // l.r1.MulByElement(&l.r1, &p[k].X)
		tmp := pr.ext12.mulBy034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2) // tmp.Mul034by034(&l.r0, &l.r1, &l.r2, &l0.r0, &l0.r1, &l0.r2)
		result = pr.ext12.mul(result, tmp)                                         // result.Mul(&result, &tmp)
	}

	return result, nil
}

func (pr Pairing) FinalExponentiation(e *GTEl) *GTEl {
	// var result GT
	// result.Set(z)
	var t [4]*GTEl // var t [4]GT

	// easy part
	t[0] = pr.ext12.conjugate(e)            // t[0].Conjugate(&result)
	result := pr.ext12.inverse(e)           // result.Inverse(&result)
	t[0] = pr.ext12.mul(t[0], result)       // t[0].Mul(&t[0], &result)
	result = pr.ext12.frobeniusSquare(t[0]) // result.FrobeniusSquare(&t[0]).
	result = pr.ext12.mul(result, t[0])     // 	Mul(&result, &t[0])

	//hard part
	t[0] = pr.ext12.expt(result)           // t[0].Expt(&result).
	t[0] = pr.ext12.conjugate(t[0])        // 	Conjugate(&t[0])
	t[0] = pr.ext12.cyclotomicSquare(t[0]) // t[0].CyclotomicSquare(&t[0])
	t[2] = pr.ext12.expt(t[0])             // t[2].Expt(&t[0]).
	t[2] = pr.ext12.conjugate(t[2])        // 	Conjugate(&t[2])
	t[1] = pr.ext12.cyclotomicSquare(t[2]) // t[1].CyclotomicSquare(&t[2])
	t[2] = pr.ext12.mul(t[2], t[1])        // t[2].Mul(&t[2], &t[1])
	t[2] = pr.ext12.mul(t[2], result)      // t[2].Mul(&t[2], &result)
	t[1] = pr.ext12.expt(t[2])             // t[1].Expt(&t[2]).
	t[1] = pr.ext12.cyclotomicSquare(t[1]) // 	CyclotomicSquare(&t[1]).
	t[1] = pr.ext12.mul(t[1], t[2])        // 	Mul(&t[1], &t[2]).
	t[1] = pr.ext12.conjugate(t[1])        // 	Conjugate(&t[1])
	t[3] = pr.ext12.conjugate(t[1])        // t[3].Conjugate(&t[1])
	t[1] = pr.ext12.cyclotomicSquare(t[0]) // t[1].CyclotomicSquare(&t[0])
	t[1] = pr.ext12.mul(t[1], result)      // t[1].Mul(&t[1], &result)
	t[1] = pr.ext12.conjugate(t[1])        // t[1].Conjugate(&t[1])
	t[1] = pr.ext12.mul(t[1], t[3])        // t[1].Mul(&t[1], &t[3])
	t[0] = pr.ext12.mul(t[0], t[1])        // t[0].Mul(&t[0], &t[1])
	t[2] = pr.ext12.mul(t[2], t[1])        // t[2].Mul(&t[2], &t[1])
	t[3] = pr.ext12.frobeniusSquare(t[1])  // t[3].FrobeniusSquare(&t[1])
	t[2] = pr.ext12.mul(t[2], t[3])        // t[2].Mul(&t[2], &t[3])
	t[3] = pr.ext12.conjugate(result)      // t[3].Conjugate(&result)
	t[3] = pr.ext12.mul(t[3], t[0])        // t[3].Mul(&t[3], &t[0])
	t[1] = pr.ext12.frobeniusCube(t[3])    // t[1].FrobeniusCube(&t[3])
	t[2] = pr.ext12.mul(t[2], t[1])        // t[2].Mul(&t[2], &t[1])
	t[1] = pr.ext12.frobenius(t[0])        // t[1].Frobenius(&t[0])
	t[1] = pr.ext12.mul(t[1], t[2])        // t[1].Mul(&t[1], &t[2])
	// result.Set(&t[1])
	return t[1] // return result
}

func (pr Pairing) Pair(P []*G1Affine, Q []*G2Affine) (*GTEl, error) {
	res, err := pr.MillerLoop(P, Q)
	if err != nil {
		return nil, fmt.Errorf("miller loop: %w", err)
	}
	res = pr.FinalExponentiation(res)
	return res, nil
}
