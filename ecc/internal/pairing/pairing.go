package pairing

const pairing = `
// FinalExponentiation computes the final expo x**(p**6-1)(p**2+1)(p**4 - p**2 +1)/r
func (curve *Curve) FinalExponentiation(z *{{.Fp12Name}}, _z ...*{{.Fp12Name}}) {{.Fp12Name}} {
	var result {{.Fp12Name}}
	result.Set(z)

	// if additional parameters are provided, multiply them into z
	for _, e := range _z {
		result.Mul(&result, e)
	}

	// memalloc
	var t [6]{{.Fp12Name}}

	// buf = x**(p^6-1)
	t[0].FrobeniusCube(&result).
		FrobeniusCube(&t[0])

	result.Inverse(&result)
	t[0].Mul(&t[0], &result)

	// z = (x**(p^6-1)) ^(p^2+1)
	result.FrobeniusSquare(&t[0]).
		Mul(&result, &t[0])

	// hard part (up to permutation)
	// performs the hard part of the final expo
	// The result is the same as p**4-p**2+1/r, but up to permutation (it's 3* (p**4 -p**2 +1 /r)), ok since r=1 mod 3)

	t[0].InverseUnitary(&result).Square(&t[0])
	t[5].Expt(&result)
	t[1].Square(&t[5])
	t[3].Mul(&t[0], &t[5])

	t[0].Expt(&t[3])
	t[2].Expt(&t[0])
	t[4].Expt(&t[2])

	t[4].Mul(&t[1], &t[4])
	t[1].Expt(&t[4])
	t[3].InverseUnitary(&t[3])
	t[1].Mul(&t[3], &t[1])
	t[1].Mul(&t[1], &result)

	t[0].Mul(&t[0], &result)
	t[0].FrobeniusCube(&t[0])

	t[3].InverseUnitary(&result)
	t[4].Mul(&t[3], &t[4])
	t[4].Frobenius(&t[4])

	t[5].Mul(&t[2], &t[5])
	t[5].FrobeniusSquare(&t[5])

	t[5].Mul(&t[5], &t[0])
	t[5].Mul(&t[5], &t[4])
	t[5].Mul(&t[5], &t[1])

	result.Set(&t[5])

	return result
}

// MillerLoop Miller loop
func (curve *Curve) MillerLoop(P G1Affine, Q G2Affine, result *{{.Fp12Name}}) *{{.Fp12Name}} {

	// init result
	result.SetOne()

	if P.IsInfinity() || Q.IsInfinity() {
		return result
	}

	// the line goes through QCur and QNext
	var QCur, QNext, QNextNeg G2Jac
	var QNeg G2Affine

	// Stores -Q
	QNeg.Neg(&Q)

	// init QCur with Q
	Q.ToJacobian(&QCur)

	var lEval lineEvalRes

	// Miller loop
	for i := 62; i >= 0; i-- {
		QNext.Set(&QCur)
		QNext.Double()
		QNextNeg.Neg(&QNext)

		result.Square(result)

		// evaluates line though Qcur,2Qcur at P
		lineEvalJac(QCur, QNextNeg, &P, &lEval)
		lEval.mulAssign(result)

		if curve.loopCounter[i] == 1 {
			// evaluates line through 2Qcur, Q at P
			lineEvalAffine(QNext, Q, &P, &lEval)
			lEval.mulAssign(result)

			QNext.AddMixed(&Q)

		} else if curve.loopCounter[i] == -1 {
			// evaluates line through 2Qcur, -Q at P
			lineEvalAffine(QNext, QNeg, &P, &lEval)
			lEval.mulAssign(result)

			QNext.AddMixed(&QNeg)
		}
		QCur.Set(&QNext)
	}

	return result
}

// lineEval computes the evaluation of the line through Q, R (on the twist) at P
// Q, R are in jacobian coordinates
// The case in which Q=R=Infinity is not handled as this doesn't happen in the SNARK pairing
func lineEvalJac(Q, R G2Jac, P *G1Affine, result *lineEvalRes) {
	// converts Q and R to projective coords
	Q.ToProjFromJac()
	R.ToProjFromJac()

	// line eq: w^3*(QyRz-QzRy)x +  w^2*(QzRx - QxRz)y + w^5*(QxRy-QyRxz)
	// result.r1 = QyRz-QzRy
	// result.r0 = QzRx - QxRz
	// result.r2 = QxRy-QyRxz

	result.r1.Mul(&Q.Y, &R.Z)
	result.r0.Mul(&Q.Z, &R.X)
	result.r2.Mul(&Q.X, &R.Y)

	Q.Z.Mul(&Q.Z, &R.Y)
	Q.X.Mul(&Q.X, &R.Z)
	Q.Y.Mul(&Q.Y, &R.X)

	result.r1.Sub(&result.r1, &Q.Z)
	result.r0.Sub(&result.r0, &Q.X)
	result.r2.Sub(&result.r2, &Q.Y)

	// multiply P.Z by coeffs[2] in case P is infinity
	result.r1.MulByElement(&result.r1, &P.X)
	result.r0.MulByElement(&result.r0, &P.Y)
	//result.r2.MulByElement(&result.r2, &P.Z)
}

// Same as above but R is in affine coords
func lineEvalAffine(Q G2Jac, R G2Affine, P *G1Affine, result *lineEvalRes) {

	// converts Q and R to projective coords
	Q.ToProjFromJac()

	// line eq: w^3*(QyRz-QzRy)x +  w^2*(QzRx - QxRz)y + w^5*(QxRy-QyRxz)
	// result.r1 = QyRz-QzRy
	// result.r0 = QzRx - QxRz
	// result.r2 = QxRy-QyRxz

	result.r1.Set(&Q.Y)
	result.r0.Mul(&Q.Z, &R.X)
	result.r2.Mul(&Q.X, &R.Y)

	Q.Z.Mul(&Q.Z, &R.Y)
	Q.Y.Mul(&Q.Y, &R.X)

	result.r1.Sub(&result.r1, &Q.Z)
	result.r0.Sub(&result.r0, &Q.X)
	result.r2.Sub(&result.r2, &Q.Y)

	// multiply P.Z by coeffs[2] in case P is infinity
	result.r1.MulByElement(&result.r1, &P.X)
	result.r0.MulByElement(&result.r0, &P.Y)
	// result.r2.MulByElement(&result.r2, &P.Z)
}

type lineEvalRes struct {
	r0 {{.Fp2Name}} // c0.b1
	r1 {{.Fp2Name}} // c1.b1
	r2 {{.Fp2Name}} // c1.b2
}

func (l *lineEvalRes) mulAssign(z *{{.Fp12Name}}) *{{.Fp12Name}} {
	var buf [3]{{.Fp6Name}}

	// mul z.c0 by l.r0 (that's {{.Fp6Name}} multiplication with y.b0 == y.b2 == 0)
	buf[0].B2.Mul(&z.C0.B1, &l.r0)
	buf[0].B0.Add(&z.C0.B1, &z.C0.B2).
		Mul(&buf[0].B0, &l.r0).
		Sub(&buf[0].B0, &buf[0].B2).
		MulByNonSquare(&buf[0].B0)

	buf[0].B1.Add(&z.C0.B0, &z.C0.B1).
		Mul(&buf[0].B1, &l.r0).
		Sub(&buf[0].B1, &buf[0].B2)

	{{.Fp6Name}}Mulb1b2(&buf[1], &z.C1, &l.r1, &l.r2)
	buf[2].Add(&z.C0, &z.C1)

	var b1 {{.Fp2Name}}
	b1.Add(&l.r0, &l.r1)

	z.C0.Set(&buf[1]).
		MulByGen(&z.C0).
		Add(&z.C0, &buf[0])
	{{.Fp6Name}}Mulb1b2(&z.C1, &buf[2], &b1, &l.r2).
		Sub(&z.C1, &buf[0]).
		Sub(&z.C1, &buf[1])

	return z
}

func {{.Fp6Name}}Mulb1b2(result, x *{{.Fp6Name}}, b1, b2 *{{.Fp2Name}}) *{{.Fp6Name}} {
	// {{.Fp6Name}}.Mul with  y.b1  & y.b2 are set, y.b0 == 0
	var t1, t2 {{.Fp2Name}}
	var buf [2]{{.Fp2Name}}

	t1.Mul(&x.B1, b1)
	t2.Mul(&x.B2, b2)

	buf[0].Add(&x.B1, &x.B2)
	buf[1].Add(b1, b2)

	result.B0.Mul(&buf[0], &buf[1]).
		Sub(&result.B0, &t1).
		Sub(&result.B0, &t2).
		MulByNonSquare(&result.B0)

	buf[0].Add(&x.B0, &x.B1)
	buf[1].Set(b1)
	result.B1.Mul(&buf[0], &buf[1]).
		Sub(&result.B1, &t1)
	result.B1.Add(&result.B1, buf[0].MulByNonSquare(&t2))

	buf[0].Add(&x.B0, &x.B2)
	buf[1].Set(b2)
	result.B2.Mul(&buf[0], &buf[1]).
		Sub(&result.B2, &t2).
		Add(&result.B2, &t1)

	return result
}
`
