package gpoint

const double = `

// Double doubles a point in Jacobian coordinates
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#doubling-dbl-2007-bl
func (p *{{.Name}}Jac) Double() *{{.Name}}Jac {
	// get some Element from our pool
	var XX, YY, YYYY, ZZ, S, M, T {{.CType}}

	// XX = a.X^2
	XX.Square(&p.X)

	// YY = a.Y^2
	YY.Square(&p.Y)

	// YYYY = YY^2
	YYYY.Square(&YY)

	// ZZ = Z1^2
	ZZ.Square(&p.Z)

	// S = 2*((X1+YY)^2-XX-YYYY)
	S.Add(&p.X, &YY)
	S.Square(&S).
		SubAssign(&XX).
		SubAssign(&YYYY).
		Double(&S)

	// M = 3*XX+a*ZZ^2
	M.Double(&XX).AddAssign(&XX)

	// res.Z = (Y1+Z1)^2-YY-ZZ
	p.Z.AddAssign(&p.Y).
		Square(&p.Z).
		SubAssign( &YY).
		SubAssign( &ZZ)

	// T = M2-2*S && res.X = T
	T.Square(&M)
	p.X = T
	T.Double(&S)
	p.X.SubAssign(&T)

	// res.Y = M*(S-T)-8*YYYY
	p.Y.Sub(&S, &p.X).
		MulAssign(&M)
	YYYY.Double(&YYYY).Double(&YYYY).Double(&YYYY)
	p.Y.SubAssign(&YYYY)

	return p
}
`
