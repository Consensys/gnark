package gpoint

const add = `

// Add point addition in montgomery form
// no assumptions on z
// Note: calling Add with p.Equal(a) produces [0, 0, 0], call p.Double() instead
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
func (p *{{.Name}}Jac) Add(curve *Curve, a *{{.Name}}Jac) *{{.Name}}Jac {
	// p is infinity, return a
	if p.Z.IsZero() {
		p.Set(a)
		return p
	}

	// a is infinity, return p
	if a.Z.IsZero() {
		return p
	}

	// get some Element from our pool
	var Z1Z1, Z2Z2, U1, U2, S1, S2, H, I, J, r, V {{.CType}}

	// Z1Z1 = a.Z ^ 2
	Z1Z1.Square(&a.Z)

	// Z2Z2 = p.Z ^ 2
	Z2Z2.Square(&p.Z)

	// U1 = a.X * Z2Z2
	U1.Mul(&a.X, &Z2Z2)

	// U2 = p.X * Z1Z1
	U2.Mul(&p.X, &Z1Z1)

	// S1 = a.Y * p.Z * Z2Z2
	S1.Mul(&a.Y, &p.Z).
		MulAssign(&Z2Z2)

	// S2 = p.Y * a.Z * Z1Z1
	S2.Mul(&p.Y, &a.Z).
		MulAssign(&Z1Z1)

	// if p == a, we double instead
	if U1.Equal(&U2) && S1.Equal(&S2) {
		return p.Double()
	}

	// H = U2 - U1
	H.Sub(&U2, &U1)

	// I = (2*H)^2
	I.Double(&H).
	Square(&I)

	// J = H*I
	J.Mul(&H, &I)

	// r = 2*(S2-S1)
	r.Sub(&S2, &S1).Double(&r)

	// V = U1*I
	V.Mul(&U1, &I)

	// res.X = r^2-J-2*V
	p.X.Square(&r).
		SubAssign( &J).
		SubAssign( &V).
		SubAssign( &V)

	// res.Y = r*(V-X3)-2*S1*J
	p.Y.Sub(&V, &p.X).
		MulAssign( &r)
	S1.MulAssign(&J).Double(&S1)
	p.Y.SubAssign(&S1)

	// res.Z = ((a.Z+p.Z)^2-Z1Z1-Z2Z2)*H
	p.Z.AddAssign(&a.Z)
	p.Z.Square(&p.Z).
		SubAssign( &Z1Z1).
		SubAssign( &Z2Z2).
		MulAssign( &H)

	return p
}

`

const addMixed = `
// AddMixed point addition in montgomery form
// assumes a is in affine coordinates (i.e a.z == 1)
// https://hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-3.html#addition-add-2007-bl
// http://www.hyperelliptic.org/EFD/g1p/auto-shortw-jacobian-0.html#addition-madd-2007-bl
func (p *{{.Name}}Jac) AddMixed(a *{{.Name}}Affine) *{{.Name}}Jac {
	
	//if a is infinity return p
	if a.X.IsZero() && a.Y.IsZero() {
		return p
	}
	// p is infinity, return a
	if p.Z.IsZero() {
		p.X = a.X
		p.Y = a.Y
		// p.Z.Set(&curve.{{toLower .Name}}sZero.X)
		p.Z.SetOne()
		return p
	}

	// get some Element from our pool
	var Z1Z1,  U2 , S2, H, HH, I, J, r, V {{.CType}}

	// Z1Z1 = p.Z ^ 2
	Z1Z1.Square(&p.Z)

	// U2 = a.X * Z1Z1
	U2.Mul(&a.X, &Z1Z1)

	// S2 = a.Y * p.Z * Z1Z1
	S2.Mul(&a.Y, &p.Z).
		MulAssign(&Z1Z1)

	// if p == a, we double instead
	if U2.Equal(&p.X) && S2.Equal(&p.Y) {
		return p.Double()
	}

	// H = U2 - p.X
	H.Sub(&U2, &p.X)
	HH.Square(&H)

	// I = 4*HH
	I.Double(&HH).Double(&I)

	// J = H*I
	J.Mul(&H, &I)

	// r = 2*(S2-Y1)
	r.Sub(&S2, &p.Y).Double(&r)

	// V = X1*I
	V.Mul(&p.X, &I)

	// res.X = r^2-J-2*V
	p.X.Square(&r).
		SubAssign(&J).
		SubAssign(&V).
		SubAssign(&V)

	// res.Y = r*(V-X3)-2*Y1*J
	J.MulAssign(&p.Y).Double(&J)
	p.Y.Sub(&V, &p.X).
		MulAssign(&r)
	p.Y.SubAssign(&J)

	// res.Z =  (p.Z+H)^2-Z1Z1-HH 
	p.Z.AddAssign(&H)
	p.Z.Square(&p.Z).
		SubAssign(&Z1Z1).
		SubAssign(&HH)

	return p
}
`
