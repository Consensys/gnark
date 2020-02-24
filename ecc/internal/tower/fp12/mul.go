package fp12

const mul = `
// Mul set z=x*y in {{.Name}} and return z
func (z *{{.Name}}) Mul(x, y *{{.Name}}) *{{.Name}} {
	// Algorithm 20 from https://eprint.iacr.org/2010/354.pdf

	var t0, t1, xSum, ySum e6

	t0.Mul(&x.C0, &y.C0) // step 1
	t1.Mul(&x.C1, &y.C1) // step 2

	// finish processing input in case z==x or y
	xSum.Add(&x.C0, &x.C1)
	ySum.Add(&y.C0, &y.C1)

	// step 3
	{{- template "fp6InlineMulByNonResidue" dict "all" . "out" "z.C0" "in" "&t1" }}
	z.C0.Add(&z.C0, &t0)                             

	// step 4
	z.C1.Mul(&xSum, &ySum).
		Sub(&z.C1, &t0).
		Sub(&z.C1, &t1)

	return z
}

// Square set z=x*x in {{.Name}} and return z
func (z *{{.Name}}) Square(x *{{.Name}}) *{{.Name}} {
	// TODO implement Algorithm 22 from https://eprint.iacr.org/2010/354.pdf
	// or the complex method from fp2
	// for now do it the dumb way
	var b0, b1 {{.Fp6Name}}

	b0.Square(&x.C0)
	b1.Square(&x.C1)
	{{- template "fp6InlineMulByNonResidue" dict "all" . "out" "b1" "in" "&b1" }}
	b1.Add(&b0, &b1)

	z.C1.Mul(&x.C0, &x.C1).Double(&z.C1)
	z.C0 = b1

	return z
}

// Inverse set z to the inverse of x in {{.Name}} and return z
func (z *{{.Name}}) Inverse(x *{{.Name}}) *{{.Name}} {
	// Algorithm 23 from https://eprint.iacr.org/2010/354.pdf

	var t [2]{{.Fp6Name}}

	t[0].Square(&x.C0) // step 1
	t[1].Square(&x.C1) // step 2
	{ // step 3
		var buf {{.Fp6Name}}
		{{- template "fp6InlineMulByNonResidue" dict "all" . "out" "buf" "in" "&t[1]" }}
		t[0].Sub(&t[0], &buf)
	}
	t[1].Inverse(&t[0]) // step 4
	z.C0.Mul(&x.C0, &t[1]) // step 5
	z.C1.Mul(&x.C1, &t[1]).Neg(&z.C1) // step 6

	return z
}

// InverseUnitary inverse a unitary element
// TODO deprecate in favour of Conjugate
func (z *{{.Name}}) InverseUnitary(x *{{.Name}}) *{{.Name}} {
	return z.Conjugate(x)
}

// Conjugate set z to (x.C0, -x.C1) and return z
func (z *{{.Name}}) Conjugate(x *{{.Name}}) *{{.Name}} {
	z.Set(x)
	z.C1.Neg(&z.C1)
	return z
}

// MulByVW set z to x*(y*v*w) and return z
// here y*v*w means the {{.Name}} element with C1.B1=y and all other components 0
func (z *{{.Name}}) MulByVW(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNR {{.Fp2Name}}
	{{ template "fp2InlineMulByNonResidue" dict "all" . "out" "yNR" "in" "y" }}
	result.C0.B0.Mul(&x.C1.B1, &yNR)
	result.C0.B1.Mul(&x.C1.B2, &yNR)
	result.C0.B2.Mul(&x.C1.B0, y)
	result.C1.B0.Mul(&x.C0.B2, &yNR)
	result.C1.B1.Mul(&x.C0.B0, y)
	result.C1.B2.Mul(&x.C0.B1, y)
	z.Set(&result)
	return z
}

// MulByV set z to x*(y*v) and return z
// here y*v means the {{.Name}} element with C0.B1=y and all other components 0
func (z *{{.Name}}) MulByV(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNR {{.Fp2Name}}
	{{ template "fp2InlineMulByNonResidue" dict "all" . "out" "yNR" "in" "y" }}
	result.C0.B0.Mul(&x.C0.B2, &yNR)
	result.C0.B1.Mul(&x.C0.B0, y)
	result.C0.B2.Mul(&x.C0.B1, y)
	result.C1.B0.Mul(&x.C1.B2, &yNR)
	result.C1.B1.Mul(&x.C1.B0, y)
	result.C1.B2.Mul(&x.C1.B1, y)
	z.Set(&result)
	return z
}

// MulByV2W set z to x*(y*v^2*w) and return z
// here y*v^2*w means the {{.Name}} element with C1.B2=y and all other components 0
func (z *{{.Name}}) MulByV2W(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNR {{.Fp2Name}}
	{{ template "fp2InlineMulByNonResidue" dict "all" . "out" "yNR" "in" "y" }}
	result.C0.B0.Mul(&x.C1.B0, &yNR)
	result.C0.B1.Mul(&x.C1.B1, &yNR)
	result.C0.B2.Mul(&x.C1.B2, &yNR)
	result.C1.B0.Mul(&x.C0.B1, &yNR)
	result.C1.B1.Mul(&x.C0.B2, &yNR)
	result.C1.B2.Mul(&x.C0.B0, y)
	z.Set(&result)
	return z
}

// MulByV2NRInv set z to x*(y*v^2*({{.Fp6NonResidue}})^{-1}) and return z
// here y*v^2 means the {{.Name}} element with C0.B2=y and all other components 0
func (z *{{.Name}}) MulByV2NRInv(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNRInv {{.Fp2Name}}

	{{ template "fp2InlineMulByNonResidueInv" dict "all" . "out" "yNRInv" "in" "y" }}

	result.C0.B0.Mul(&x.C0.B1, y)
	result.C0.B1.Mul(&x.C0.B2, y)
	result.C0.B2.Mul(&x.C0.B0, &yNRInv)

	result.C1.B0.Mul(&x.C1.B1, y)
	result.C1.B1.Mul(&x.C1.B2, y)
	result.C1.B2.Mul(&x.C1.B0, &yNRInv)

	z.Set(&result)
	return z
}

// MulByVWNRInv set z to x*(y*v*w*({{.Fp6NonResidue}})^{-1}) and return z
// here y*v*w means the {{.Name}} element with C1.B1=y and all other components 0
func (z *{{.Name}}) MulByVWNRInv(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNRInv {{.Fp2Name}}

	{{ template "fp2InlineMulByNonResidueInv" dict "all" . "out" "yNRInv" "in" "y" }}

	result.C0.B0.Mul(&x.C1.B1, y)
	result.C0.B1.Mul(&x.C1.B2, y)
	result.C0.B2.Mul(&x.C1.B0, &yNRInv)

	result.C1.B0.Mul(&x.C0.B2, y)
	result.C1.B1.Mul(&x.C0.B0, &yNRInv)
	result.C1.B2.Mul(&x.C0.B1, &yNRInv)

	z.Set(&result)
	return z
}

// MulByWNRInv set z to x*(y*w*({{.Fp6NonResidue}})^{-1}) and return z
// here y*w means the {{.Name}} element with C1.B0=y and all other components 0
func (z *{{.Name}}) MulByWNRInv(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var result {{.Name}}
	var yNRInv {{.Fp2Name}}

	{{ template "fp2InlineMulByNonResidueInv" dict "all" . "out" "yNRInv" "in" "y" }}

	result.C0.B0.Mul(&x.C1.B2, y)
	result.C0.B1.Mul(&x.C1.B0, &yNRInv)
	result.C0.B2.Mul(&x.C1.B1, &yNRInv)

	result.C1.B0.Mul(&x.C0.B0, &yNRInv)
	result.C1.B1.Mul(&x.C0.B1, &yNRInv)
	result.C1.B2.Mul(&x.C0.B2, &yNRInv)

	z.Set(&result)
	return z
}

// MulByNonResidue multiplies a {{.Fp6Name}} by ((0,0),(1,0),(0,0))
func (z *{{.Fp6Name}}) MulByNonResidue(x *{{.Fp6Name}}) *{{.Fp6Name}} {
	{{- template "fp6MulByNonResidueBody" dict "all" . "out" "z" "in" "x" }}
	return z
}
`
