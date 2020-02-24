package fp6

const mul = `
// Mul multiplies two numbers in {{.Name}}
func (z *{{.Name}}) Mul(x, y *{{.Name}}) *{{.Name}} {
	// Algorithm 13 from https://eprint.iacr.org/2010/354.pdf
	var rb0, b0, b1, b2, b3, b4 {{.Fp2Name}}

	b0.Mul(&x.B0, &y.B0) // step 1
	b1.Mul(&x.B1, &y.B1) // step 2
	b2.Mul(&x.B2, &y.B2) // step 3

	// step 4
	b3.Add(&x.B1, &x.B2)
	b4.Add(&y.B1, &y.B2)
	rb0.Mul(&b3, &b4).
		SubAssign(&b1).
		SubAssign(&b2)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "rb0" "in" "&rb0" }}
	rb0.AddAssign(&b0)

	// step 5
	b3.Add(&x.B0, &x.B1)
	b4.Add(&y.B0, &y.B1)
	z.B1.Mul(&b3, &b4).
		SubAssign(&b0).
		SubAssign(&b1)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "b3" "in" "&b2" }}
	z.B1.AddAssign(&b3)

	// step 6
	b3.Add(&x.B0, &x.B2)
	b4.Add(&y.B0, &y.B2)
	z.B2.Mul(&b3, &b4).
		SubAssign(&b0).
		SubAssign(&b2).
		AddAssign(&b1)

	z.B0 = rb0
	return z
}

// MulBy{{capitalize .Fp2Name}} multiplies x by an elements of {{.Fp2Name}}
func (z *{{.Name}}) MulBy{{capitalize .Fp2Name}}(x *{{.Name}}, y *{{.Fp2Name}}) *{{.Name}} {
	var yCopy {{.Fp2Name}}
	yCopy.Set(y)
	z.B0.Mul(&x.B0, &yCopy)
	z.B1.Mul(&x.B1, &yCopy)
	z.B2.Mul(&x.B2, &yCopy)
	return z
}

// MulByNotv2 multiplies x by y with &y.b2=0
func (z *{{.Name}}) MulByNotv2(x, y *{{.Name}}) *{{.Name}} {
	// Algorithm 15 from https://eprint.iacr.org/2010/354.pdf
	var rb0, b0, b1, b2, b3 {{.Fp2Name}}

	b0.Mul(&x.B0, &y.B0) // step 1
	b1.Mul(&x.B1, &y.B1) // step 2

	// step 3
	b2.Add(&x.B1, &x.B2)
	rb0.Mul(&b2, &y.B1).
		SubAssign(&b1)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "rb0" "in" "&rb0" }}
	rb0.AddAssign(&b0)

	// step 4
	b2.Add(&x.B0, &x.B1)
	b3.Add(&y.B0, &y.B1)
	z.B1.Mul(&b2, &b3).
		SubAssign(&b0).
		SubAssign(&b1)

	// step 5
	z.B2.Mul(&x.B2, &y.B0).
		AddAssign(&b1)

	z.B0 = rb0
	return z
}

// Square squares a {{.Name}}
func (z *{{.Name}}) Square(x *{{.Name}}) *{{.Name}} {
	// Algorithm 16 from https://eprint.iacr.org/2010/354.pdf
	var b0, b1, b2, b3, b4 {{.Fp2Name}}

	b3.Mul(&x.B0, &x.B1).Double(&b3) // step 1
	b4.Square(&x.B2) // step 2
	
	// step 3
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "b0" "in" "&b4" }}
	b0.AddAssign(&b3)

	b1.Sub(&b3, &b4) // step 4
	b2.Square(&x.B0) // step 5
	b3.Sub(&x.B0, &x.B1).AddAssign(&x.B2).Square(&b3) // steps 6 and 8
	b4.Mul(&x.B1, &x.B2).Double(&b4) // step 7

	// step 9
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "z.B0" "in" "&b4" }}
	z.B0.AddAssign(&b2)
	
	// step 10
	z.B2.Add(&b1, &b3).
		AddAssign(&b4).
		SubAssign(&b2)

	z.B1 = b0
	return z
}

// Square2 squares a {{.Name}}
func (z *{{.Name}}) Square2(x *{{.Name}}) *{{.Name}} {
	// Karatsuba from Section 4 of https://eprint.iacr.org/2006/471.pdf
	var v0, v1, v2, v01, v02, v12 {{.Fp2Name}}
	v0.Square(&x.B0)
	v1.Square(&x.B1)
	v2.Square(&x.B2)
	v01.Add(&x.B0, &x.B1)
	v01.Square(&v01)
	v02.Add(&x.B0, &x.B2)
	v02.Square(&v02)
	v12.Add(&x.B1, &x.B2)
	v12.Square(&v12)

	z.B0.Sub(&v12, &v1).SubAssign(&v2)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "z.B0" "in" "&z.B0" }}
	z.B0.AddAssign(&v0)

	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "z.B1" "in" "&v2" }}
	z.B1.AddAssign(&v01).SubAssign(&v0).SubAssign(&v1)

	z.B2.Add(&v02, &v1).SubAssign(&v0).SubAssign(&v2)
	return z
}

// Square3 squares a {{.Name}}
func (z *{{.Name}}) Square3(x *{{.Name}}) *{{.Name}} {
	// CH-SQR2 from from Section 4 of https://eprint.iacr.org/2006/471.pdf
	var s0, s1, s2, s3, s4 {{.Fp2Name}}
	s0.Square(&x.B0)
	s1.Mul(&x.B0, &x.B1).Double(&s1)
	s2.Sub(&x.B0, &x.B1).AddAssign(&x.B2).Square(&s2)
	s3.Mul(&x.B1, &x.B2).Double(&s3)
	s4.Square(&x.B2)

	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "z.B0" "in" "&s3" }}
	z.B0.AddAssign(&s0)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "z.B1" "in" "&s4" }}
	z.B1.AddAssign(&s1)
	z.B2.Add(&s1, &s2).AddAssign(&s3).SubAssign(&s0).SubAssign(&s4)
	return z
}

// Inverse an element in {{.Name}}
func (z *{{.Name}}) Inverse(x *{{.Name}}) *{{.Name}} {
	// Algorithm 17 from https://eprint.iacr.org/2010/354.pdf
	// step 9 is wrong in the paper!

	// memalloc
	var t [7]{{.Fp2Name}}
	var c [3]{{.Fp2Name}}
	var buf {{.Fp2Name}}

	t[0].Square(&x.B0) // step 1
	t[1].Square(&x.B1) // step 2
	t[2].Square(&x.B2) // step 3
	t[3].Mul(&x.B0, &x.B1) // step 4
	t[4].Mul(&x.B0, &x.B2) // step 5
	t[5].Mul(&x.B1, &x.B2) // step 6

	// step 7
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "c[0]" "in" "&t[5]" }}
	c[0].Neg(&c[0]).AddAssign(&t[0])

	// step 8
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "c[1]" "in" "&t[2]" }}
	c[1].SubAssign(&t[3])

	c[2].Sub(&t[1], &t[4]) // step 9 is wrong in 2010/354!

	// steps 10, 11, 12
	t[6].Mul(&x.B2, &c[1])
	buf.Mul(&x.B1, &c[2])
	t[6].AddAssign(&buf)
	{{- template "fp2InlineMulByNonResidue" dict "all" . "out" "t[6]" "in" "&t[6]" }}
	buf.Mul(&x.B0, &c[0])
	t[6].AddAssign(&buf)
	
	t[6].Inverse(&t[6]) // step 13
	z.B0.Mul(&c[0], &t[6]) // step 14
	z.B1.Mul(&c[1], &t[6]) // step 15
	z.B2.Mul(&c[2], &t[6]) // step 16

	return z
}

// MulByNonResidue multiplies a {{.Fp2Name}} by ({{.Fp6NonResidue}})
func (z *{{.Fp2Name}}) MulByNonResidue(x *{{.Fp2Name}}) *{{.Fp2Name}} {
	{{- template "fp2MulByNonResidueBody" dict "all" . "out" "z" "in" "x" }}
	return z
}

// MulByNonResidueInv multiplies a {{.Fp2Name}} by ({{.Fp6NonResidue}})^{-1}
func (z *{{.Fp2Name}}) MulByNonResidueInv(x *{{.Fp2Name}}) *{{.Fp2Name}} {
	{{- template "fp2MulByNonResidueInvBody" dict "all" . "out" "z" "in" "x" }}
	return z
}
`
