package fp2

const mul = `
// Mul sets z to the {{.Name}}-product of x,y, returns z
func (z *{{.Name}}) Mul(x, y *{{.Name}}) *{{.Name}} {
	{{ template "mul" dict "all" . "V1" "x" "V2" "y"}}
	return z
}

// MulAssign sets z to the {{.Name}}-product of z,x returns z
func (z *{{.Name}}) MulAssign(x *{{.Name}}) *{{.Name}} {
	{{ template "mul" dict "all" . "V1" "z" "V2" "x"}}
	return z
}

{{ define "mul" -}}
	// (a+bu)*(c+du) == (ac+({{.all.Fp2NonResidue}})*bd) + (ad+bc)u where u^2 == {{.all.Fp2NonResidue}}
	// Karatsuba: 3 fp multiplications instead of 4
	// [1]: ac
	// [2]: bd
	// [3]: (a+b)*(c+d)
	// Then z.A0: [1] + ({{.all.Fp2NonResidue}})*[2]
	// Then z.A1: [3] - [2] - [1]
	var ac, bd, cplusd, aplusbcplusd fp.Element

	ac.Mul(&{{$.V1}}.A0, &{{$.V2}}.A0)            // [1]: ac
	bd.Mul(&{{$.V1}}.A1, &{{$.V2}}.A1)            // [2]: bd
	cplusd.Add(&{{$.V2}}.A0, &{{$.V2}}.A1)        // c+d
	aplusbcplusd.Add(&{{$.V1}}.A0, &{{$.V1}}.A1)  // a+b
	aplusbcplusd.MulAssign(&cplusd) // [3]: (a+b)*(c+d)
	z.A1.Add(&ac, &bd)              // ad+bc, [2] + [1]
	z.A1.Sub(&aplusbcplusd, &z.A1)  // z.A1: [3] - [2] - [1]

	{{- if eq $.all.Fp2NonResidue "-1" }}
		z.A0.Sub(&ac, &bd) // z.A0: [1] - [2]
	{{- else }}
		MulByNonResidue(&z.A0, &bd)
		z.A0.AddAssign(&ac) // z.A0: [1] + ({{.all.Fp2NonResidue}})*[2]
	{{- end -}}

{{ end }}

// Square sets z to the e2-product of x,x returns z
func (z *{{.Name}}) Square(x *{{.Name}}) *{{.Name}} {
	// (a+bu)^2 == (a^2+({{.Fp2NonResidue}})*b^2) + (2ab)u where u^2 == {{.Fp2NonResidue}}
	// Complex method: 2 fp multiplications instead of 3
	// [1]: ab
	// [2]: (a+b)*(a+({{.Fp2NonResidue}})*b)
	// Then z.A0: [2] - ({{.Fp2NonResidue}}+1)*[1]
	// Then z.A1: 2[1]

	{{- if eq .Fp2NonResidue "-1" }}
		// optimize for quadratic nonresidue -1
		var aplusb fp.Element
		var result e2

		aplusb.Add(&x.A0, &x.A1) // a+b
		result.A0.Sub(&x.A0, &x.A1) // a-b
		result.A0.MulAssign(&aplusb) // [2]: (a+b)*(a-b)
		result.A1.Mul(&x.A0, &x.A1).Double(&result.A1) // [1]: ab

		z.Set(&result)
	{{- else }}
		var ab, aplusb, ababetab fp.Element

		MulByNonResidue(&ababetab, &x.A1)

		ababetab.AddAssign(&x.A0)   // a+({{.Fp2NonResidue}})*b
		aplusb.Add(&x.A0, &x.A1)    // a+b
		ababetab.MulAssign(&aplusb) // [2]: (a+b)*(a+({{.Fp2NonResidue}})*b)
		ab.Mul(&x.A0, &x.A1)        // [1]: ab
		z.A1.Double(&ab)            // z.A1: 2*[1]

		{{- if eq .Fp2NonResidue "5"}}
			z.A0.Add(&ab, &z.A1).Double(&z.A0) // (5+1)*ab, optimize for quadratic nonresidue 5
		{{- else}}
			MulByNonResidue(&z.A0, &ab).AddAssign(&ab) // ({{.Fp2NonResidue}}+1)*ab
		{{- end }}
		z.A0.Sub(&ababetab, &z.A0) // z.A0: [2] - ({{.Fp2NonResidue}}+1)[1]
	{{- end }}

	return z
}

// MulByNonSquare multiplies an element by (0,1)
// TODO deprecate in favor of inlined MulByNonResidue in fp6 package
func (z *{{.Name}}) MulByNonSquare(x *{{.Name}}) *{{.Name}} {
	a := x.A0
	MulByNonResidue(&z.A0, &x.A1)
	z.A1 = a
	return z
}

// Inverse sets z to the {{.Name}}-inverse of x, returns z
func (z *{{.Name}}) Inverse(x *{{.Name}}) *{{.Name}} {
	// Algorithm 8 from https://eprint.iacr.org/2010/354.pdf
	{{- if eq .Fp2NonResidue "-1" }}
		var a0, a1, t0, t1 fp.Element
	{{- else }}
		var a0, a1, t0, t1, t1beta fp.Element
	{{- end }}

	a0 = x.A0 // = is slightly faster than Set()
	a1 = x.A1 // = is slightly faster than Set()

	t0.Square(&a0) // step 1
	t1.Square(&a1) // step 2

	{{- if eq .Fp2NonResidue "-1" }}
		t0.Add(&t0, &t1) // step 3
	{{- else }}
		MulByNonResidue(&t1beta, &t1)
		t0.SubAssign(&t1beta)        // step 3
	{{- end }}
	t1.Inverse(&t0)              // step 4
	z.A0.Mul(&a0, &t1)           // step 5
	z.A1.Neg(&a1).MulAssign(&t1) // step 6

	return z
}

// MulByElement multiplies an element in {{.Name}} by an element in fp
func (z *{{.Name}}) MulByElement(x *{{.Name}}, y *fp.Element) *{{.Name}} {
	var yCopy fp.Element
	yCopy.Set(y)
	z.A0.Mul(&x.A0, &yCopy)
	z.A1.Mul(&x.A1, &yCopy)
	return z
}

// Conjugate conjugates an element in {{.Name}}
func (z *{{.Name}}) Conjugate(x *{{.Name}}) *{{.Name}} {
	z.A0.Set(&x.A0)
	z.A1.Neg(&x.A1)
	return z
}

// MulByNonResidue multiplies a fp.Element by {{.Fp2NonResidue}}
// It would be nice to make this a method of fp.Element but fp.Element is outside this package
func MulByNonResidue(out, in *fp.Element) *fp.Element {
	{{- template "fpMulByNonResidueBody" dict "all" . "out" "out" "in" "in" }}
	return out
}

// MulByNonResidueInv multiplies a fp.Element by {{.Fp2NonResidue}}^{-1}
// It would be nice to make this a method of fp.Element but fp.Element is outside this package
func MulByNonResidueInv(out, in *fp.Element) *fp.Element {
	{{- template "fpMulByNonResidueInvBody" dict "all" . "out" "out" "in" "in" }}
	return out
}
`
