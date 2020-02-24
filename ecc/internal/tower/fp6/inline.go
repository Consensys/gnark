package fp6

// {{ define }} statements only; this template might appear in multiple packages

const Inline = `
{{- define "fp2InlineMulByNonResidue" }}
	{ // begin: inline {{$.out}}.MulByNonResidue({{$.in}})
		{{- template "fp2MulByNonResidueBody" dict "all" $.all "out" $.out "in" $.in }}
	} // end: inline {{$.out}}.MulByNonResidue({{$.in}})
{{- end }}

{{- define "fp2MulByNonResidueBody" }}
	{{- if eq $.all.Fp6NonResidue "0,1" }}
		buf := ({{$.in}}).A0
		{{- template "fpInlineMulByNonResidue" dict "all" $.all "out" (print "&(" $.out ").A0") "in" (print "&(" $.in ").A1") }}
		({{$.out}}).A1 = buf
	{{- else if eq $.all.Fp6NonResidue "1,1"}}
		var buf {{$.all.Fp2Name}}
		buf.Set({{$.in}})
		{{$.out}}.A1.Add(&buf.A0, &buf.A1)
		{{- template "fpInlineMulByNonResidue" dict "all" $.all "out" (print "&(" $.out ").A0") "in" "&buf.A1" }}
		{{$.out}}.A0.AddAssign(&buf.A0)
	{{- else if eq $.all.Fp6NonResidue "9,1"}}
		var buf, buf9 {{$.all.Fp2Name}}
		buf.Set({{$.in}})
		buf9.Double(&buf).
			Double(&buf9).
			Double(&buf9).
			Add(&buf9, &buf)
		{{$.out}}.A1.Add(&buf.A0, &buf9.A1)
		{{- template "fpInlineMulByNonResidue" dict "all" $.all "out" (print "&(" $.out ").A0") "in" "&buf.A1" }}
		{{$.out}}.A0.AddAssign(&buf9.A0)
	{{- else}}
		panic("not implemented yet")
	{{- end }}
{{- end }}

{{- define "fp2InlineMulByNonResidueInv" }}
	{ // begin: inline {{$.out}}.MulByNonResidueInv({{$.in}})
		{{- template "fp2MulByNonResidueInvBody" dict "all" $.all "out" $.out "in" $.in }}
	} // end: inline {{$.out}}.MulByNonResidueInv({{$.in}})
{{- end }}

{{- define "fp2MulByNonResidueInvBody" }}
	{{- if eq $.all.Fp6NonResidue "0,1" }}
		buf := ({{$.in}}).A1
		{{- template "fpInlineMulByNonResidueInv" dict "all" $.all "out" (print "&(" $.out ").A1") "in" (print "&(" $.in ").A0") }}
		({{$.out}}).A0 = buf
	{{- else if (and (eq $.all.Fp6NonResidue "1,1") (eq $.all.Fp2NonResidue "-1")) }}
		// ({{$.out}}).A0 = (({{$.in}}).A0 + ({{$.in}}).A1)/2
		// ({{$.out}}).A1 = (({{$.in}}).A1 - ({{$.in}}).A0)/2
		buf := *({{$.in}})
		({{$.out}}).A0.Add(&buf.A0, &buf.A1)
		({{$.out}}).A1.Sub(&buf.A1, &buf.A0)
		twoInv := fp.Element{
			1730508156817200468,
			9606178027640717313,
			7150789853162776431,
			7936136305760253186,
			15245073033536294050,
			1728177566264616342,
		}
		({{$.out}}).A0.MulAssign(&twoInv)
		({{$.out}}).A1.MulAssign(&twoInv)
	{{- else if (and (eq $.all.Fp6NonResidue "9,1") (eq $.all.Fp2NonResidue "-1")) }}
		// ({{$.out}}).A0 = (9*({{$.in}}).A0 + ({{$.in}}).A1)/82
		// ({{$.out}}).A1 = (9*({{$.in}}).A1 - ({{$.in}}).A0)/82
		copy := *({{$.in}})

		var copy9 e2
		copy9.Double(&copy).
			Double(&copy9).
			Double(&copy9).
			AddAssign(&copy)

		({{$.out}}).A0.Add(&copy9.A0, &copy.A1)
		({{$.out}}).A1.Sub(&copy9.A1, &copy.A0)

		buf82inv := fp.Element{
			15263610803691847034,
			14617516054323294413,
			1961223913490700324,
			3456812345740674661,
		}
		({{$.out}}).A0.MulAssign(&buf82inv)
		({{$.out}}).A1.MulAssign(&buf82inv)
	{{- else if (and (eq $.all.Fp6NonResidue "9,1") (eq $.all.Fp2NonResidue "3")) }}
		// ({{$.out}}).A0 = (9*({{$.in}}).A0 - 3*({{$.in}}).A1)/78
		// ({{$.out}}).A1 = (9*({{$.in}}).A1 - ({{$.in}}).A0)/78
		copy := *({{$.in}})

		var copy9 e2
		copy9.Double(&copy).
			Double(&copy9).
			Double(&copy9).
			AddAssign(&copy)

		var copy3A1 fp.Element
		copy3A1.Double(&copy.A1).
			AddAssign(&copy.A1)

		({{$.out}}).A0.Sub(&copy9.A0, &copy3A1)
		({{$.out}}).A1.Sub(&copy9.A1, &copy.A0)

		var buf78inv fp.Element
		buf78inv.SetUint64(78).Inverse(&buf78inv) // TODO hardcode
		({{$.out}}).A0.MulAssign(&buf78inv)
		({{$.out}}).A1.MulAssign(&buf78inv)
	{{- else}}
		panic("not implemented yet")
	{{- end }}
{{- end }}
`
