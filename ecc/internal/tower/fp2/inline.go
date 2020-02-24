package fp2

// {{ define }} statements only; this template might appear in multiple packages

const Inline = `
{{- define "fpInlineMulByNonResidue" }}
	{ // begin: inline MulByNonResidue({{$.out}}, {{$.in}})
		{{- template "fpMulByNonResidueBody" dict "all" $.all "out" $.out "in" $.in }}
	} // end: inline MulByNonResidue({{$.out}}, {{$.in}})
{{- end }}

{{- define "fpMulByNonResidueBody" }}
	{{- if eq $.all.Fp2NonResidue "5" }}
		buf := *({{$.in}})
		({{$.out}}).Double(&buf).Double({{$.out}}).AddAssign(&buf)
	{{- else if eq $.all.Fp2NonResidue "-1" }}
		({{$.out}}).Neg({{$.in}})
	{{- else if eq $.all.Fp2NonResidue "3" }}
		buf := *({{$.in}})
		({{$.out}}).Double(&buf).AddAssign(&buf)
	{{- else }}
		panic("not implemented yet")
	{{- end }}
{{- end }}

{{- define "fpInlineMulByNonResidueInv" }}
	{ // begin: inline MulByNonResidueInv({{$.out}}, {{$.in}})
		{{- template "fpMulByNonResidueInvBody" dict "all" $.all "out" $.out "in" $.in }}
	} // end: inline MulByNonResidueInv({{$.out}}, {{$.in}})
{{- end }}

{{- define "fpMulByNonResidueInvBody" }}
	{{- if eq $.all.Fp2NonResidue "5" }}
		nrinv := fp.Element{
			330620507644336508,
			9878087358076053079,
			11461392860540703536,
			6973035786057818995,
			8846909097162646007,
			104838758629667239,
		}
		({{$.out}}).Mul({{$.in}}, &nrinv)
	{{- else if eq $.all.Fp2NonResidue "-1" }}
		// TODO this should be a no-op when {{$.out}}=={{$.in}}
		({{$.out}}).Set({{$.in}})
	{{- else if eq $.all.Fp2NonResidue "3" }}
		nrinv := fp.Element{
			12669921578670009932,
			16188407930212075331,
			13036317521149659693,
			1499583668832556317,
		}
		({{$.out}}).Mul(({{$.in}}), &nrinv)
	{{- else }}
		panic("not implemented yet")
	{{- end }}
{{- end }}
`
