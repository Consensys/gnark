package templates

const ImportCurve = `
{{ define "import_curve" }}
{{if eq .Curve "GENERIC"}}
	"github.com/consensys/gnark/curve"
	"github.com/consensys/gnark/curve/fr"
{{else if eq .Curve "BLS377"}}
	curve "github.com/consensys/gurvy/bls377"
	"github.com/consensys/gurvy/bls377/fr"
{{else if eq .Curve "BLS381"}}
	curve "github.com/consensys/gurvy/bls381"
	"github.com/consensys/gurvy/bls381/fr"
{{else if eq .Curve "BN256"}}
curve "github.com/consensys/gurvy/bn256"	
"github.com/consensys/gurvy/bn256/fr"
{{end}}

{{end}}

{{ define "import_backend" }}
{{if eq .Curve "BLS377"}}
	"github.com/consensys/gnark/backend/static/bls377"
{{else if eq .Curve "BLS381"}}
"github.com/consensys/gnark/backend/static/bls381"
{{else if eq .Curve "BN256"}}
"github.com/consensys/gnark/backend/static/bn256"
{{else if eq .Curve "GENERIC"}}
"github.com/consensys/gnark/backend"
{{end}}

{{end}}
`
