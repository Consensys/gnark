package representations

const R1CSConvertor = `


import (
	{{ template "import_backend" . }}
	{{ template "import_fr" . }}
)

func (r1cs *UntypedR1CS) to{{toUpper .Curve}}() *backend_{{toLower .Curve}}.R1CS {

	toReturn := backend_{{toLower .Curve}}.R1CS{
		NbWires:         r1cs.NbWires,
		NbPublicWires:   r1cs.NbPublicWires,
		NbSecretWires:  r1cs.NbSecretWires,
		SecretWires:    r1cs.SecretWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
		Constraints: 	r1cs.Constraints,
		Coefficients: 	make([]fr.Element, len(r1cs.Coefficients)),
	}

	for i := 0; i < len(r1cs.Coefficients); i++ {
		toReturn.Coefficients[i].SetBigInt(&r1cs.Coefficients[i])
	}

	return &toReturn
}

`
