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
		NbPrivateWires:  r1cs.NbPrivateWires,
		PrivateWires:    r1cs.PrivateWires,
		PublicWires:     r1cs.PublicWires,
		WireTags:        r1cs.WireTags,
		NbConstraints:   r1cs.NbConstraints,
		NbCOConstraints: r1cs.NbCOConstraints,
	}
	toReturn.Constraints = make([]backend_{{toLower .Curve}}.R1C, len(r1cs.Constraints))

	
	lookupTable := make(map[string]int)
	var e fr.Element

	getCoeffIdx := func(b *big.Int) int {
		e.SetBigInt(b)
		key := hex.EncodeToString(e.Bytes())
		if idx, ok := lookupTable[key]; ok {
			return idx
		} 
		r := len(toReturn.Coefficients)
		toReturn.Coefficients = append(toReturn.Coefficients, e)
		lookupTable[key] = r
		return r
	}

	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_{{toLower .Curve}}.R1C{
			Solver: from.Solver,
			L:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.L)),
			R:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.R)),
			O:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j].ID = from.L[j].ID
			to.L[j].CoeffID = getCoeffIdx(&from.L[j].Coeff)
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j].ID = from.R[j].ID
			to.R[j].CoeffID = getCoeffIdx(&from.R[j].Coeff)
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j].ID = from.O[j].ID
			to.O[j].CoeffID = getCoeffIdx(&from.O[j].Coeff)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

`
