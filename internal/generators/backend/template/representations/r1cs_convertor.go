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
	var e, eOne, eTwo, eMinusOne fr.Element
	eOne.SetOne()
	eMinusOne.Neg(&eOne)
	eTwo.SetUint64(2)

	const maxInt = int (^uint(0) >> 1)

	getCoeffIdx := func(b *big.Int) (coeffID, specialValue int) {
		e.SetBigInt(b)

		// let's check if wwe have a special value
		specialValue = maxInt
		if e.IsZero() {
			specialValue = 0
			return
		} else if e.Equal(&eOne) {
			specialValue = 1
			return
		} else if e.Equal(&eMinusOne) {
			specialValue = -1
			return
		} else if e.Equal(&eTwo) {
			specialValue = 2
			return
		}

		// no special value, let's check if we have encountered the coeff already
		// note: this is slow. but "offline"
		key := hex.EncodeToString(e.Bytes())
		if idx, ok := lookupTable[key]; ok {
			coeffID = idx
			return 
		} 

		// we didn't find it, let's add it to our coefficients
		coeffID = len(toReturn.Coefficients)
		toReturn.Coefficients = append(toReturn.Coefficients, e)
		lookupTable[key] = coeffID
		return
	}

	var cID, specialValue int
	
	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_{{toLower .Curve}}.R1C{
			Solver: from.Solver,
			L:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.L)),
			R:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.R)),
			O:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			cID, specialValue = getCoeffIdx(&from.L[j].Coeff)
			to.L[j] = backend_{{toLower .Curve}}.NewTerm(int(from.L[j].ID), cID, specialValue)
		}
		for j := 0; j < len(from.R); j++ {
			cID, specialValue = getCoeffIdx(&from.R[j].Coeff)
			to.R[j] = backend_{{toLower .Curve}}.NewTerm(int(from.R[j].ID), cID, specialValue)
		}
		for j := 0; j < len(from.O); j++ {
			cID, specialValue = getCoeffIdx(&from.O[j].Coeff)
			to.O[j] = backend_{{toLower .Curve}}.NewTerm(int(from.O[j].ID), cID, specialValue)
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

`
