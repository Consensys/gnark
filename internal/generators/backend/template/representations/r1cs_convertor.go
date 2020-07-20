package representations

const R1CSConvertor = `


import (
	{{ template "import_backend" . }}
	{{ template "import_fr" . }}
	"github.com/consensys/gnark/backend/r1cs/term"
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

	getCoeffIdx := func(uTerm term.Term) (constraintID, coeffID, specialValue int) {
		constraintID = uTerm.ConstraintID()
		specialValue = uTerm.SpecialValueInt()
		if specialValue != maxInt {
			// we have a special value, no need to get a coeff ID
			return
		}

		// no special value in big.Int format, but it might be one if we set it mod fr.Element

		// get big.Int value
		b := r1cs.Coefficients[uTerm.CoeffID()]
		e.SetBigInt(&b)

		// let's check if wwe have a special value mod fr modulus
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

	for i := 0; i < len(r1cs.Constraints); i++ {
		from := r1cs.Constraints[i]
		to := backend_{{toLower .Curve}}.R1C{
			Solver: from.Solver,
			L:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.L)),
			R:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.R)),
			O:      make(backend_{{toLower .Curve}}.LinearExpression, len(from.O)),
		}

		for j := 0; j < len(from.L); j++ {
			to.L[j] = term.NewTerm(getCoeffIdx(from.L[j]))
		}
		for j := 0; j < len(from.R); j++ {
			to.R[j] = term.NewTerm(getCoeffIdx(from.R[j]))
		}
		for j := 0; j < len(from.O); j++ {
			to.O[j] = term.NewTerm(getCoeffIdx(from.O[j]))
		}

		toReturn.Constraints[i] = to
	}

	return &toReturn
}

`
