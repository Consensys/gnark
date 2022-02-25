package cs

import (
	"math/big"
)

// Builder helps build a constraint system but need not be serialized after compilation
type Builder struct {
	// Coefficients in the constraints
	Coeffs         []big.Int      // list of unique coefficients.
	CoeffsIDsLarge map[string]int // map to check existence of a coefficient (key = coeff.Bytes())
	CoeffsIDsInt64 map[int64]int  // map to check existence of a coefficient (key = int64 value)

	// map for recording boolean constrained variables (to not constrain them twice)
	MTBooleans map[int]struct{}
}

func NewBuilder() Builder {
	return Builder{
		Coeffs:         make([]big.Int, 4),
		CoeffsIDsLarge: make(map[string]int),
		CoeffsIDsInt64: make(map[int64]int, 4),
		MTBooleans:     make(map[int]struct{}),
	}
}

// CoeffID tries to fetch the entry where b is if it exits, otherwise appends b to
// the list of Coeffs and returns the corresponding entry
func (b *Builder) CoeffID(v *big.Int) int {

	// if the coeff is a int64 we have a fast path.
	if v.IsInt64() {
		return b.coeffID64(v.Int64())
	}

	// GobEncode is 3x faster than b.Text(16). Slightly slower than Bytes, but Bytes return the same
	// thing for -x and x .
	bKey, _ := v.GobEncode()
	key := string(bKey)

	// if the coeff is already stored, fetch its ID from the cs.CoeffsIDs map
	if idx, ok := b.CoeffsIDsLarge[key]; ok {
		return idx
	}

	// else add it in the cs.Coeffs map and update the cs.CoeffsIDs map
	var bCopy big.Int
	bCopy.Set(v)
	resID := len(b.Coeffs)
	b.Coeffs = append(b.Coeffs, bCopy)
	b.CoeffsIDsLarge[key] = resID
	return resID
}

func (b *Builder) coeffID64(v int64) int {
	if resID, ok := b.CoeffsIDsInt64[v]; ok {
		return resID
	} else {
		var bCopy big.Int
		bCopy.SetInt64(v)
		resID := len(b.Coeffs)
		b.Coeffs = append(b.Coeffs, bCopy)
		b.CoeffsIDsInt64[v] = resID
		return resID
	}
}
