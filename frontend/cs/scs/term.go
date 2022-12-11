package scs

// TODO @gbotrel factorize with R1CS package
type LinearExpressionToRefactor []TermToRefactor

func (l LinearExpressionToRefactor) Clone() LinearExpressionToRefactor {
	res := make(LinearExpressionToRefactor, len(l))
	copy(res, l)
	return res
}

func newTerm(vID, cID int) TermToRefactor {
	return TermToRefactor{cID: cID, vID: vID}
}

type TermToRefactor struct {
	cID int
	vID int
}

func (t TermToRefactor) Unpack() (cID, vID int) {
	return t.cID, t.vID
}

func (t *TermToRefactor) SetCoeffID(cID int) {
	t.cID = cID
}
func (t TermToRefactor) WireID() int {
	return t.vID
}

// Len return the lenght of the Variable (implements Sort interface)
func (l LinearExpressionToRefactor) Len() int {
	return len(l)
}

// Equals returns true if both SORTED expressions are the same
//
// pre conditions: l and o are sorted
func (l LinearExpressionToRefactor) Equal(o LinearExpressionToRefactor) bool {
	if len(l) != len(o) {
		return false
	}
	if (l == nil) != (o == nil) {
		return false
	}
	for i := 0; i < len(l); i++ {
		if l[i] != o[i] {
			return false
		}
	}
	return true
}

// Swap swaps terms in the Variable (implements Sort interface)
func (l LinearExpressionToRefactor) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// Less returns true if variableID for term at i is less than variableID for term at j (implements Sort interface)
func (l LinearExpressionToRefactor) Less(i, j int) bool {
	iID := l[i].WireID()
	jID := l[j].WireID()
	return iID < jID
}

// HashCode returns a fast-to-compute but NOT collision resistant hash code identifier for the linear
// expression
func (l LinearExpressionToRefactor) HashCode() uint64 {
	h := uint64(17)
	for _, val := range l {
		h = h*23 + uint64(val.cID) + uint64(val.vID<<32) // TODO @gbotrel revisit
	}
	return h
}
