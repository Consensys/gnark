package scs

// TODO @gbotrel factorize with R1CS package
type REPrivateLinearExpressionSCS []REPrivateTermSCS

func (l REPrivateLinearExpressionSCS) Clone() REPrivateLinearExpressionSCS {
	res := make(REPrivateLinearExpressionSCS, len(l))
	copy(res, l)
	return res
}

func newTerm(vID, cID int) REPrivateTermSCS {
	return REPrivateTermSCS{cID: cID, vID: vID}
}

type REPrivateTermSCS struct {
	cID int
	vID int
}

func (t REPrivateTermSCS) Unpack() (cID, vID int) {
	return t.cID, t.vID
}

func (t *REPrivateTermSCS) SetCoeffID(cID int) {
	t.cID = cID
}
func (t REPrivateTermSCS) WireID() int {
	return t.vID
}

// Len return the lenght of the Variable (implements Sort interface)
func (l REPrivateLinearExpressionSCS) Len() int {
	return len(l)
}

// Equals returns true if both SORTED expressions are the same
//
// pre conditions: l and o are sorted
func (l REPrivateLinearExpressionSCS) Equal(o REPrivateLinearExpressionSCS) bool {
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
func (l REPrivateLinearExpressionSCS) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// Less returns true if variableID for term at i is less than variableID for term at j (implements Sort interface)
func (l REPrivateLinearExpressionSCS) Less(i, j int) bool {
	iID := l[i].WireID()
	jID := l[j].WireID()
	return iID < jID
}

// HashCode returns a fast-to-compute but NOT collision resistant hash code identifier for the linear
// expression
func (l REPrivateLinearExpressionSCS) HashCode() uint64 {
	h := uint64(17)
	for _, val := range l {
		h = h*23 + uint64(val.cID) + uint64(val.vID<<32) // TODO @gbotrel revisit
	}
	return h
}
