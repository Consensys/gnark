package expr

import (
	"github.com/consensys/gnark/constraint"
	"golang.org/x/crypto/blake2b"
)

type LinearExpression[E constraint.Element] []Term[E]

// NewLinearExpression helper to initialize a linear expression with one term
func NewLinearExpression[E constraint.Element](vID int, cID E) LinearExpression[E] {
	return LinearExpression[E]{Term[E]{Coeff: cID, VID: vID}}
}

func (l LinearExpression[E]) Clone() LinearExpression[E] {
	res := make(LinearExpression[E], len(l))
	copy(res, l)
	return res
}

// Len return the length of the Variable (implements Sort interface)
func (l LinearExpression[E]) Len() int {
	return len(l)
}

// Equals returns true if both SORTED expressions are the same
//
// pre conditions: l and o are sorted
func (l LinearExpression[E]) Equal(o LinearExpression[E]) bool {
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
func (l LinearExpression[E]) Swap(i, j int) {
	l[i], l[j] = l[j], l[i]
}

// Less returns true if variableID for term at i is less than variableID for term at j (implements Sort interface)
func (l LinearExpression[E]) Less(i, j int) bool {
	iID := l[i].WireID()
	jID := l[j].WireID()
	return iID < jID
}

// HashCode returns a collision-resistant identifier of the linear expression. It is constructed from the hash codes of the terms.
func (l LinearExpression[E]) HashCode() [16]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	for i := range l {
		termHash := l[i].HashCode()
		h.Write(termHash[:])
	}
	crc := h.Sum(nil)
	return [16]byte(crc[:16])
}
