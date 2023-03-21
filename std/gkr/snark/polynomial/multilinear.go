package polynomial

import (
	"fmt"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// MultilinearByValues represents a multilinear polynomial by its values
type MultilinearByValues struct {
	Table []frontend.Variable
}

// AllocateMultilinear returns an empty multilinear with a given size
func AllocateMultilinear(nVars int) MultilinearByValues {
	size := 1 << nVars
	multilinears := make([]frontend.Variable, size)
	for i := range multilinears {
		multilinears[i] = 0
	}
	return NewMultilinearByValues(multilinears)
}

// Assign a preallocated Multilinear with the given values
func (m *MultilinearByValues) Assign(values []interface{}) {
	if len(values) != len(m.Table) {
		panic(fmt.Sprintf("Inconsistent assignment expected len %v but got %v", len(m.Table), len(values)))
	}
	for i, c := range values {
		m.Table[i] = c
	}
}

// AssignFromChunkedBKT a preallocated Multilinear with the given values
func (m *MultilinearByValues) AssignFromChunkedBKT(values [][]fr.Element) {
	nChunks := len(values)
	for b := range values {
		for i := range values[b] {
			m.Table[b+i*nChunks] = values[b][i]
		}
	}
}

// NewMultilinearByValues is the default constructor
func NewMultilinearByValues(Table []frontend.Variable) MultilinearByValues {
	return MultilinearByValues{Table: Table}
}

// DeepCopy returns a deepcopied value
func (m MultilinearByValues) DeepCopy() MultilinearByValues {
	tableDC := make([]frontend.Variable, len(m.Table))
	copy(tableDC, m.Table)
	return NewMultilinearByValues(tableDC)
}

// Fold partially evaluates the polynomial on one of the variable
func (m *MultilinearByValues) Fold(cs frontend.API, x frontend.Variable) {
	k := len(m.Table) / 2
	for i := 0; i < k; i++ {
		tmpLinExp := cs.Sub(m.Table[i+k], m.Table[i])
		// cs.LinearExpression(
		// 	cs.Term(m.Table[i+k], big.NewInt(1)),
		// 	cs.Term(m.Table[i], big.NewInt(-1)),
		// )
		tmp := cs.Mul(tmpLinExp, x)
		// Ideally we replace this by a r1c.LinearExpression too ...
		m.Table[i] = cs.Add(m.Table[i], tmp)
	}
	m.Table = m.Table[:k]
}

// Eval the multilinear polynomial
func (m MultilinearByValues) Eval(cs frontend.API, xs []frontend.Variable) frontend.Variable {
	f := m.DeepCopy()
	for _, x := range xs {
		// Repeatedly fold the table
		f.Fold(cs, x)
	}
	return f.Table[0]
}

// EvalMixed the multilinear polynomial
// We must have len(qL) == len(qR)
// And len(Table) = 2 ** len(qL) + len(qPrime)
func (m MultilinearByValues) EvalMixed(
	cs frontend.API,
	qL, qR, qPrime []frontend.Variable,
) (vL, vR frontend.Variable) {
	// The function proceeds by putting in common the evaluations over qPrime
	// to save a maximum of space
	nChunks := 1 << len(qL)
	chunkSize := len(m.Table) / nChunks
	intermediateTable := make([]frontend.Variable, nChunks)

	// Evaluate each portion of the table on qPrime. For different values of q.
	for i := range intermediateTable {
		multlin := NewMultilinearByValues(m.Table[i*chunkSize : (i+1)*chunkSize])
		intermediateTable[i] = multlin.Eval(cs, qPrime)
	}
	intermediatePoly := NewMultilinearByValues(intermediateTable)
	return intermediatePoly.Eval(cs, qL), intermediatePoly.Eval(cs, qR)
}
