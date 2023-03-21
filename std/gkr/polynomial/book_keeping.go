package polynomial

import (
	"fmt"
	"github.com/consensys/gnark/std/gkr/common"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// BookKeepingTable tracks the values of a (dense i.e. not sparse) multilinear polynomial
type BookKeepingTable struct {
	Table []fr.Element
}

func (bkt *BookKeepingTable) String() string {
	return fmt.Sprintf("table = %v", common.FrSliceToString(bkt.Table))
}

// NewBookKeepingTable returns a new instance of bookkeeping table
func NewBookKeepingTable(table []fr.Element) BookKeepingTable {
	return BookKeepingTable{
		Table: table,
	}
}

// InterleavedChunk returns a single chunk from an interleaved splitting
func (bkt *BookKeepingTable) InterleavedChunk(on, nChunk int) BookKeepingTable {
	chunkSize := len(bkt.Table) / nChunk
	table := make([]fr.Element, chunkSize)
	for i := 0; i < chunkSize; i++ {
		table[i] = bkt.Table[on+i*nChunk]
	}
	return NewBookKeepingTable(table)
}

// Fold folds the table on its first coordinate using the given value r
func (bkt *BookKeepingTable) Fold(r fr.Element) {
	mid := bkt.middleIndex()
	bottom, top := bkt.Table[:mid], bkt.Table[mid:]
	for i := range bottom {
		// updating bookkeeping table
		// table[i] <- table[i] + r (table[i + mid] - table[i])
		top[i].Sub(&top[i], &bottom[i])
		top[i].Mul(&top[i], &r)
		bottom[i].Add(&bottom[i], &top[i])
	}
	bkt.Table = bkt.Table[:mid]
}

// FunctionEvals evaluates implicitly over the first variable in bkt
// E.g. if one has to interpolate, say, x |--> (x + cst)^7 with x in the bkt,
// We return the value P(r, 0, b), and delta = P(r, 1, b) - P(r, 0, b) in an array
// [P(r, 0, b), delta]
func (bkt BookKeepingTable) FunctionEvals() []fr.Element {
	mid := bkt.middleIndex()
	fEvals := make([]fr.Element, mid)
	bottom, top := bkt.Table[:mid], bkt.Table[mid:]

	for i := range bottom {
		fEvals[i].Sub(&top[i], &bottom[i])
	}

	return fEvals
}

func (bkt BookKeepingTable) middleIndex() int {
	return len(bkt.Table) / 2
}

// DeepCopy creates a deep copy of a book-keeping table.
// Both ultilinear interpolation and sumcheck require folding an underlying
// array, but folding changes the array. To do both one requires a deep copy
// of the book-keeping table.
func (bkt *BookKeepingTable) DeepCopy() BookKeepingTable {
	tableDeepCopy := make([]fr.Element, len(bkt.Table))
	copy(tableDeepCopy, bkt.Table)
	return NewBookKeepingTable(tableDeepCopy)
}

// Evaluate takes a dense book-keeping table, deep copies it, folds it along the
// variables on which the table depends by substituting the corresponding coordinate
// from relevantCoordinates. After folding, bkCopy.table is reduced to a one item slice
// containing the evaluation of the original bkt.table at relevantCoordinates. This is returned.
func (bkt *BookKeepingTable) Evaluate(coordinates []fr.Element) fr.Element {
	bkCopy := bkt.DeepCopy()
	for _, r := range coordinates {
		bkCopy.Fold(r)
	}

	return bkCopy.Table[0]
}

// EvaluateLeftAndRight produces two evaluations of a book-keeping table V:
// V(q,l) and V(q,r). Folding is first done along the first done for q, then two
// copies are generated to handle the further copies.
// Variable order: [q', q, hl, hr, h']
func (bkt *BookKeepingTable) EvaluateLeftAndRight(hPrime, hL, hR []fr.Element) (fr.Element, fr.Element) {

	bkCopyLeft := bkt.DeepCopy()
	bkCopyRight := bkt.DeepCopy()

	// Fix a bug where hPrime, hL and hR are all subSlices of the same table
	coordinatesLeft := append([]fr.Element{}, hL...)
	coordinatesLeft = append(coordinatesLeft, hPrime...)
	coordinatesRight := append([]fr.Element{}, hR...)
	coordinatesRight = append(coordinatesRight, hPrime...)

	leftEval, rightEval := bkCopyLeft.Evaluate(coordinatesLeft),
		bkCopyRight.Evaluate(coordinatesRight)
	return leftEval, rightEval
}

// LinearCombinationOfBookKeepingTables is an alternative to
// LinearCombinationOfBookKeepingTable
func LinearCombinationOfBookKeepingTables(
	prefoldedBKT0, prefoldedBKT1 BookKeepingTable,
	a0, a1 fr.Element,
) BookKeepingTable {

	// CAREFUL: indices to be confirmed!
	// In BOTH CASES ought to be: bN + uint(i)
	// Variables: order & size:
	// q',	q,	r,	l,	h'
	// bN,	bG,	bG,	bG,	bN
	for i := range prefoldedBKT1.Table {
		prefoldedBKT0.Table[i].Mul(&prefoldedBKT0.Table[i], &a0)
		prefoldedBKT1.Table[i].Mul(&prefoldedBKT1.Table[i], &a1)
		prefoldedBKT1.Table[i].Add(&prefoldedBKT1.Table[i], &prefoldedBKT0.Table[i])
	}

	return prefoldedBKT1
}

// Add two bookKeepingTable
func (bkt *BookKeepingTable) Add(left, right BookKeepingTable) {
	size := len(left.Table)
	// Check that left and right have the same size
	if len(right.Table) != size {
		panic("Left and right do not have the right size")
	}
	// Reallocate the table if necessary
	if cap(bkt.Table) < size {
		bkt.Table = make([]fr.Element, size)
	}
	// Resize the destination table
	bkt.Table = bkt.Table[:size]
	// Then performs the addition
	for i := 0; i < size; i++ {
		bkt.Table[i].Add(&left.Table[i], &right.Table[i])
	}
}

// Sub two bookKeepingTable
func (bkt *BookKeepingTable) Sub(left, right BookKeepingTable, nCore int) {
	size := len(left.Table)
	chunks := common.IntoChunkRanges(nCore, size)
	semaphore := common.NewSemaphore(nCore)
	var wg sync.WaitGroup
	wg.Add(len(chunks))

	// Check that left and right have the same size
	if len(right.Table) != size {
		panic("Left and right do not have the right size")
	}
	// Reallocate the table if necessary
	if cap(bkt.Table) < size {
		bkt.Table = make([]fr.Element, size)
	}
	// Resize the destination table
	bkt.Table = bkt.Table[:size]
	// Then performs the addition
	for _, chunk := range chunks {
		semaphore.Acquire()
		go func(chunk common.ChunkRange) {
			for i := chunk.Begin; i < chunk.End; i++ {
				bkt.Table[i].Sub(&left.Table[i], &right.Table[i])
			}
			semaphore.Release()
			wg.Done()
		}(chunk)
	}

	wg.Wait()
}

// Mul a bookkeeping table by a constant
func (bkt *BookKeepingTable) Mul(lambda fr.Element, x BookKeepingTable, nCore int) {
	size := len(x.Table)
	chunks := common.IntoChunkRanges(nCore, size)
	semaphore := common.NewSemaphore(nCore)
	var wg sync.WaitGroup
	wg.Add(len(chunks))

	// Reallocate the table if necessary
	if cap(bkt.Table) < size {
		bkt.Table = make([]fr.Element, size)
	}

	// Resize the destination table
	bkt.Table = bkt.Table[:size]
	// Then performs the addition
	for _, chunk := range chunks {
		semaphore.Acquire()
		go func(chunk common.ChunkRange) {
			for i := chunk.Begin; i < chunk.End; i++ {
				bkt.Table[i].Mul(&x.Table[i], &lambda)
			}
			semaphore.Release()
			wg.Done()
		}(chunk)
	}
	wg.Wait()
}
