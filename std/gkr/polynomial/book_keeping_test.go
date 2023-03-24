package polynomial

import (
	"github.com/consensys/gnark/std/gkr/common"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestLinearCombinationOfBookKeepingTables(t *testing.T) {

	i0 := 13
	i1 := 1789
	table0 := make([]fr.Element, 2)
	table1 := make([]fr.Element, 2)
	correctLinComb := make([]fr.Element, 2)
	for i := 0; i < 2; i++ {
		table0[i].SetUint64(uint64(i))
		table1[i].SetUint64(uint64(i*i + 3*i + 2))
		correctLinComb[i].SetUint64(uint64(i0*i + i1*(i*i+3*i+2)))
	}

	var a0, a1 fr.Element
	a0.SetUint64(uint64(i0))
	a1.SetUint64(uint64(i1))

	t0 := NewBookKeepingTable(table0)
	t1 := NewBookKeepingTable(table1)
	correctLinCombDenseTable := NewBookKeepingTable(correctLinComb)

	linCombDenseTable := LinearCombinationOfBookKeepingTables(t0, t1, a0, a1)

	assert.Equal(t, correctLinCombDenseTable, linCombDenseTable, "Linear combination failed.")
}

func TestFold(t *testing.T) {
	// [0, 1, 2, 3]
	table := make([]fr.Element, 4)
	for i := 0; i < 4; i++ {
		table[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	bkt := NewBookKeepingTable(table)
	// Folding on 5 should yield [10, 11]
	bkt.Fold(r)

	var ten, eleven fr.Element
	ten.SetUint64(uint64(10))
	eleven.SetUint64(uint64(11))

	assert.Equal(t, ten, bkt.Table[0], "Mismatch on 0")
	assert.Equal(t, eleven, bkt.Table[1], "Mismatch on 1")
}

func TestFuncEval(t *testing.T) {
	// [0, 1, 2, 3]
	table := make([]fr.Element, 4)
	for i := 0; i < 4; i++ {
		table[i].SetUint64(uint64(i))
	}

	bkt := NewBookKeepingTable(table)
	// Folding on 5 should yield [10, 11]
	evals := bkt.FunctionEvals()

	var two fr.Element
	two.SetUint64(uint64(2))

	assert.Equal(t, two, evals[0])
	assert.Equal(t, two, evals[1])
}

func BenchmarkFolding(b *testing.B) {

	size := 1 << 25

	// [0, 1, 2, 3]
	table := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		table[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	bkt := NewBookKeepingTable(table)
	// Folding on 5 should yield [10, 11]

	b.ResetTimer()
	for k := 0; k < b.N; k++ {

		bkt2 := bkt.DeepCopy()
		common.ProfileTrace(b, false, false, func() {
			bkt2.Fold(r)
		})
	}
}

func BenchmarkEvals(b *testing.B) {
	size := 1 << 25

	// [0, 1, 2, 3]
	table := make([]fr.Element, size)
	for i := 0; i < size; i++ {
		table[i].SetUint64(uint64(i))
	}

	var r fr.Element
	r.SetUint64(uint64(5))

	bkt := NewBookKeepingTable(table)
	// Folding on 5 should yield [10, 11]
	b.ResetTimer()
	for k := 0; k < b.N; k++ {
		common.ProfileTrace(b, false, false, func() {
			fEvals = bkt.FunctionEvals()
		})
	}
}

var fEvals []fr.Element
