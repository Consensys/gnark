package frontend

import (
	"sort"
	"testing"

	"github.com/consensys/gnark/internal/backend/compiled"
)

func TestQuickSort(t *testing.T) {

	toSort := make(compiled.LinearExpression, 12)
	rand := 3
	for i := 0; i < 12; i++ {
		toSort[i].SetVariableVisibility(compiled.Secret)
		toSort[i].SetVariableID(rand)
		rand += 3
		rand = rand % 13
	}

	sort.Sort(toSort)

	for i := 0; i < 10; i++ {
		_, cur, _ := toSort[i].Unpack()
		_, next, _ := toSort[i+1].Unpack()
		if cur >= next {
			t.Fatal("err sorting linear expression")
		}
	}

}

func TestReduce(t *testing.T) {

	cs := newConstraintSystem()
	x := cs.newInternalVariable()
	y := cs.newInternalVariable()
	z := cs.newInternalVariable()

	a := cs.Mul(x, 3)
	b := cs.Mul(x, 5)
	c := cs.Mul(y, 10)
	d := cs.Mul(y, 11)
	e := cs.Mul(z, 2)
	f := cs.Mul(z, 2)

	toTest := cs.Add(a, b, c, d, e, f)

	// check sizes
	if len(toTest.linExp) != 3 {
		t.Fatal("Error reduce, duplicate variables not collapsed")
	}

}

func TestPopVariable(t *testing.T) {

	sizeAfterPoped := 29
	nbInternalVars := 10

	le := make([]compiled.Term, 30)
	for i := 0; i < 10; i++ {
		le[i] = compiled.Pack(i, 2*i, compiled.Internal)
		le[10+i] = compiled.Pack(i, 2*(i+10), compiled.Public)
		le[20+i] = compiled.Pack(i, 2*(i+20), compiled.Secret)
	}

	for i := 0; i < nbInternalVars; i++ {
		l, v := popInternalVariable(le, i)
		_v := le[i]
		_l := make(compiled.LinearExpression, len(le)-1)
		copy(_l, le[:i])
		copy(_l[i:], le[i+1:])
		if len(l) != sizeAfterPoped {
			t.Fatal("wrong length")
		}
		if _v != v {
			t.Fatal("wrong variable")
		}
		for j := 0; j < sizeAfterPoped; j++ {
			if _l[j] != l[j] {
				t.Fatal("wrong lin exp")
			}
		}
	}
}

func TestFindUnsolvedVariable(t *testing.T) {

	sizeLe := 10
	totalInternalVariables := 3 * sizeLe / 2

	l := make(compiled.LinearExpression, sizeLe)
	r := make(compiled.LinearExpression, sizeLe)
	o := make(compiled.LinearExpression, sizeLe)
	for i := 0; i < sizeLe/2; i++ {
		l[i] = compiled.Pack(3*i, i, compiled.Internal)
		l[i+sizeLe/2] = compiled.Pack(3*i, i, compiled.Public)
	}
	for i := 0; i < sizeLe/2; i++ {
		r[i] = compiled.Pack(3*i+1, i, compiled.Internal)
		r[i+sizeLe/2] = compiled.Pack(3*i+1, i, compiled.Public)
	}
	for i := 0; i < sizeLe/2; i++ {
		o[i] = compiled.Pack(3*i+2, i, compiled.Internal)
		o[i+sizeLe/2] = compiled.Pack(3*i+2, i, compiled.Public)
	}

	solvedVariables := make([]bool, totalInternalVariables)
	for i := 0; i < totalInternalVariables; i++ {
		solvedVariables[i] = true
	}
	r1c := compiled.R1C{L: l, R: r, O: o, Solver: compiled.SingleOutput}

	for i := 0; i < totalInternalVariables; i++ {
		solvedVariables[i] = false
		expectedPos := i % 3 // left=0, right=1, out = 3
		expectedID := i
		pos, id := findUnsolvedVariable(r1c, solvedVariables)
		if pos != expectedPos {
			t.Fatal("wrong position")
		}
		if id != expectedID {
			t.Fatal("wrong id")
		}
		solvedVariables[i] = true
	}
}
