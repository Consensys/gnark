package conditional_applicator

import (
	"errors"
	hint "github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"math/big"
)

type ConditionalApplicator struct {
	f              func(frontend.API, ...frontend.Variable) []frontend.Variable
	fHint          hint.Hint
	fNbOut         int
	maxActualCalls int
	nbActualCalls  frontend.Variable
	c              []frontend.Variable
	ins            [][]frontend.Variable
	outs           [][]frontend.Variable
	api            frontend.API
}

func (a *ConditionalApplicator) Call(c frontend.Variable, ins ...frontend.Variable) ([]frontend.Variable, error) {

	allIns := make([]frontend.Variable, 1, len(ins)+1)
	allIns[0] = c
	allIns = append(allIns, ins...)

	outs, err := a.api.NewHint(a.fHint, a.fNbOut, allIns...)
	if err != nil {
		return nil, err
	}

	if len(a.ins) != 0 && len(ins) != len(a.ins[0]) {
		return nil, errors.New("incongruous input size")
	}

	a.ins = append(a.ins, ins)
	a.outs = append(a.outs, outs)
	a.c = append(a.c, c)

	for i := range outs { // TODO: Make this optional?
		outs[i] = a.api.Mul(outs[i], c)
	}

	return outs, nil
}

func (a *ConditionalApplicator) finalize(api frontend.API) error {
	if len(a.c) == 0 {
		return nil // nothing to do
	}

	if a.api != api {
		panic("api mismatch") // this should be impossible
	}

	if a.maxActualCalls <= 0 || a.maxActualCalls > len(a.c) {
		a.maxActualCalls = len(a.c)
	}

	fNbIn := len(a.ins[0])
	collectedIns := make([]frontend.Variable, 2, 2+len(a.c)*(1+fNbIn+a.fNbOut))
	collectedIns[0] = len(a.c)
	collectedIns[1] = len(a.ins[0])

	for i := range a.c {
		collectedIns = append(collectedIns, a.c[i])
		collectedIns = append(collectedIns, a.ins[i]...)
		collectedIns = append(collectedIns, a.outs[i]...)
	}

	return errors.New("TODO")
}

// Collect takes removes the entries of s corresponding to c[i] == 0.
// It assumes, but does not check, that c[i] is a boolean.
// As such, it must be that len(s) == len(c).
// Furthermore len(s[i]) must be the same for all i.
// maxNbCollected dictates the size of the output. If it is no greater than 0 or greater than len(c), it is set to len(c).
func Collect(api frontend.API, c []frontend.Variable, maxNbCollected int, s ...[]frontend.Variable) (collected [][]frontend.Variable, nbCollected frontend.Variable, err error) {
	if len(c) == 0 {
		return nil, 0, nil // nothing to do
	}
	if len(c) != len(s) {
		return nil, nil, errors.New("incongruous input size")
	}
	if maxNbCollected <= 0 || maxNbCollected > len(c) {
		maxNbCollected = len(c)
	}
	hintIn := make([]frontend.Variable, 1, 1+len(c)*(1+len(s[0])))
	hintIn[0] = len(s[0])
	for i := range c {
		if len(s[i]) != len(s[0]) {
			return nil, nil, errors.New("incongruous input block size")
		}
		hintIn = append(hintIn, c[i])
		for j := range s[i] {
			hintIn = append(hintIn, s[i][j])
		}
	}
	outs, err := api.NewHint(collectHint, maxNbCollected*len(s[0]), hintIn...)
	if err != nil {
		return nil, nil, err
	}
	collected = make([][]frontend.Variable, maxNbCollected)
	for i := range collected {
		collected[i] = outs[:len(s[0])]
		outs = outs[len(s[0]):]
	}

	collectedTables := make([]*logderivlookup.Table, len(collected))
	for i := range s[0] {
		collectedTables[i] = logderivlookup.New(api)
		for j := range collected {
			collectedTables[i].Insert(collected[j][i])
		}
	}

	nbCollected = 0
	for i := range c {
		for j := range s[i] {
			AssertEqualIf(api, c[i], collectedTables[j].Lookup(nbCollected)[0], s[i][j])
		}
		nbCollected = api.Add(nbCollected, c[i])
	}

	return
}

func init() {
	hint.RegisterHint(collectHint)
}

// collectHint weeds out input/output values corresponding to c == 0
// ins[0] = blockSize
// then follow {c[i], block[i]}
// output will be {block[i]} for all c[i] != 0
func collectHint(_ *big.Int, ins, outs []*big.Int) error {
	blockSize := int(ins[0].Uint64())

	if !ins[0].IsUint64() || uint64(blockSize) != ins[0].Uint64() {
		return errors.New("int expected")
	}
	ins = ins[1:]

	preSelectionSize := len(ins) / (blockSize + 1)
	if len(ins) != preSelectionSize*(blockSize+1) {
		return errors.New("unexpected input size")
	}

	maxPostSelectionSize := len(outs) / blockSize
	if maxPostSelectionSize*blockSize != len(outs) {
		return errors.New("output size is not a multiple of block size")
	}

	for range preSelectionSize {
		if ins[0].BitLen() != 0 {
			for j := range blockSize {
				outs[j].Set(ins[1+j])
			}
			outs = outs[blockSize:]
		}
		ins = ins[1+blockSize:]
	}

	for i := range outs {
		outs[i].SetUint64(0)
	}

	return nil
}

/*
// collectHint weeds out input/output values corresponding to c == 0
// ins[0] = nbCalls
// ins[1] = nbIns per call
// ins[2] = nbOuts per call
// then follows c
// then follow ins
// then follow outs
// outs: collected and interleaved ins/outs
func collectHint(_ *big.Int, ins, outs []*big.Int) error {
	nbCalls := int(ins[0].Uint64())
	nbIns := int(ins[1].Uint64())
	nbOuts := int(ins[2].Uint64())

	if !ins[0].IsUint64() || uint64(nbCalls) != ins[0].Uint64() ||
		!ins[1].IsUint64() || uint64(nbIns) != ins[1].Uint64() ||
		!ins[2].IsUint64() || uint64(nbOuts) != ins[2].Uint64() {
		return errors.New("int expected")
	}

	if len(ins) != 3+nbCalls*(1+nbIns+nbOuts) {
		return errors.New("unexpected input size")
	}

	maxNbActualCalls := len(outs) / (nbIns + nbOuts)
	if maxNbActualCalls*(nbIns+nbOuts) != len(outs) {
		return errors.New("output size is not a multiple of nbIns+nbOuts")
	}

	cs := ins[3 : nbCalls+3]
	unprunedIns := ins[3+nbCalls : 3+nbCalls*(1+nbIns)]
	unprunedOuts := ins[3+nbCalls*(1+nbIns):]
	nbActualCalls := 0

	for _, c := range cs {
		if c.BitLen() != 0 {
			if nbActualCalls > maxNbActualCalls {
				return fmt.Errorf("too many calls %d > %d", nbActualCalls, maxNbActualCalls)
			}
			for i := range nbIns {
				outs[i].Set(unprunedIns[i])
			}
			for i := range nbOuts {
				outs[i+nbIns].Set(unprunedOuts[i])
			}
			unprunedIns = unprunedIns[nbIns:]
			unprunedOuts = unprunedOuts[nbOuts:]
			outs = outs[nbIns+nbOuts:]
			nbActualCalls++
		}
	}

	return nil
}
*/

// AssertEqualIf asserts that a == b if c != 0
func AssertEqualIf(api frontend.API, c frontend.Variable, a, b frontend.Variable) {
	api.AssertIsEqual(api.Mul(c, api.Sub(a, b)), 0)
}
