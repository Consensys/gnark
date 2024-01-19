package plonk

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"reflect"
	"testing"
)

func TestCustomConstraint(t *testing.T) {
	const nbCases = 1000

	// only testing cases with qO = -1

	circuit := customConstraintCircuit{
		A:    make([]frontend.Variable, nbCases),
		B:    make([]frontend.Variable, nbCases),
		O:    make([]frontend.Variable, nbCases),
		mode: make([]int, nbCases),
		aVal: make(fr.Vector, nbCases),
		bVal: make(fr.Vector, nbCases),
		oVal: make(fr.Vector, nbCases),
		qC:   make([]int, nbCases),
		qL:   make([]int, nbCases),
		qR:   make([]int, nbCases),
		qM:   make([]int, nbCases),
	}

	assignment := customConstraintCircuit{
		A: make([]frontend.Variable, nbCases),
		B: make([]frontend.Variable, nbCases),
		O: make([]frontend.Variable, nbCases),
	}

	randomizeInts(circuit.qC, circuit.qL, circuit.qR, circuit.qM)
	randomizeElems(circuit.aVal, circuit.bVal)

	var sum, summand fr.Element
	for i := range circuit.A {
		circuit.mode[i] = i % 8

		sum.SetInt64(int64(circuit.qC[i]))

		summand.SetInt64(int64(circuit.qL[i]))
		summand.Mul(&summand, &circuit.aVal[i])
		sum.Add(&sum, &summand)

		summand.SetInt64(int64(circuit.qR[i]))
		summand.Mul(&summand, &circuit.bVal[i])
		sum.Add(&sum, &summand)

		summand.SetInt64(int64(circuit.qM[i]))
		summand.Mul(&summand, &circuit.aVal[i]).Mul(&summand, &circuit.bVal[i])
		sum.Add(&sum, &summand)

		assignment.O[i] = sum
		circuit.oVal[i] = sum
	}

	assignment.A = test_vector_utils.ToVariableSlice(circuit.aVal)
	assignment.B = test_vector_utils.ToVariableSlice(circuit.bVal)

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func randomizeInts(slices ...[]int) {
	var buff [8]byte
	for _, slice := range slices {
		for i := range slice {
			if _, err := rand.Read(buff[:]); err != nil {
				panic(err)
			}
			neg := 1 - 2*int(buff[0]>>7)
			buff[0] &= 127
			slice[i] = int(binary.BigEndian.Uint64(buff[:])) * neg
		}
	}
}

func randomizeElems(vectors ...fr.Vector) {
	for _, vector := range vectors {
		for i := range vector {
			if _, err := vector[i].SetRandom(); err != nil {
				panic(err)
			}
		}
	}
}

type customConstraintCircuit struct {
	A, B                 []frontend.Variable
	O                    []frontend.Variable
	aVal, bVal, oVal     fr.Vector
	mode, qC, qL, qR, qM []int
}

func ifConstThenElse(api frontend.API, isConst int, val fr.Element, _var frontend.Variable) frontend.Variable {
	api.AssertIsEqual(val, _var)

	if isConst != 0 {
		return val
	}

	return _var
}

func (c *customConstraintCircuit) Define(api frontend.API) error {
	slices := []interface{}{c.B, c.O, c.mode, c.aVal, c.bVal, c.oVal, c.qC, c.qL, c.qR, c.qM}
	for _, slice := range slices {
		if reflect.ValueOf(slice).Len() != len(c.A) {
			return errors.New("inconsistent lengths")
		}
	}

	for i := range c.A {
		a, b, o := ifConstThenElse(api, c.mode[i]&1, c.aVal[i], c.A[i]), ifConstThenElse(api, c.mode[i]&2, c.bVal[i], c.B[i]), ifConstThenElse(api, c.mode[i]&4, c.oVal[i], c.O[i])

		_o := EvaluateExpression(api, a, b, c.qL[i], c.qR[i], c.qM[i], c.qC[i])
		api.AssertIsEqual(_o, o)

		AddConstraint(api, a, b, o, c.qL[i], c.qR[i], -1, c.qM[i], c.qC[i])
	}

	return nil
}
