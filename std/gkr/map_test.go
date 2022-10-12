package gkr_test

import (
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"strings"
	"testing"
)

// TODO: These data structures fail to equate different representations of the same number. i.e. 5 = -10/-2

type Map struct {
	keys   []frontend.Variable
	values []frontend.Variable
}

func getDelta(api frontend.API, x frontend.Variable, deltaIndex int, keys []frontend.Variable) frontend.Variable {
	num := frontend.Variable(1)
	den := frontend.Variable(1)

	for i, key := range keys {
		if i != deltaIndex {
			num = api.Mul(num, api.Sub(key, x))
			den = api.Mul(den, api.Sub(key, keys[deltaIndex]))
		}
	}

	return api.Div(num, den)
}

// Get returns garbage if key is not present
func (m Map) Get(api frontend.API, key frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)

	for i := range m.keys {
		deltaI := getDelta(api, key, i, m.keys)
		res = api.Add(res, api.Mul(deltaI, m.values[i]))
	}

	return res
}

type DoubleMap struct {
	keys1  []frontend.Variable
	keys2  []frontend.Variable
	values [][]frontend.Variable
}

// Get is very inefficient. Do not use outside testing
func (m DoubleMap) Get(api frontend.API, key1, key2 frontend.API) frontend.Variable {
	deltas1 := make([]frontend.Variable, len(m.keys1))
	deltas2 := make([]frontend.Variable, len(m.keys2))

	for i := range deltas1 {
		deltas1[i] = getDelta(api, key1, i, m.keys1)
	}

	for j := range deltas2 {
		deltas2[j] = getDelta(api, key2, j, m.keys2)
	}

	res := frontend.Variable(0)

	for i := range deltas1 {
		for j := range deltas2 {

			deltaIJ := api.Mul(deltas1[i], deltas2[j], m.values[i][j])
			res = api.Add(res, deltaIJ)
		}
	}

	return res
}

func register[K comparable](m map[K]int, key K) {
	if _, ok := m[key]; !ok {
		m[key] = len(m)
	}
}

func ReadMap(in map[string]interface{}) (Map, DoubleMap) {
	single := Map{
		keys:   make([]frontend.Variable, 0),
		values: make([]frontend.Variable, 0),
	}

	keys1 := make(map[string]int)
	keys2 := make(map[string]int)

	for k, v := range in {
		kSep := strings.Split(k, ",")
		switch len(kSep) {
		case 1:
			single.keys = append(single.keys, k)
			single.values = append(single.values, v)
		case 2:

			register(keys1, kSep[0])
			register(keys2, kSep[1])

		default:
			panic("too many keys")
		}
	}

	vals := make([][]frontend.Variable, len(keys1))
	for i := range vals {
		vals[i] = make([]frontend.Variable, len(keys2))
	}

	for k, v := range in {
		kSep := strings.Split(k, ",")
		if len(kSep) == 2 {
			i1 := keys1[kSep[0]]
			i2 := keys2[kSep[1]]
			vals[i1][i2] = v
		}
	}

	double := DoubleMap{
		keys1:  toVariableSlice(getKeys(keys1)),
		keys2:  toVariableSlice(getKeys(keys2)),
		values: vals,
	}

	return single, double
}

func getKeys[K comparable, V any](m map[K]V) []K {
	kS := make([]K, len(m))
	i := 0
	for k := range m {
		kS[i] = k
		i++
	}
	return kS
}

func toVariableSlice[V any](slice []V) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, len(slice))
	for i, v := range slice {
		variableSlice[i] = v
	}
	return
}

type SimpleCircuit struct {
	X frontend.Variable
}

func (c *SimpleCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 1)
	return nil
}

func TestSimple(t *testing.T) {

	assert := test.NewAssert(t)
	assert.ProverSucceeded(
		&SimpleCircuit{},
		&SimpleCircuit{X: 1}, test.WithBackends(backend.PLONK),
	)
}

type TestSingleMapCircuit struct {
}

//func (c *TestSingleMapCircuit) Define(api frontend.API)
