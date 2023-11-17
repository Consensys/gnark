package test_vector_utils

import (
	"encoding/json"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/assert"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// These data structures fail to equate different representations of the same number. i.e. 5 = -10/-2
// @Tabaie TODO Replace with proper lookup tables

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
		res = api.MulAcc(res, deltaI, m.values[i])
	}

	return res
}

// The keys in a DoubleMap must be constant. i.e. known at setup time
type DoubleMap struct {
	keys1  []frontend.Variable
	keys2  []frontend.Variable
	values [][]frontend.Variable
}

// Get is very inefficient. Do not use outside testing
func (m DoubleMap) Get(api frontend.API, key1, key2 frontend.Variable) frontend.Variable {
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
			if m.values[i][j] != nil {
				deltaIJ := api.Mul(deltas1[i], deltas2[j], m.values[i][j])
				res = api.Add(res, deltaIJ)
			}
		}
	}

	return res
}

func register[K comparable](m map[K]int, key K) {
	if _, ok := m[key]; !ok {
		m[key] = len(m)
	}
}

func orderKeys[K comparable](order map[K]int) (ordered []K) {
	ordered = make([]K, len(order))
	for k, i := range order {
		ordered[i] = k
	}
	return
}

type ElementMap struct {
	single Map
	double DoubleMap
}

func ReadMap(in map[string]interface{}) ElementMap {
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
			single.values = append(single.values, ToVariable(v))
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
			vals[i1][i2] = ToVariable(v)
		}
	}

	double := DoubleMap{
		keys1:  ToVariableSlice(orderKeys(keys1)),
		keys2:  ToVariableSlice(orderKeys(keys2)),
		values: vals,
	}

	return ElementMap{
		single: single,
		double: double,
	}
}

func ToVariable(v interface{}) frontend.Variable {
	switch vT := v.(type) {
	case float64:
		return int(vT)
	default:
		return v
	}
}

func ToVariableSlice[V any](slice []V) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, len(slice))
	for i := range slice {
		variableSlice[i] = ToVariable(slice[i])
	}
	return
}

func ToVariableSliceSlice[V any](sliceSlice [][]V) (variableSliceSlice [][]frontend.Variable) {
	variableSliceSlice = make([][]frontend.Variable, len(sliceSlice))
	for i := range sliceSlice {
		variableSliceSlice[i] = ToVariableSlice(sliceSlice[i])
	}
	return
}

func ToMap(keys1, keys2, values []frontend.Variable) map[string]interface{} {
	res := make(map[string]interface{}, len(keys1))
	for i := range keys1 {
		str := strconv.Itoa(keys1[i].(int)) + "," + strconv.Itoa(keys2[i].(int))
		res[str] = values[i].(int)
	}
	return res
}

var MapCache = make(map[string]ElementMap) // @Tabaie: global bad?

func ElementMapFromFile(path string) (ElementMap, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return ElementMap{}, err
	}
	if h, ok := MapCache[path]; ok {
		return h, nil
	}
	var bytes []byte
	if bytes, err = os.ReadFile(path); err == nil {
		var asMap map[string]interface{}
		if err = json.Unmarshal(bytes, &asMap); err != nil {
			return ElementMap{}, err
		}

		res := ReadMap(asMap)
		MapCache[path] = res
		return res, nil

	} else {
		return ElementMap{}, err
	}
}

type MapHash struct {
	Map        ElementMap
	state      frontend.Variable
	API        frontend.API
	stateValid bool
}

func (m *MapHash) Sum() frontend.Variable {
	return m.state
}

func (m *MapHash) Write(data ...frontend.Variable) {
	for _, x := range data {
		m.write(x)
	}
}

func (m *MapHash) Reset() {
	m.stateValid = false
}

func (m *MapHash) write(x frontend.Variable) {
	if m.stateValid {
		m.state = m.Map.double.Get(m.API, x, m.state)
	} else {
		m.state = m.Map.single.Get(m.API, x)
	}
	m.stateValid = true
}

func AssertSliceEqual[T comparable](t *testing.T, expected, seen []T) {
	assert.Equal(t, len(expected), len(seen))
	for i := range seen {
		assert.True(t, expected[i] == seen[i], "@%d: %v != %v", i, expected[i], seen[i]) // assert.Equal is not strict enough when comparing pointers, i.e. it compares what they refer to
	}
}

func SliceEqual[T comparable](expected, seen []T) bool {
	if len(expected) != len(seen) {
		return false
	}
	for i := range seen {
		if expected[i] != seen[i] {
			return false
		}
	}
	return true
}
