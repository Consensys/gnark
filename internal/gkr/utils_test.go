package gkr_test

import (
	"fmt"
	"strconv"
	"strings"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

// This file contains test vector utilities and unit tests related to them.

// These data structures fail to equate different representations of the same number. i.e. 5 = -10/-2
// @Tabaie TODO Replace with proper lookup tables

type varsMap struct {
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

// get returns garbage if key is not present
func (m varsMap) get(api frontend.API, key frontend.Variable) frontend.Variable {
	res := frontend.Variable(0)

	for i := range m.keys {
		deltaI := getDelta(api, key, i, m.keys)
		res = api.MulAcc(res, deltaI, m.values[i])
	}

	return res
}

// The keys in a doubleMap must be constant. i.e. known at setup time
type doubleMap struct {
	keys1  []frontend.Variable
	keys2  []frontend.Variable
	values [][]frontend.Variable
}

// get is very inefficient. Do not use outside testing
func (m doubleMap) get(api frontend.API, key1, key2 frontend.Variable) frontend.Variable {
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

type elementMap struct {
	single varsMap
	double doubleMap
}

func readMap(in map[string]interface{}) elementMap {
	single := varsMap{
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
			single.values = append(single.values, toVariable(v))
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
			vals[i1][i2] = toVariable(v)
		}
	}

	double := doubleMap{
		keys1:  toVariableSlice(orderKeys(keys1)),
		keys2:  toVariableSlice(orderKeys(keys2)),
		values: vals,
	}

	return elementMap{
		single: single,
		double: double,
	}
}

func toVariable(v interface{}) frontend.Variable {
	switch vT := v.(type) {
	case float64:
		return int(vT)
	default:
		return v
	}
}

func toVariableSlice[V any](slice []V) (variableSlice []frontend.Variable) {
	variableSlice = make([]frontend.Variable, len(slice))
	for i := range slice {
		variableSlice[i] = toVariable(slice[i])
	}
	return
}

func toVariableSliceSlice[V any](sliceSlice [][]V) (variableSliceSlice [][]frontend.Variable) {
	variableSliceSlice = make([][]frontend.Variable, len(sliceSlice))
	for i := range sliceSlice {
		variableSliceSlice[i] = toVariableSlice(sliceSlice[i])
	}
	return
}

func toMap(keys1, keys2, values []frontend.Variable) map[string]interface{} {
	res := make(map[string]interface{}, len(keys1))
	for i := range keys1 {
		str := strconv.Itoa(keys1[i].(int)) + "," + strconv.Itoa(keys2[i].(int))
		res[str] = values[i].(int)
	}
	return res
}

func assertSliceEqual[T comparable](t *testing.T, expected, seen []T) {
	assert.Equal(t, len(expected), len(seen))
	for i := range seen {
		assert.True(t, expected[i] == seen[i], "@%d: %v != %v", i, expected[i], seen[i]) // assert.Equal is not strict enough when comparing pointers, i.e. it compares what they refer to
	}
}

func sliceEqual[T comparable](expected, seen []T) bool {
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

type testSingleMapCircuit struct {
	M      varsMap `gnark:"-"`
	Values []frontend.Variable
}

func (c *testSingleMapCircuit) Define(api frontend.API) error {

	for i, k := range c.M.keys {
		v := c.M.get(api, k)
		api.AssertIsEqual(v, c.Values[i])
	}

	return nil
}

func TestSingleMap(t *testing.T) {
	m := map[string]interface{}{
		"1": -2,
		"4": 1,
		"6": 7,
	}
	single := readMap(m).single

	assignment := testSingleMapCircuit{
		M:      single,
		Values: single.values,
	}

	circuit := testSingleMapCircuit{
		M:      single,
		Values: make([]frontend.Variable, len(m)), // Okay to use the same object?
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type testDoubleMapCircuit struct {
	M      doubleMap `gnark:"-"`
	Values []frontend.Variable
	Keys1  []frontend.Variable `gnark:"-"`
	Keys2  []frontend.Variable `gnark:"-"`
}

func (c *testDoubleMapCircuit) Define(api frontend.API) error {

	for i := range c.Keys1 {
		v := c.M.get(api, c.Keys1[i], c.Keys2[i])
		api.AssertIsEqual(v, c.Values[i])
	}

	return nil
}

func TestReadDoubleMap(t *testing.T) {
	keys1 := []frontend.Variable{1, 2}
	keys2 := []frontend.Variable{1, 0}
	values := []frontend.Variable{3, 1}

	for i := 0; i < 100; i++ {
		m := toMap(keys1, keys2, values)
		double := readMap(m).double
		valuesOrdered := [][]frontend.Variable{{3, nil}, {nil, 1}}

		assert.True(t, double.keys1[0] == "1" && double.keys1[1] == "2" || double.keys1[0] == "2" && double.keys1[1] == "1")
		assert.True(t, double.keys2[0] == "1" && double.keys2[1] == "0" || double.keys2[0] == "0" && double.keys2[1] == "1")

		if double.keys1[0] != "1" {
			valuesOrdered[0], valuesOrdered[1] = valuesOrdered[1], valuesOrdered[0]
		}

		if double.keys2[0] != "1" {
			valuesOrdered[0][0], valuesOrdered[0][1] = valuesOrdered[0][1], valuesOrdered[0][0]
			valuesOrdered[1][0], valuesOrdered[1][1] = valuesOrdered[1][1], valuesOrdered[1][0]
		}

		assert.True(t, slice2Eq(valuesOrdered, double.values))

	}

}

func slice2Eq(s1, s2 [][]frontend.Variable) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if !sliceEq(s1[i], s2[i]) {
			return false
		}
	}
	return true
}

func sliceEq(s1, s2 []frontend.Variable) bool {
	if len(s1) != len(s2) {
		return false
	}
	for i := range s1 {
		if s1[i] != s2[i] {
			return false
		}
	}
	return true
}

func TestDoubleMap(t *testing.T) {
	keys1 := []frontend.Variable{1, 5, 5, 3}
	keys2 := []frontend.Variable{1, -5, 4, 4}
	values := []frontend.Variable{0, 2, 3, 0}

	m := toMap(keys1, keys2, values)
	double := readMap(m).double

	fmt.Println(double)

	assignment := testDoubleMapCircuit{
		M:      double,
		Values: values,
		Keys1:  keys1,
		Keys2:  keys2,
	}

	circuit := testDoubleMapCircuit{
		M:      double,
		Keys1:  keys1,
		Keys2:  keys2,
		Values: make([]frontend.Variable, len(m)), // Okay to use the same object?
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

func TestDoubleMapManyTimes(t *testing.T) {
	for i := 0; i < 100; i++ {
		TestDoubleMap(t)
	}
}
