package test_vector_utils

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
)

type TestSingleMapCircuit struct {
	M      Map `gnark:"-"`
	Values []frontend.Variable
}

func (c *TestSingleMapCircuit) Define(api frontend.API) error {

	for i, k := range c.M.keys {
		v := c.M.Get(api, k)
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
	single := ReadMap(m).single

	assignment := TestSingleMapCircuit{
		M:      single,
		Values: single.values,
	}

	circuit := TestSingleMapCircuit{
		M:      single,
		Values: make([]frontend.Variable, len(m)), // Okay to use the same object?
	}

	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment))
}

type TestDoubleMapCircuit struct {
	M      DoubleMap `gnark:"-"`
	Values []frontend.Variable
	Keys1  []frontend.Variable `gnark:"-"`
	Keys2  []frontend.Variable `gnark:"-"`
}

func (c *TestDoubleMapCircuit) Define(api frontend.API) error {

	for i := range c.Keys1 {
		v := c.M.Get(api, c.Keys1[i], c.Keys2[i])
		api.AssertIsEqual(v, c.Values[i])
	}

	return nil
}

func TestReadDoubleMap(t *testing.T) {
	keys1 := []frontend.Variable{1, 2}
	keys2 := []frontend.Variable{1, 0}
	values := []frontend.Variable{3, 1}

	for i := 0; i < 100; i++ {
		m := ToMap(keys1, keys2, values)
		double := ReadMap(m).double
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

	m := ToMap(keys1, keys2, values)
	double := ReadMap(m).double

	fmt.Println(double)

	assignment := TestDoubleMapCircuit{
		M:      double,
		Values: values,
		Keys1:  keys1,
		Keys2:  keys2,
	}

	circuit := TestDoubleMapCircuit{
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
