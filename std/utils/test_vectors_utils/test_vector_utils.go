package test_vector_utils

import (
	"fmt"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/stretchr/testify/assert"
	"testing"
)

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

type HashDescription map[string]interface{}

func HashFromDescription(api frontend.API, d HashDescription) (hash.Hash, error) {
	if _type, ok := d["type"]; ok {
		switch _type {
		case "const":
			startState := int64(d["val"].(float64))
			return &MessageCounter{startState: startState, step: 0, state: startState, api: api}, nil
		default:
			return nil, fmt.Errorf("unknown fake hash type \"%s\"", _type)
		}
	}
	return nil, fmt.Errorf("hash description missing type")
}

type MessageCounter struct {
	startState int64
	state      int64
	step       int64

	// cheap trick to avoid unconstrained input errors
	api  frontend.API
	zero frontend.Variable
}

func (m *MessageCounter) Write(data ...frontend.Variable) {

	for i := range data {
		sq1, sq2 := m.api.Mul(data[i], data[i]), m.api.Mul(data[i], data[i])
		m.zero = m.api.Sub(sq1, sq2, m.zero)
	}

	m.state += int64(len(data)) * m.step
}

func (m *MessageCounter) Sum() frontend.Variable {
	return m.api.Add(m.state, m.zero)
}

func (m *MessageCounter) Reset() {
	m.zero = 0
	m.state = m.startState
}

func NewMessageCounter(api frontend.API, startState, step int) hash.Hash {
	transcript := &MessageCounter{startState: int64(startState), state: int64(startState), step: int64(step), api: api}
	return transcript
}

func NewMessageCounterGenerator(startState, step int) func(frontend.API) hash.Hash {
	return func(api frontend.API) hash.Hash {
		return NewMessageCounter(api, startState, step)
	}
}
