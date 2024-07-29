package utils

import (
	"fmt"
	gohash "hash"
	"math/big"
	"testing"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/emulated"
	"github.com/stretchr/testify/assert"
)

func SliceToBigIntSlice[T any](slice []T) ([]big.Int, error) {
	elementSlice := make([]big.Int, len(slice))
	for i, v := range slice {
		switch v := any(v).(type) {
		case *big.Int:
			elementSlice[i] = *v
		case float64:
			elementSlice[i] = *big.NewInt(int64(v))
		default:
			return nil, fmt.Errorf("unsupported type: %T", v)
		}
	}
	return elementSlice, nil
}

func ConvertToBigIntSlice(input []big.Int) []*big.Int {
	output := make([]*big.Int, len(input))
	for i := range input {
		output[i] = &input[i]
	}
	return output
}

func SliceEqualsBigInt(a []*big.Int, b []*big.Int) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if a[i].Cmp(b[i]) != 0 {
			return fmt.Errorf("at index %d: %s ≠ %s", i, a[i].String(), b[i].String())
		}
	}
	return nil
}

func ToVariableFr[FR emulated.FieldParams](v interface{}) emulated.Element[FR] {
	switch vT := v.(type) {
	case float64:
		return *new(emulated.Field[FR]).NewElement(int(vT))
	default:
		return *new(emulated.Field[FR]).NewElement(v)
	}
}

func ToVariableSliceFr[FR emulated.FieldParams, V any](slice []V) (variableSlice []emulated.Element[FR]) {
	variableSlice = make([]emulated.Element[FR], len(slice))
	for i := range slice {
		variableSlice[i] = ToVariableFr[FR](slice[i])
	}
	return
}

func ToVariableSliceSliceFr[FR emulated.FieldParams, V any](sliceSlice [][]V) (variableSliceSlice [][]emulated.Element[FR]) {
	variableSliceSlice = make([][]emulated.Element[FR], len(sliceSlice))
	for i := range sliceSlice {
		variableSliceSlice[i] = ToVariableSliceFr[FR](sliceSlice[i])
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

func HashFromDescription(d HashDescription) (gohash.Hash, error) {
	if _type, ok := d["type"]; ok {
		switch _type {
		case "const":
			startState := int64(d["val"].(float64))
			return &MessageCounter{startState: startState, step: 0, state: startState}, nil
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
}

func (m *MessageCounter) Write(p []byte) (n int, err error) {
	var temp big.Int
	inputBlockSize := (len(p)-1)/len(temp.Bytes()) + 1
	m.state += int64(inputBlockSize) * m.step
	return len(p), nil
}

func (m *MessageCounter) Sum(b []byte) []byte {
	var temp big.Int
	inputBlockSize := (len(b)-1)/len(temp.Bytes()) + 1
	resI := m.state + int64(inputBlockSize)*m.step
	var res big.Int
	res.SetInt64(int64(resI))
	resBytes := res.Bytes()
	return resBytes[:]
}

func (m *MessageCounter) Reset() {
	m.state = m.startState
}

func (m *MessageCounter) Size() int {
	var temp big.Int
	return len(temp.Bytes())
}

func (m *MessageCounter) BlockSize() int {
	var temp big.Int
	return len(temp.Bytes())
}

func NewMessageCounter(startState, step int) gohash.Hash {
	transcript := &MessageCounter{startState: int64(startState), state: int64(startState), step: int64(step)}
	return transcript
}

func NewMessageCounterGenerator(startState, step int) func() gohash.Hash {
	return func() gohash.Hash {
		return NewMessageCounter(startState, step)
	}
}

type MessageCounterEmulated struct {
	startState int64
	state      int64
	step       int64

	// cheap trick to avoid unconstrained input errors
	api  frontend.API
	zero frontend.Variable
}

func (m *MessageCounterEmulated) Write(data ...frontend.Variable) {

	for i := range data {
		sq1, sq2 := m.api.Mul(data[i], data[i]), m.api.Mul(data[i], data[i])
		m.zero = m.api.Sub(sq1, sq2, m.zero)
	}

	m.state += int64(len(data)) * m.step
}

func (m *MessageCounterEmulated) Sum() frontend.Variable {
	return m.api.Add(m.state, m.zero)
}

func (m *MessageCounterEmulated) Reset() {
	m.zero = 0
	m.state = m.startState
}

func NewMessageCounterEmulated(api frontend.API, startState, step int) hash.FieldHasher {
	transcript := &MessageCounterEmulated{startState: int64(startState), state: int64(startState), step: int64(step), api: api}
	return transcript
}

func NewMessageCounterGeneratorEmulated(startState, step int) func(frontend.API) hash.FieldHasher {
	return func(api frontend.API) hash.FieldHasher {
		return NewMessageCounterEmulated(api, startState, step)
	}
}
