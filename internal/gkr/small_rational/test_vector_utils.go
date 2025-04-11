// Copyright 2020-2025 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

// Code generated by gnark DO NOT EDIT

package gkr

import (
	"fmt"
	"github.com/consensys/gnark/internal/small_rational"
	"github.com/consensys/gnark/internal/small_rational/polynomial"
	"hash"
	"reflect"
)

func ToElement(i int64) *small_rational.SmallRational {
	var res small_rational.SmallRational
	res.SetInt64(i)
	return &res
}

type HashDescription map[string]interface{}

func HashFromDescription(d HashDescription) (hash.Hash, error) {
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
	inputBlockSize := (len(p)-1)/small_rational.Bytes + 1
	m.state += int64(inputBlockSize) * m.step
	return len(p), nil
}

func (m *MessageCounter) Sum(b []byte) []byte {
	inputBlockSize := (len(b)-1)/small_rational.Bytes + 1
	resI := m.state + int64(inputBlockSize)*m.step
	var res small_rational.SmallRational
	res.SetInt64(int64(resI))
	resBytes := res.Bytes()
	return resBytes[:]
}

func (m *MessageCounter) Reset() {
	m.state = m.startState
}

func (m *MessageCounter) Size() int {
	return small_rational.Bytes
}

func (m *MessageCounter) BlockSize() int {
	return small_rational.Bytes
}

func NewMessageCounter(startState, step int) hash.Hash {
	transcript := &MessageCounter{startState: int64(startState), state: int64(startState), step: int64(step)}
	return transcript
}

func NewMessageCounterGenerator(startState, step int) func() hash.Hash {
	return func() hash.Hash {
		return NewMessageCounter(startState, step)
	}
}

type ListHash []small_rational.SmallRational

func (h *ListHash) Write(p []byte) (n int, err error) {
	return len(p), nil
}

func (h *ListHash) Sum(b []byte) []byte {
	res := (*h)[0].Bytes()
	*h = (*h)[1:]
	return res[:]
}

func (h *ListHash) Reset() {
}

func (h *ListHash) Size() int {
	return small_rational.Bytes
}

func (h *ListHash) BlockSize() int {
	return small_rational.Bytes
}

func SliceToElementSlice[T any](slice []T) ([]small_rational.SmallRational, error) {
	elementSlice := make([]small_rational.SmallRational, len(slice))
	for i, v := range slice {
		if _, err := elementSlice[i].SetInterface(v); err != nil {
			return nil, err
		}
	}
	return elementSlice, nil
}

func SliceEquals(a []small_rational.SmallRational, b []small_rational.SmallRational) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if !a[i].Equal(&b[i]) {
			return fmt.Errorf("at index %d: %s ≠ %s", i, a[i].String(), b[i].String())
		}
	}
	return nil
}

func SliceSliceEquals(a [][]small_rational.SmallRational, b [][]small_rational.SmallRational) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if err := SliceEquals(a[i], b[i]); err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}
	}
	return nil
}

func PolynomialSliceEquals(a []polynomial.Polynomial, b []polynomial.Polynomial) error {
	if len(a) != len(b) {
		return fmt.Errorf("length mismatch %d≠%d", len(a), len(b))
	}
	for i := range a {
		if err := SliceEquals(a[i], b[i]); err != nil {
			return fmt.Errorf("at index %d: %w", i, err)
		}
	}
	return nil
}

func ElementToInterface(x *small_rational.SmallRational) interface{} {
	if i := x.BigInt(nil); i != nil {
		return i
	}
	return x.Text(10)
}

func ElementSliceToInterfaceSlice(x interface{}) []interface{} {
	if x == nil {
		return nil
	}

	X := reflect.ValueOf(x)

	res := make([]interface{}, X.Len())
	for i := range res {
		xI := X.Index(i).Interface().(small_rational.SmallRational)
		res[i] = ElementToInterface(&xI)
	}
	return res
}

func ElementSliceSliceToInterfaceSliceSlice(x interface{}) [][]interface{} {
	if x == nil {
		return nil
	}

	X := reflect.ValueOf(x)

	res := make([][]interface{}, X.Len())
	for i := range res {
		res[i] = ElementSliceToInterfaceSlice(X.Index(i).Interface())
	}

	return res
}
