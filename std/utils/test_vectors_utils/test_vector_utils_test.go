package test_vector_utils

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type constHashCircuit struct {
	X frontend.Variable
}

func (c *constHashCircuit) Define(api frontend.API) error {
	hsh := NewMessageCounter(api, 0, 0)
	hsh.Reset()
	hsh.Write(c.X)
	api.AssertIsEqual(hsh.Sum(), 0)
	return nil
}

func TestConstHash(t *testing.T) {
	test.NewAssert(t).SolvingSucceeded(&constHashCircuit{}, &constHashCircuit{X: 1})
}
