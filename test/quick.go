package test

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
	"sync"
	"testing"
)

var snarkFunctionStore sync.Map

type snarkFunctionTestCircuit struct {
	funcId     uint64            // this workaround is necessary because deepEquals fails on objects with function fields
	DummyInput frontend.Variable // to keep the Plonk backend from crashing
}

func (c *snarkFunctionTestCircuit) Define(api frontend.API) error {

	f, ok := snarkFunctionStore.Load(c.funcId)
	if !ok {
		return errors.New("function not found")
	}

	F, ok := f.(func(frontend.API) error)
	if !ok {
		panic("unexpected entry type")
	}

	return F(api)
}

// Function returns a test function that can run a simple circuit consisting of function f
func Function(f func(frontend.API) error, opts ...TestingOption) func(*testing.T) {
	return func(t *testing.T) {
		var (
			c snarkFunctionTestCircuit
			b [8]byte
		)
		_, err := rand.Read(b[:])
		require.NoError(t, err)
		c.funcId = binary.BigEndian.Uint64(b[:])
		snarkFunctionStore.Store(c.funcId, f)

		NewAssert(t).SolvingSucceeded(&c, &snarkFunctionTestCircuit{DummyInput: 0}, opts...)
		snarkFunctionStore.Delete(c.funcId)
	}
}
