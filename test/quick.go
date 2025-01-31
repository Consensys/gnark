package test

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/stretchr/testify/require"
	"testing"
)

var snarkFunctionStore = make(map[uint64]func(frontend.API) []frontend.Variable) // todo make thread safe
type snarkFunctionTestCircuit struct {
	Outs   []frontend.Variable
	funcId uint64 // this workaround is necessary because deepEquals fails on objects with function fields
}

func (c *snarkFunctionTestCircuit) Define(api frontend.API) error {
	outs := snarkFunctionStore[c.funcId](api)
	delete(snarkFunctionStore, c.funcId)

	// todo replace with SliceEquals
	if len(outs) != len(c.Outs) {
		return errors.New("SingleFunction: unexpected number of output")
	}
	for i := range outs {
		api.AssertIsEqual(outs[i], c.Outs[i])
	}
	return nil
}

// SingleFunction returns a test function that can run a simple circuit consisting of function f, and match its output with outs
func SingleFunction(curve ecc.ID, f func(frontend.API) []frontend.Variable, outs ...frontend.Variable) func(*testing.T) {

	return func(t *testing.T) {
		c := snarkFunctionTestCircuit{
			Outs: make([]frontend.Variable, len(outs)),
		}
		var b [8]byte
		_, err := rand.Read(b[:])
		require.NoError(t, err)
		c.funcId = binary.BigEndian.Uint64(b[:])
		snarkFunctionStore[c.funcId] = f

		a := snarkFunctionTestCircuit{
			Outs: outs,
		}
		require.NoError(t, IsSolved(&c, &a, curve.ScalarField()))
	}
}
