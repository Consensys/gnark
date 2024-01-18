package compress

import (
	"crypto/rand"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestShiftLeft(t *testing.T) {
	for n := 4; n < 20; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		assert.NoError(t, err)

		shiftAmount, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
		assert.NoError(t, err)

		shifted := make([]byte, n)
		for i := range shifted {
			if j := i + int(shiftAmount.Int64()); j < len(shifted) {
				shifted[i] = b[j]
			} else {
				shifted[i] = 0
			}
		}

		circuit := shiftLeftCircuit{
			Slice:   make([]frontend.Variable, len(b)),
			Shifted: make([]frontend.Variable, len(shifted)),
		}

		assignment := shiftLeftCircuit{
			Slice:       test_vector_utils.ToVariableSlice(b),
			Shifted:     test_vector_utils.ToVariableSlice(shifted),
			ShiftAmount: shiftAmount,
		}

		test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
	}
}

type shiftLeftCircuit struct {
	Slice       []frontend.Variable
	Shifted     []frontend.Variable
	ShiftAmount frontend.Variable
}

func (c *shiftLeftCircuit) Define(api frontend.API) error {
	if len(c.Slice) != len(c.Shifted) {
		panic("witness length mismatch")
	}
	shifted := ShiftLeft(api, c.Slice, c.ShiftAmount)
	if len(shifted) != len(c.Shifted) {
		panic("wrong length")
	}
	for i := range shifted {
		api.AssertIsEqual(c.Shifted[i], shifted[i])
	}
	return nil
}
