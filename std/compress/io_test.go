package compress

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
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

func BenchmarkShiftLeft(b *testing.B) {
	const n = 128 * 1024

	circuit := shiftLeftCircuit{
		Slice:   make([]frontend.Variable, n),
		Shifted: make([]frontend.Variable, n),
	}

	p := profile.Start()
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println(cs.GetNbConstraints(), "constraints")
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

func TestChecksumBytes(t *testing.T) {

	for n := 1; n < 100; n++ {
		b := make([]byte, n)
		_, err := rand.Read(b)
		assert.NoError(t, err)

		checksum := ChecksumBytes(b, len(b), hash.MIMC_BLS12_377.New(), fr.Bits)

		circuit := checksumTestCircuit{
			Bytes: make([]frontend.Variable, len(b)),
		}

		assignment := checksumTestCircuit{
			Bytes: test_vector_utils.ToVariableSlice(b),
			Sum:   checksum,
		}

		test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))

	}
}

type checksumTestCircuit struct {
	Bytes []frontend.Variable
	Sum   frontend.Variable
}

func (c *checksumTestCircuit) Define(api frontend.API) error {
	Packed := append(Pack(api, c.Bytes, 8), len(c.Bytes))
	return AssertChecksumEquals(api, Packed, c.Sum)
}
