package lzss_v1

import (
	"errors"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/compress"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"testing"
)

func TestPack(t *testing.T) {
	field := ecc.BN254.ScalarField()

	d := []int{1, 2, 3}
	c := compress.Stream{
		D:       d,
		NbSymbs: 256,
	}
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBitsAddress: 8,
			NbBitsLength:  8,
		},
	}

	packed := Pack(c, field.BitLen(), settings)

	circuit := packingTestCircuit{
		Packed:   make([]frontend.Variable, len(packed)),
		Unpacked: make([]frontend.Variable, len(d)),
	}

	assignment := packingTestCircuit{
		Packed:   packed,
		Unpacked: test_vector_utils.ToVariableSlice(d),
	}

	solver.RegisterHint(Decompose)
	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type packingTestCircuit struct {
	Packed   []frontend.Variable
	Unpacked []frontend.Variable
	Settings Settings
}

func (c *packingTestCircuit) Define(api frontend.API) error {
	unpacked, err := Unpack(api, c.Packed, c.Settings)
	if err != nil {
		return err
	}
	if len(unpacked) < len(c.Unpacked) {
		return errors.New("length mismatch")
	}
	for i := range c.Unpacked {
		api.AssertIsEqual(c.Unpacked[i], unpacked[i])
	}
	for i := len(c.Unpacked); i < len(unpacked); i++ {
		api.AssertIsEqual(unpacked[i], 0)
	}
	return nil
}
