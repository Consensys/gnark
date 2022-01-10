package witness

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	witness_bls12377 "github.com/consensys/gnark/internal/backend/bls12-377/witness"
	witness_bls12381 "github.com/consensys/gnark/internal/backend/bls12-381/witness"
	witness_bls24315 "github.com/consensys/gnark/internal/backend/bls24-315/witness"
	witness_bn254 "github.com/consensys/gnark/internal/backend/bn254/witness"
	witness_bw6633 "github.com/consensys/gnark/internal/backend/bw6-633/witness"
	witness_bw6761 "github.com/consensys/gnark/internal/backend/bw6-761/witness"
	"github.com/stretchr/testify/require"
)

type circuit struct {
	// tagging a variable is optional
	// default uses variable name and secret visibility.
	X frontend.Variable `gnark:",public"`
	Y frontend.Variable `gnark:",public"`

	E frontend.Variable
}

func (circuit *circuit) Define(api frontend.API) error {
	return nil
}

type marshaller uint8

const (
	JSON marshaller = iota
	Binary
)

func roundTripMarshal(assert *require.Assertions, assignment circuit, m marshaller, opts ...func(opt *WitnessOption) error) {
	// build the vector
	w, err := New(&assignment, ecc.BN254, opts...)
	assert.NoError(err)

	marshal := w.MarshalBinary
	if m == JSON {
		marshal = w.MarshalJSON
	}

	// serialize the vector to binary
	data, err := marshal()
	assert.NoError(err)

	// re-read
	witness := Witness{CurveID: ecc.BN254, Schema: w.Schema}
	unmarshal := witness.UnmarshalBinary
	if m == JSON {
		unmarshal = witness.UnmarshalJSON
	}
	err = unmarshal(data)
	assert.NoError(err)

	// reconstruct a circuit object
	var reconstructed circuit

	// TODO @gbotrel this is very ugly fixme
	publicOnly := len(opts) > 0
	switch wt := witness.Vector.(type) {
	case *witness_bls12377.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bls12381.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bls24315.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bn254.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bw6633.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bw6761.Witness:
		wt.VectorToAssignment(&reconstructed, tVariable, publicOnly)
	default:
		panic("not implemented")
	}

	// err = witness.copyTo(&reconstructed, tVariable)
	// assert.NoError(err)

	assert.True(reflect.DeepEqual(assignment, reconstructed), "public witness reconstructed doesn't match original value")
}

func TestMarshalPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	var e fr.Element
	assignment.X = *(e.SetInt64(42))
	assignment.Y = *(e.SetInt64(8000))

	roundTripMarshal(assert, assignment, JSON, PublicOnly())
	roundTripMarshal(assert, assignment, Binary, PublicOnly())
}

func TestMarshal(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	var e fr.Element
	assignment.X = *(e.SetInt64(42))
	assignment.Y = *(e.SetInt64(8000))
	assignment.E = *(e.SetInt64(1))

	roundTripMarshal(assert, assignment, JSON)
	roundTripMarshal(assert, assignment, Binary)
}

// TODO @gbotrel add test with unmarshal partial jsons
