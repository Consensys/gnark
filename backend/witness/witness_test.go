package witness

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
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

	var reconstructed circuit
	// serialize the vector to binary
	data, err := marshal()
	assert.NoError(err)

	// re-read
	witness := Witness{CurveID: ecc.BN254}
	unmarshal := witness.UnmarshalBinary
	if m == JSON {
		unmarshal = witness.UnmarshalJSON
	}
	err = unmarshal(data)
	assert.NoError(err)

	// reconstruct a circuit object
	err = witness.copyTo(&reconstructed, tVariable)
	assert.NoError(err)

	assert.True(reflect.DeepEqual(assignment, reconstructed), "public witness reconstructed doesn't match original value")
}

func TestMarshalPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	var e fr.Element
	assignment.X = *(e.SetInt64(42))
	assignment.Y = *(e.SetInt64(8000))

	roundTripMarshal(assert, assignment, Binary, PublicOnly())
}

func TestMarshal(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	var e fr.Element
	assignment.X = *(e.SetInt64(42))
	assignment.Y = *(e.SetInt64(8000))
	assignment.E = *(e.SetInt64(1))

	roundTripMarshal(assert, assignment, Binary)
}
