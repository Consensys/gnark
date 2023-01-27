package witness_test

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/witness"
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

func (c *circuit) Define(frontend.API) error {
	return nil
}

func roundTripMarshal(assert *require.Assertions, assignment circuit, publicOnly bool) {
	// build the vector
	var opts []frontend.WitnessOption
	if publicOnly {
		opts = append(opts, frontend.PublicOnly())
	}
	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField(), opts...)
	assert.NoError(err)

	// serialize the vector to binary
	data, err := w.MarshalBinary()
	assert.NoError(err)

	// re-read
	rw, err := witness.New(ecc.BN254.ScalarField())
	assert.NoError(err)
	err = rw.UnmarshalBinary(data)
	assert.NoError(err)

	assert.True(reflect.DeepEqual(rw, w), "witness binary round trip serialization")

}

func TestMarshalPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)

	roundTripMarshal(assert, assignment, true)
}

func TestMarshal(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	roundTripMarshal(assert, assignment, false)
}

func TestPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	w, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	assert.NoError(err)

	publicW, err := w.Public()
	assert.NoError(err)

	wt := publicW.Vector().(fr.Vector)

	assert.Equal(3, len(w.Vector().(fr.Vector)))
	assert.Equal(2, len(wt))

	assert.Equal("42", wt[0].String())
	assert.Equal("8000", wt[1].String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.TypeOf(circuit{}.E)
}
