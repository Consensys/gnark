package witness

import (
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	X *fr.Element `gnark:",public"`
	Y *fr.Element `gnark:",public"`

	E *fr.Element
}

type marshaller uint8

const (
	JSON marshaller = iota
	Binary
)

func roundTripMarshal(assert *require.Assertions, assignment circuit, m marshaller, publicOnly bool) {
	// build the vector
	w, err := New(ecc.BN254.ScalarField(), nil)
	assert.NoError(err)

	w.Schema, err = w.Vector.FromAssignment(&assignment, tVariable, publicOnly)
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

	switch wt := witness.Vector.(type) {
	case *witness_bls12377.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bls12381.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bls24315.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bn254.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bw6633.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	case *witness_bw6761.Witness:
		wt.ToAssignment(&reconstructed, tVariable, publicOnly)
	default:
		panic("not implemented")
	}

	assert.True(reflect.DeepEqual(assignment, reconstructed), "public witness reconstructed doesn't match original value")
}

func TestMarshalPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)

	roundTripMarshal(assert, assignment, JSON, true)
	roundTripMarshal(assert, assignment, Binary, true)
}

func TestMarshal(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	roundTripMarshal(assert, assignment, JSON, false)
	roundTripMarshal(assert, assignment, Binary, false)
}

func TestPublic(t *testing.T) {
	assert := require.New(t)

	var assignment circuit
	assignment.X = new(fr.Element).SetInt64(42)
	assignment.Y = new(fr.Element).SetInt64(8000)
	assignment.E = new(fr.Element).SetInt64(1)

	w, err := New(ecc.BN254.ScalarField(), nil)
	assert.NoError(err)

	w.Schema, err = w.Vector.FromAssignment(&assignment, tVariable, false)
	assert.NoError(err)

	publicW, err := w.Public()
	assert.NoError(err)

	assert.Equal(3, w.Vector.Len())
	assert.Equal(2, publicW.Vector.Len())

	wt := publicW.Vector.(*witness_bn254.Witness)

	assert.Equal("42", (*wt)[0].String())
	assert.Equal("8000", (*wt)[1].String())
}

var tVariable reflect.Type

func init() {
	tVariable = reflect.TypeOf(circuit{}.E)
}
