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

func TestReconstructionPublic(t *testing.T) {
	assert := require.New(t)

	var wPublic, wPublicReconstructed circuit
	var e fr.Element
	wPublic.X = *(e.SetInt64(42))
	wPublic.Y = *(e.SetInt64(8000))

	// build the vector
	w, err := New(&wPublic, ecc.BN254, PublicOnly())
	assert.NoError(err)

	// serialize the vector to binary
	data, err := w.MarshalBinary()
	assert.NoError(err)

	// re-read
	wReconstructed := Witness{
		CurveID: ecc.BN254,
	}
	err = wReconstructed.UnmarshalBinary(data)
	assert.NoError(err)

	// reconstruct a circuit object
	err = wReconstructed.copyTo(&wPublicReconstructed, tVariable)
	assert.NoError(err)

	if !reflect.DeepEqual(wPublic, wPublicReconstructed) {
		t.Fatal("public witness reconstructed doesn't match original value")
	}
}

func TestReconstructionFull(t *testing.T) {
	assert := require.New(t)

	var wFull, wFullReconstructed circuit
	var e fr.Element
	wFull.X = *(e.SetInt64(42))
	wFull.Y = *(e.SetInt64(8000))
	wFull.E = *(e.SetInt64(1))

	// build the vector
	w, err := New(&wFull, ecc.BN254)
	assert.NoError(err)

	// serialize the vector to binary
	data, err := w.MarshalBinary()
	assert.NoError(err)

	// re-read
	wReconstructed := Witness{
		CurveID: ecc.BN254,
	}
	err = wReconstructed.UnmarshalBinary(data)
	assert.NoError(err)

	// reconstruct a circuit object
	err = wReconstructed.copyTo(&wFullReconstructed, tVariable)
	assert.NoError(err)

	if !reflect.DeepEqual(wFull, wFullReconstructed) {
		t.Fatal("full witness reconstructed doesn't match original value")
	}
}
