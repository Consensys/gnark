package witness

import (
	"bytes"
	"math/big"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
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

func (circuit *circuit) Define(curveID ecc.ID, cs frontend.API) error {
	return nil
}

func TestReconstructionPublic(t *testing.T) {
	assert := require.New(t)

	var wPublic, wPublicReconstructed circuit
	wPublic.X.Assign(new(big.Int).SetInt64(42))
	wPublic.Y.Assign(new(big.Int).SetInt64(8000))

	var buf bytes.Buffer
	written, err := WritePublicTo(&buf, ecc.BN254, &wPublic)
	assert.NoError(err)

	read, err := ReadPublicFrom(&buf, ecc.BN254, &wPublicReconstructed)
	assert.NoError(err)
	assert.Equal(written, read)

	if !reflect.DeepEqual(wPublic, wPublicReconstructed) {
		t.Fatal("public witness reconstructed doesn't match original value")
	}
}

func TestReconstructionFull(t *testing.T) {
	assert := require.New(t)

	var wFull, wFullReconstructed circuit
	wFull.X.Assign(new(big.Int).SetInt64(42))
	wFull.Y.Assign(new(big.Int).SetInt64(8000))
	wFull.E.Assign(new(big.Int).SetInt64(1))

	var buf bytes.Buffer
	written, err := WriteFullTo(&buf, ecc.BN254, &wFull)
	assert.NoError(err)

	read, err := ReadFullFrom(&buf, ecc.BN254, &wFullReconstructed)
	assert.NoError(err)
	assert.Equal(written, read)

	if !reflect.DeepEqual(wFull, wFullReconstructed) {
		t.Fatal("public witness reconstructed doesn't match original value")
	}
}
