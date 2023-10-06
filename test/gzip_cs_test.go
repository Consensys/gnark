package test

import (
	"bytes"
	"compress/gzip"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/stretchr/testify/assert"
	"testing"
)

type isZeroCircuit struct {
	X frontend.Variable
}

func (c *isZeroCircuit) Define(api frontend.API) error {
	api.AssertIsEqual(c.X, 0)
	return nil
}

func TestGZipRoundTrip(t *testing.T) {
	var c isZeroCircuit
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(t, err)

	var bb bytes.Buffer
	gzW := gzip.NewWriter(&bb)
	_, err = cs.WriteTo(gzW)
	assert.NoError(t, err)
	assert.NoError(t, gzW.Close())

	gzR, err := gzip.NewReader(&bb)
	assert.NoError(t, err)
	_, err = cs.ReadFrom(gzR)
	assert.NoError(t, err)
}
