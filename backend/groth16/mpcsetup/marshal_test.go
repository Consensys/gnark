package mpcsetup

import (
	"bytes"
	"io"
	"reflect"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/stretchr/testify/require"
)

func TestContributionSerialization(t *testing.T) {
	assert := require.New(t)

	// Phase 1
	srs1 := InitPhase1(9)
	srs1.Contribute()
	{
		var reconstructed Phase1
		roundTripCheck(t, &srs1, &reconstructed)
	}

	var myCircuit Circuit
	ccs, err := frontend.Compile(bn254.ID.ScalarField(), r1cs.NewBuilder, &myCircuit)
	assert.NoError(err)

	r1cs := ccs.(*cs_bn254.R1CS)

	// Phase 2
	srs2, _ := InitPhase2(r1cs, &srs1)
	srs2.Contribute()

	{
		var reconstructed Phase2
		roundTripCheck(t, &srs2, &reconstructed)
	}
}

func roundTripCheck(t *testing.T, from io.WriterTo, reconstructed io.ReaderFrom) {
	t.Helper()

	var buf bytes.Buffer
	written, err := from.WriteTo(&buf)
	if err != nil {
		t.Fatal("couldn't serialize", err)
	}

	read, err := reconstructed.ReadFrom(&buf)
	if err != nil {
		t.Fatal("couldn't deserialize", err)
	}

	if !reflect.DeepEqual(from, reconstructed) {
		t.Fatal("reconstructed object don't match original")
	}

	if written != read {
		t.Fatal("bytes written / read don't match")
	}
}
