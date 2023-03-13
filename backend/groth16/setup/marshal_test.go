package setup

import (
	"bytes"
	"io"
	"reflect"
	"testing"
)

func TestPhase1Serialization(t *testing.T) {
	var phase1, reconstructed Phase1
	phase1 = NewPhase1(8)

	roundTripCheck(t, &phase1, &reconstructed)
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
