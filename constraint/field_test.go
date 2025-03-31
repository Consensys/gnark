package constraint

import (
	"bytes"
	"testing"

	fr_bn254 "github.com/consensys/gnark-crypto/ecc/bn254/fr"
	fr_bw6761 "github.com/consensys/gnark-crypto/ecc/bw6-761/fr"
	"github.com/consensys/gnark-crypto/field/babybear"
)

func TestNewElement(t *testing.T) {
	var r1 fr_bn254.Element
	var r2 fr_bw6761.Element
	var r3 babybear.Element
	r1.SetRandom()
	r2.SetRandom()
	r3.SetRandom()

	r1b := r1.Bytes()
	r2b := r2.Bytes()
	r3b := r3.Bytes()

	r1bp := append(r1b[:], make([]byte, 48-len(r1b))...)

	e1 := NewElement[U64](r1bp[:])
	e2 := NewElement[U64](r2b[:])
	e3 := NewElement[U32](r3b[:])

	e1b := e1.Bytes()
	e2b := e2.Bytes()
	e3b := e3.Bytes()

	if len(e1b[:32]) != len(r1b) {
		t.Fatalf("expected %d, got %d", len(r1b), len(e1b))
	}
	if len(e2b) != len(r2b) {
		t.Fatalf("expected %d, got %d", len(r2b), len(e2b))
	}
	if len(e3b) != len(r3b) {
		t.Fatalf("expected %d, got %d", len(r3b), len(e3b))
	}

	if !bytes.Equal(e1b[:32], r1b[:]) {
		t.Fatalf("expected %x, got %x", r1b, e1b)
	}
	if !bytes.Equal(e2b, r2b[:]) {
		t.Fatalf("expected %x, got %x", r2b, e2b)
	}
	if !bytes.Equal(e3b, r3b[:]) {
		t.Fatalf("expected %x, got %x", r3b, e3b)
	}
}
