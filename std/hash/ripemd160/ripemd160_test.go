package ripemd160

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/ripemd160" //nolint staticcheck, backwards compatiblity
)

type ripemd160Circuit struct {
	In       []uints.U8
	Expected [20]uints.U8
}

func (c *ripemd160Circuit) Define(api frontend.API) error {
	h, err := New(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.Sum()
	if len(res) != len(c.Expected) {
		return fmt.Errorf("not 20 bytes")
	}
	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestRipemd160(t *testing.T) {
	bts := make([]byte, 310)
	h := ripemd160.New()
	h.Write(bts)
	dgst := h.Sum(nil)
	witness := ripemd160Circuit{
		In: uints.NewU8Array(bts),
	}
	copy(witness.Expected[:], uints.NewU8Array(dgst[:]))
	err := test.IsSolved(&ripemd160Circuit{In: make([]uints.U8, len(bts))}, &witness, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatal(err)
	}
}
