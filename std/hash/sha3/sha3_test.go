package sha3

import (
	"hash"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	zkhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
	"golang.org/x/crypto/sha3"
)

type testCase struct {
	zk     func(api frontend.API) (zkhash.BinaryHasher, error)
	native func() hash.Hash
}

var testCases = map[string]testCase{
	"SHA3-256":   {New256, sha3.New256},
	"SHA3-384":   {New384, sha3.New384},
	"SHA3-512":   {New512, sha3.New512},
	"Keccak-256": {NewLegacyKeccak256, sha3.NewLegacyKeccak256},
	"Keccak-512": {NewLegacyKeccak512, sha3.NewLegacyKeccak512},
}

var currentHash func(api frontend.API) (zkhash.BinaryHasher, error)

type sha3Circuit struct {
	In       []uints.U8
	Expected []uints.U8
}

func (c *sha3Circuit) Define(api frontend.API) error {
	h, err := currentHash(api)
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}

	h.Write(c.In)
	res := h.Sum()

	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA3(t *testing.T) {
	in := make([]byte, 310)

	for name, strategy := range testCases {
		h := strategy.native()
		h.Write(in)
		expected := h.Sum(nil)

		circuit := &sha3Circuit{
			In:       make([]uints.U8, len(in)),
			Expected: make([]uints.U8, len(expected)),
		}

		witness := &sha3Circuit{
			In:       uints.NewU8Array(in),
			Expected: uints.NewU8Array(expected),
		}

		currentHash = strategy.zk

		if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
			t.Fatalf("%s: %s", name, err)
		}
	}
}
