package sha3

import (
	"crypto/rand"
	"fmt"
	"hash"
	"testing"

	"golang.org/x/crypto/sha3"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	zkhash "github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/test"
)

type testCase struct {
	zk     func(api frontend.API, opts ...zkhash.Option) (zkhash.BinaryFixedLengthHasher, error)
	native func() hash.Hash
}

var testCases = map[string]testCase{
	"SHA3-256":   {New256, sha3.New256},
	"SHA3-384":   {New384, sha3.New384},
	"SHA3-512":   {New512, sha3.New512},
	"Keccak-256": {NewLegacyKeccak256, sha3.NewLegacyKeccak256},
	"Keccak-512": {NewLegacyKeccak512, sha3.NewLegacyKeccak512},
}

type sha3Circuit struct {
	In       []uints.U8
	Expected []uints.U8

	hasher string
}

func (c *sha3Circuit) Define(api frontend.API) error {
	newHasher, ok := testCases[c.hasher]
	if !ok {
		return fmt.Errorf("hash function unknown: %s", c.hasher)
	}
	h, err := newHasher.zk(api)
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
	assert := test.NewAssert(t)
	in := make([]byte, 310)
	_, err := rand.Reader.Read(in)
	assert.NoError(err)

	for name := range testCases {
		assert.Run(func(assert *test.Assert) {
			name := name
			strategy := testCases[name]
			h := strategy.native()
			h.Write(in)
			expected := h.Sum(nil)

			circuit := &sha3Circuit{
				In:       make([]uints.U8, len(in)),
				Expected: make([]uints.U8, len(expected)),
				hasher:   name,
			}

			witness := &sha3Circuit{
				In:       uints.NewU8Array(in),
				Expected: uints.NewU8Array(expected),
			}

			if err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField()); err != nil {
				t.Fatalf("%s: %s", name, err)
			}
		}, name)
	}
}

type sha3FixedLengthSumCircuit struct {
	In       []uints.U8
	Expected []uints.U8
	Length   frontend.Variable
	hasher   string

	// minimal length of the input is the circuit parameter
	minimalLength int
}

func (c *sha3FixedLengthSumCircuit) Define(api frontend.API) error {
	newHasher, ok := testCases[c.hasher]
	if !ok {
		return fmt.Errorf("hash function unknown: %s", c.hasher)
	}
	h, err := newHasher.zk(api, zkhash.WithMinimalLength(c.minimalLength))
	if err != nil {
		return err
	}
	uapi, err := uints.New[uints.U64](api)
	if err != nil {
		return err
	}
	h.Write(c.In)
	res := h.FixedLengthSum(c.Length)

	for i := range c.Expected {
		uapi.ByteAssertEq(c.Expected[i], res[i])
	}
	return nil
}

func TestSHA3FixedLengthSum(t *testing.T) {
	const maxLen = 310
	assert := test.NewAssert(t)
	in := make([]byte, maxLen)
	_, err := rand.Reader.Read(in)
	assert.NoError(err)

	for name := range testCases {
		assert.Run(func(assert *test.Assert) {
			name := name
			strategy := testCases[name]
			nHasher := strategy.native()
			for _, lengthBound := range []int{0, 1, nHasher.BlockSize() - 1, nHasher.BlockSize(), nHasher.BlockSize() + 1, len(in)} {
				circuit := &sha3FixedLengthSumCircuit{
					In:            make([]uints.U8, len(in)),
					Expected:      make([]uints.U8, nHasher.Size()),
					hasher:        name,
					minimalLength: lengthBound,
				}
				for _, length := range []int{0, 1, nHasher.BlockSize() - 1, nHasher.BlockSize(), nHasher.BlockSize() + 1, len(in)} {
					assert.Run(func(assert *test.Assert) {
						h := strategy.native()
						h.Write(in[:length])
						expected := h.Sum(nil)

						witness := &sha3FixedLengthSumCircuit{
							In:       uints.NewU8Array(in),
							Expected: uints.NewU8Array(expected),
							Length:   length,
						}
						err := test.IsSolved(circuit, witness, ecc.BN254.ScalarField())
						if length >= lengthBound {
							assert.NoError(err)
						} else if length < lengthBound {
							assert.Error(err, "expected error for length < lengthBound")
						}
					}, fmt.Sprintf("bound=%d/length=%d", lengthBound, length))
				}
			}
		}, fmt.Sprintf("hash=%s", name))
	}
}
