package evmprecompiles

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type sha256PermuteCircuit struct {
	PrevDigest     [16]frontend.Variable
	Block          [32]frontend.Variable
	ExpectedDigest [16]frontend.Variable
}

func (c *sha256PermuteCircuit) Define(api frontend.API) error {
	SHA256Permute(api, c.PrevDigest, c.Block, c.ExpectedDigest)
	return nil
}

var fixedIV [16]uint16 = [16]uint16{
	0x0001, 0x0010, 0x0100, 0x1000, 0x0008, 0x0080, 0x0800, 0x8000,
	0x000f, 0x00f0, 0x0f00, 0xf000, 0x0001, 0x0001, 0x0001, 0x0001,
}

var fixedBlock [32]uint16 = [32]uint16{
	0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0007, 0x0008,
	0x0009, 0x000a, 0x000b, 0x000c, 0x000d, 0x000e, 0x000f, 0x0010,
	0x0011, 0x0012, 0x0013, 0x0014, 0x0015, 0x0016, 0x0017, 0x0018,
	0x0019, 0x001a, 0x001b, 0x001c, 0x001d, 0x001e, 0x001f, 0x0020,
}

var expectedDigest [16]uint16 = [16]uint16{
	0xd2d6, 0xeaf0, 0xa1c5, 0xc819, 0xac97, 0x25fe, 0x6c74, 0x4cf0,
	0x7f2f, 0xa2ba, 0x82ec, 0xea3b, 0x46aa, 0x6ef0, 0x236a, 0x8f63,
}

func TestSha256Permute(t *testing.T) {
	assert := test.NewAssert(t)
	witness := sha256PermuteCircuit{}
	for i := range witness.PrevDigest {
		witness.PrevDigest[i] = fixedIV[i]
	}
	for i := range witness.Block {
		witness.Block[i] = fixedBlock[i]
	}
	for i := range witness.ExpectedDigest {
		witness.ExpectedDigest[i] = expectedDigest[i]
	}
	err := test.IsSolved(&sha256PermuteCircuit{}, &witness, ecc.BLS12_377.ScalarField())
	assert.NoError(err)
}
