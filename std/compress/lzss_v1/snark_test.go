package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{0})
	testCompressionRoundTripSnark(t, 2, []byte{0})
}

func Test2ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{0, 0})
	testCompressionRoundTripSnark(t, 2, []byte{0, 0})
}

func Test8ZerosSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{0, 0, 0, 0, 0, 0, 0, 0})
	testCompressionRoundTripSnark(t, 2, []byte{0, 0, 0, 0, 0, 0, 0, 0})
}

func TestTwoConsecutiveBackrefsSnark(t *testing.T) {
	testDecompressionSnark(t, 1, make([]byte, 6), []byte{0, 0})
}
func Test300ZerosSnark(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTripSnark(t, 1, make([]byte, 300))
	testCompressionRoundTripSnark(t, 2, make([]byte, 300))
}

func TestSingleNonzeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{1})
	testCompressionRoundTripSnark(t, 2, []byte{1})
}

func TestHiSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{'h', 'i'})
	testCompressionRoundTripSnark(t, 2, []byte{'h', 'i'})
}

func TestZeroAfterNonzeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{1, 0})
	testCompressionRoundTripSnark(t, 2, []byte{1, 0})
}

func TestTwoZerosAfterNonzeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{1, 0, 0})
	testCompressionRoundTripSnark(t, 2, []byte{1, 0, 0})
}

func Test8ZerosAfterNonzeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, append([]byte{1}, make([]byte, 8)...))
	testCompressionRoundTripSnark(t, 2, append([]byte{1}, make([]byte, 8)...))
}

func TestTwoBackrefsAfterNonzeroSnark(t *testing.T) {
	testDecompressionSnark(t, 1, []byte{1, 0, 1, 0, 0, 0, 0}, []byte{1, 0, 0})
}

func Test257ZerosAfterNonzeroSnark(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTripSnark(t, 1, append([]byte{1}, make([]byte, 257)...))
	//testCompressionRoundTripSnark(t, 2, append([]byte{1}, make([]byte, 257)...))
}

func Test300ZerosAfterNonzeroSnark(t *testing.T) { // probably won't happen in our calldata
	testCompressionRoundTripSnark(t, 1, append([]byte{'h', 'i'}, make([]byte, 300)...))
	testCompressionRoundTripSnark(t, 2, append([]byte{'h', 'i'}, make([]byte, 300)...))
}

func TestRepeatedNonzeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, 1, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
	testCompressionRoundTripSnark(t, 2, []byte{'h', 'i', 'h', 'i', 'h', 'i'})
}

func TestCalldataSnark(t *testing.T) {
	t.Parallel()
	folders := []string{
		"3c2943",
	}
	for _, folder := range folders {
		d, err := os.ReadFile("../" + folder + "/data.bin")
		require.NoError(t, err)
		t.Run(folder, func(t *testing.T) {
			testCompressionRoundTripSnark(t, 2, d)
		})
	}
}

func BenchmarkCompilation26KBSnark(b *testing.B) {
	c := decompressionTestCircuit{
		C: make([]frontend.Variable, 7000),
		D: make([]byte, 30000),
		settings: Settings{
			BackRefSettings: BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
				Symbol:         0,
			},
		},
	}

	p := profile.Start()
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println(p.NbConstraints(), "constraints")
}

type decompressionTestCircuit struct {
	C        []frontend.Variable
	D        []byte
	settings Settings
}

func (c *decompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)*2) // TODO Try smaller constants
	api.Println("maxLen(dBack)", len(dBack))
	dLen, err := Decompress(api, c.C, dBack, c.settings)
	if err != nil {
		return err
	}
	api.Println("got len", dLen, "expected", len(c.D))
	api.AssertIsEqual(len(c.D), dLen)
	for i := range c.D {
		api.Println("decompressed at", i, "->", dBack[i], "expected", c.D[i], "dBack", dBack[i])
		api.AssertIsEqual(c.D[i], dBack[i])
	}
	return nil
}

func testCompressionRoundTripSnark(t *testing.T, nbBytesOffset uint, d []byte) {
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesOffset,
			NbBytesLength:  1,
			Symbol:         0,
			ReferenceTo:    false,
			AddressingMode: false,
		},
		Logger:   nil,
		LogHeads: new([]LogHeads),
	}

	c, err := Compress(d, settings)
	require.NoError(t, err)
	testDecompressionSnark(t, nbBytesOffset, c, d)
}

func testDecompressionSnark(t *testing.T, nbBytesOffset uint, c []byte, d []byte) {
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesOffset,
			NbBytesLength:  1,
			Symbol:         0,
		},
	}

	cVars := make([]frontend.Variable, len(c)*3+settings.BackRefSettings.NbBytes())
	for i := range c {
		cVars[i] = frontend.Variable(c[i])
	}
	cVars[len(c)] = SnarkEofSymbol
	for i := len(c) + 1; i < len(cVars); i++ {
		cVars[i] = 0
	}

	decompressor := &decompressionTestCircuit{
		C:        make([]frontend.Variable, len(cVars)),
		D:        d,
		settings: settings,
	}
	//p := profile.Start()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, decompressor)
	//p.Stop()
	require.NoError(t, err)
	kzgSrs, err := test.NewKZGSRS(cs)
	require.NoError(t, err)
	pk, _, err := plonk.Setup(cs, kzgSrs)
	require.NoError(t, err)
	_witness, err := frontend.NewWitness(&decompressionTestCircuit{
		C: cVars,
	}, ecc.BN254.ScalarField())
	require.NoError(t, err)
	_, err = plonk.Prove(cs, pk, _witness)
	require.NoError(t, err)
}
