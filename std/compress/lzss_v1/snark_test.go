package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"testing"
	"time"
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
	testCompressionRoundTripSnark(t, 2, append([]byte{1}, make([]byte, 257)...))
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
	t.SkipNow() // TODO unskip
	t.Parallel()
	folders := []string{
		"3c2943",
	}
	for _, folder := range folders {
		d, err := os.ReadFile("../test_cases/" + folder + "/data.bin")
		require.NoError(t, err)
		t.Run(folder, func(t *testing.T) {
			testCompressionRoundTripSnark(t, 2, d)
		})
	}
}

func BenchmarkCompilation64KBSnark(b *testing.B) {
	c := DecompressionTestCircuit{
		C: make([]frontend.Variable, 21333),
		D: make([]byte, 64000),
		Settings: Settings{
			BackRefSettings: BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
			},
		},
	}

	p := profile.Start()
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println(p.NbConstraints(), "constraints")
}

func BenchmarkCompilation300KBSnark(b *testing.B) {
	c := DecompressionTestCircuit{
		C: make([]frontend.Variable, 70000),
		D: make([]byte, 300000),
		Settings: Settings{
			BackRefSettings: BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
			},
		},
	}

	testCaseName := "large"

	// compilation
	fmt.Println("compilation")
	p := profile.Start()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println("26KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*300000)/26000, "constraints for 600KB at", float64(p.NbConstraints())/26000.0, "constraints per uncompressed byte")
	assert.NoError(b, compress.GzWrite("../test_cases/"+testCaseName+"/300KB.cs.gz", cs))

	// setup
	fmt.Println("setup")
	kzgSrs, err := test.NewKZGSRS(cs)
	require.NoError(b, err)
	pk, _, err := plonk.Setup(cs, kzgSrs)
	require.NoError(b, err)
	assert.NoError(b, compress.GzWrite("../test_cases/"+testCaseName+"/300KB.pk.gz", pk))
}

// TODO Change name to reflect that setup is also occurring
func compile26KBSnark(t require.TestingT, testCaseName string) {
	c := DecompressionTestCircuit{
		C: make([]frontend.Variable, 7300),
		D: make([]byte, 26000),
		Settings: Settings{
			BackRefSettings: BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
			},
		},
	}

	startTimer := func() {}
	stopTimer := func() {}
	if b, ok := t.(*testing.B); ok {
		startTimer = func() {
			b.StartTimer()
		}

		stopTimer = func() {
			b.StopTimer()
		}
	}

	// compilation
	fmt.Println("compilation")
	p := profile.Start()
	startTimer()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(t, err)
	stopTimer()
	p.Stop()
	fmt.Println("26KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*600000)/26000, "constraints for 600KB at", float64(p.NbConstraints())/26000.0, "constraints per uncompressed byte")
	assert.NoError(t, compress.GzWrite("../test_cases/"+testCaseName+"/cs.gz", cs))

	// setup
	fmt.Println("setup")
	startTimer()
	kzgSrs, err := test.NewKZGSRS(cs)
	require.NoError(t, err)
	pk, _, err := plonk.Setup(cs, kzgSrs)
	require.NoError(t, err)
	stopTimer()
	assert.NoError(t, compress.GzWrite("../test_cases/"+testCaseName+"/pk.gz", pk))
}

func BenchmarkCompilation26KBSnark(b *testing.B) {
	compile26KBSnark(b, "3c2943")
}

func BenchmarkProof26KBSnark(b *testing.B) {
	cs := plonk.NewCS(ecc.BN254)
	pk := plonk.NewProvingKey(ecc.BN254)

	if err := compress.GzRead("../test_cases/3c2943/cs.gz", cs); err != nil { // we don't have the constraints stored. compile and try again
		fmt.Println("reading constraints failed. attempting to recreate...")
		compile26KBSnark(b, "3c2943")
		fmt.Println("created constraints and proving key")
		cs = plonk.NewCS(ecc.BN254)
		assert.NoError(b, compress.GzRead("../test_cases/3c2943/cs.gz", cs))
	}
	fmt.Println("constraints loaded")
	assert.NoError(b, compress.GzRead("../test_cases/3c2943/pk.gz", pk))
	fmt.Println("proving key loaded")
	c, err := os.ReadFile("../test_cases/3c2943/data.lzssv1")
	assert.NoError(b, err)
	proveDecompressionSnark(b, cs, pk, c, 7300)
}

func BenchmarkCompilation600KBSnark(b *testing.B) {
	c := DecompressionTestCircuit{
		C: make([]frontend.Variable, 120000),
		D: make([]byte, 612000),
		Settings: Settings{
			BackRefSettings: BackRefSettings{
				NbBytesAddress: 2,
				NbBytesLength:  1,
			},
		},
	}

	p := profile.Start()
	_, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &c)
	assert.NoError(b, err)
	p.Stop()
	fmt.Println(p.NbConstraints(), "constraints")
}

func testCompressionRoundTripSnark(t *testing.T, nbBytesOffset uint, d []byte) {
	const contextSize = 256
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesOffset,
			NbBytesLength:  1,
		},
		StartAt: contextSize,
	}

	d = append(make([]byte, contextSize), d...)
	c, err := Compress(d, settings)
	require.NoError(t, err)
	testDecompressionSnark(t, nbBytesOffset, c, d[contextSize:])
}

func testDecompressionSnark(t *testing.T, nbBytesOffset uint, c []byte, d []byte) {
	settings := Settings{
		BackRefSettings: BackRefSettings{
			NbBytesAddress: nbBytesOffset,
			NbBytesLength:  1,
		},
	}

	cMax := len(c) * 3

	decompressor := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cMax),
		D:                d,
		Settings:         settings,
		CheckCorrectness: true,
	}
	//p := profile.Start()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, decompressor)
	//p.Stop()
	require.NoError(t, err)

	kzgSrs, err := test.NewKZGSRS(cs)
	require.NoError(t, err)
	pk, _, err := plonk.Setup(cs, kzgSrs)
	require.NoError(t, err)

	proveDecompressionSnark(t, cs, pk, c, cMax)
}

func proveDecompressionSnark(t require.TestingT, cs constraint.ConstraintSystem, pk plonk.ProvingKey, c []byte, cMax int) {

	cVars := make([]frontend.Variable, cMax)
	for i := range c {
		cVars[i] = frontend.Variable(c[i])
	}

	for i := len(c); i < len(cVars); i++ {
		cVars[i] = 0
	}

	var start int64
	restartTimer := func() {
		if start != 0 {
			fmt.Println("time taken:", time.Now().UnixMilli()-start, "ms")
		}
		start = time.Now().UnixMilli()
	}

	fmt.Println("constructing witness")
	_witness, err := frontend.NewWitness(&DecompressionTestCircuit{
		C:       cVars,
		CLength: len(c),
	}, ecc.BN254.ScalarField())
	require.NoError(t, err)
	restartTimer()
	fmt.Println("proving")
	_, err = plonk.Prove(cs, pk, _witness)
	require.NoError(t, err)
	restartTimer()
}
