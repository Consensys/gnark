package compress

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/witness"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"os"
	"testing"
	"time"
)

const TestCase = //"705b24/"

"777003/"

//"c9b5a2/"
//"fa4a22/"
//"e4207e/"

//"3c2943/"

// TODO Edge case where "compressed" is longer than original data

func TestHexToBinary(t *testing.T) {
	in, err := os.ReadFile(TestCase + "data.hex")
	require.NoError(t, err)

	var out bytes.Buffer

	for i := 0; len(in) != 0; i++ {
		_, err = expect(&in, '[')
		require.NoError(t, err)

		var n int
		n, err = expectNumber(&in)
		require.NoError(t, err)
		require.Equal(t, i, n)

		require.NoError(t, expectString(&in, "]:"))
		expectStar(&in, ' ')

		require.NoError(t, readHex(&out, &in, 32))

		_, err = expect(&in, '\n')
		require.NoError(t, err)
	}
	require.NoError(t, os.WriteFile(TestCase+"data.bin", out.Bytes(), 0644))
}

func compressZeroCounter(out io.ByteWriter, in []byte) error {
	for i := 0; i < len(in); i++ {
		if err := out.WriteByte(in[i]); err != nil {
			return err
		}
		if in[i] == 0 {
			i0 := i
			for i < len(in) && in[i] == 0 && i-i0 < 256 {
				i++
			}
			i--

			fmt.Println("zero sequence length", i-i0)
			if err := out.WriteByte(byte(i - i0)); err != nil {
				return err
			}
		}
	}
	return nil
}

func decompressZeroCounter(out io.ByteWriter, in []byte) error {
	for i := 0; i < len(in); i++ {
		if err := out.WriteByte(in[i]); err != nil {
			return err
		}
		if in[i] == 0 {
			i++
			for l := in[i]; l > 0; l-- {
				if err := out.WriteByte(0); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func TestZeroCounterTrivial(t *testing.T) {
	var compressed, decompressed bytes.Buffer
	data := []byte{0}
	require.NoError(t, compressZeroCounter(&compressed, data))
	require.NoError(t, decompressZeroCounter(&decompressed, compressed.Bytes()))
	assert.Equal(t, data, decompressed.Bytes())
}

func TestCompressZeroCounter(t *testing.T) {
	var out bytes.Buffer
	in, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)

	require.NoError(t, compressZeroCounter(&out, in))

	compressed := out.Bytes()

	require.NoError(t, os.WriteFile(TestCase+"data.zct", compressed, 0644))
	fmt.Println("original size", len(in))
	fmt.Printf("achieved %d%% compression\n", 100*len(compressed)/len(in))
	fmt.Println("compression rate", float64(len(in))/float64(len(compressed)))
	zerosGasCost := float64(len(in)-len(compressed)) * .25
	fmt.Println("gas cost", float64(len(compressed))/(float64(len(compressed))+zerosGasCost))

	// decompress and check match
	var decompressed bytes.Buffer
	require.NoError(t, decompressZeroCounter(&decompressed, compressed))

	require.Equal(t, in, decompressed.Bytes())
}

func BytesToVars(d []byte) []frontend.Variable {
	vars := make([]frontend.Variable, len(d))
	for i := range d {
		vars[i] = d[i]
	}
	return vars
}

type decompressionProofCircuit struct {
	DataBytes       []frontend.Variable // TODO: 0 - 255 or roots of unity?
	CompressedBytes []frontend.Variable

	// proof
	//InputIndex   []frontend.Variable
	//ZerosToWrite []frontend.Variable
}

func newDecompressionProofCircuitBn254(t *testing.T, data []byte) *decompressionProofCircuit {
	var bb bytes.Buffer
	if err := compressZeroCounter(&bb, data); err != nil {
		panic(err)
	}
	compressed := bb.Bytes()

	inputIndex := make([]int, len(data))
	zerosToWrite := make([]int, len(data))

	if data[0] == 0 {
		zerosToWrite[0] = int(compressed[1])
	}

	assert.Equal(t, data[0], compressed[0])

	for i := 1; i < len(data); i++ {
		// input index
		if compressed[inputIndex[i-1]] == 0 {
			if zerosToWrite[i-1] == 0 {
				inputIndex[i] = inputIndex[i-1] + 2
			} else {
				inputIndex[i] = inputIndex[i-1]
			}
		} else {
			inputIndex[i] = inputIndex[i-1] + 1
		}

		// zeros to write
		if zerosToWrite[i-1] != 0 {
			zerosToWrite[i] = zerosToWrite[i-1] - 1
		} else {
			if compressed[inputIndex[i]] == 0 {
				zerosToWrite[i] = int(compressed[inputIndex[i]+1])
			} else {
				zerosToWrite[i] = 0
			}
		}

		// output
		if zerosToWrite[i-1] != 0 {
			assert.Equal(t, byte(0), data[i])
		} else {
			assert.Equal(t, compressed[inputIndex[i]], data[i])
		}
	}

	fmt.Println("data", data)
	fmt.Println("compressed", compressed)
	fmt.Println("input index", inputIndex)
	fmt.Println("zeros to write", zerosToWrite)

	return &decompressionProofCircuit{
		DataBytes:       BytesToVars(data),
		CompressedBytes: BytesToVars(compressed),
	}
}

func (c *decompressionProofCircuit) hollow() *decompressionProofCircuit {
	return &decompressionProofCircuit{
		DataBytes:       make([]frontend.Variable, len(c.DataBytes)),
		CompressedBytes: make([]frontend.Variable, len(c.CompressedBytes)),
	}
}

// only for bn254
func (c *decompressionProofCircuit) Define(api frontend.API) error {

	byteIsZeroTable := logderivlookup.New(api)
	bytesTable := logderivlookup.New(api) // TODO replace this with a simple set membership
	byteIsZeroTable.Insert(1)
	bytesTable.Insert(0)
	for i := 1; i < 256; i++ {
		byteIsZeroTable.Insert(0)
		bytesTable.Insert(0)
	}

	data, compressed := c.DataBytes, c.CompressedBytes
	inputIndex := make([]frontend.Variable, len(c.DataBytes))
	zerosToWrite := make([]frontend.Variable, len(c.DataBytes))

	// assert that the input are actually bytes
	bytesMembership := bytesTable.Lookup(compressed...)
	for i := range bytesMembership {
		api.AssertIsEqual(bytesMembership[i], 0)
	}

	api.AssertIsEqual(data[0], compressed[0])

	compressedMap := logderivlookup.New(api)
	for i := range compressed {
		compressedMap.Insert(compressed[i])
	}

	currentInput := compressed[0]
	inputLookAhead := compressed[1]
	prevInputZero := frontend.Variable(0)
	currentInputZero := byteIsZeroTable.Lookup(currentInput)[0]
	zerosToWrite[0] = api.Mul(currentInputZero, inputLookAhead)
	api.Println("zerosToWrite[ 0 ] =", zerosToWrite[0])

	//prevInput := compressed[0]
	inputIndex[0] = 0
	for i := 1; i < len(data); i++ {
		prevInputZero = currentInputZero
		//fmt.Println("data[", i, "] =", data[i])

		// input index
		noMoreZerosToWrite := byteIsZeroTable.Lookup(zerosToWrite[i-1])[0] // z
		/*if compressed[inputIndex[i-1]] == 0 {
			if zerosToWrite[i-1] == 0 {
				inputIndex[i] = inputIndex[i-1] + 2
			} else {
				inputIndex[i] = inputIndex[i-1]
			}
		} else {
			inputIndex[i] = inputIndex[i-1] + 1
		}*/
		coeff := api.Add(noMoreZerosToWrite, noMoreZerosToWrite, -1) // 2z - 1
		api.Println("step 1", coeff)
		api.Println("prevInputZero", prevInputZero)
		diffMinusOne := api.Mul(prevInputZero, coeff) // 2zp - p
		api.Println("diffMinusOne", diffMinusOne)
		inputIndex[i] = api.Add(inputIndex[i-1], diffMinusOne, 1) // 2zp - p + 1
		api.Println("inputIndex[", i, "] =", inputIndex[i])
		// Current input
		api.Println("currentInput[", i, "] =", currentInput)
		api.Println("inputLookAhead[", i, "] =", inputLookAhead)
		if i+1 < len(data) {
			ins := compressedMap.Lookup(inputIndex[i], api.Add(inputIndex[i], 1))
			currentInput, inputLookAhead = ins[0], ins[1]
		} else {
			currentInput = compressedMap.Lookup(inputIndex[i])[0]
			//api.AssertIsDifferent(currentInput, 0) TODO: Check that the input correc
		}
		currentInputZero = byteIsZeroTable.Lookup(currentInput)[0]

		// zeros to write
		coeff = api.MulAcc(
			api.Sub(1, zerosToWrite[i-1]),
			currentInputZero, inputLookAhead) // this can be a single plonk constraint

		zerosToWrite[i] = api.MulAcc(
			api.Sub(zerosToWrite[i-1], 1),
			noMoreZerosToWrite, coeff) // this can be a single plonk constraint

		api.Println("zerosToWrite[", i, "] =", zerosToWrite[i])

		/*

				// zeros to write
			if zerosToWrite[i-1] == 0 {
				if compressed[inputIndex[i]] == 0 {
					zerosToWrite[i] = int(compressed[inputIndex[i]+1])
				} else {
					zerosToWrite[i] = 0
				}
			} else {
				zerosToWrite[i] = zerosToWrite[i-1] - 1
			}
		*/

		api.AssertIsEqual(data[i], currentInput)

		//prevInput = currentInput
	}

	return nil
}

func TestCreateProofSmall(t *testing.T) {
	data, err := hex.DecodeString("0000002b23dd5f0000")
	require.NoError(t, err)
	assignment := newDecompressionProofCircuitBn254(t, data)
	circuit := assignment.hollow()
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCreateProofSmallReal(t *testing.T) {
	data, err := hex.DecodeString("0000002b23dd5f0000")
	require.NoError(t, err)
	assignment := newDecompressionProofCircuitBn254(t, data)
	circuit := assignment.hollow()
	var (
		cs     constraint.ConstraintSystem
		wtness witness.Witness
		pk     groth16.ProvingKey
	)
	fmt.Println("compiling...")
	p := profile.Start()
	cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	p.Stop()
	fmt.Println(cs.GetNbConstraints(), " constraints")

	wtness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	pk, err = groth16.DummySetup(cs)
	_, err = groth16.Prove(cs, pk, wtness)
	require.NoError(t, err)
}

func TestCreateProofMedium(t *testing.T) {
	data, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	assignment := newDecompressionProofCircuitBn254(t, data[:100])
	circuit := assignment.hollow()
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestCreateProofLargeBench(t *testing.T) {
	data, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)
	start := time.Now().UnixMilli()
	assignment := newDecompressionProofCircuitBn254(t, data)
	circuit := assignment.hollow()
	var (
		cs     constraint.ConstraintSystem
		wtness witness.Witness
		pk     groth16.ProvingKey
	)
	fmt.Println("compiling...")

	cs, err = frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	fmt.Println("compile time", time.Now().UnixMilli()-start, "ms")
	fmt.Println(cs.GetNbConstraints(), "r1cs constraints")
	start = time.Now().UnixMilli()

	wtness, err = frontend.NewWitness(assignment, ecc.BN254.ScalarField())
	require.NoError(t, err)
	fmt.Println("new witness time", time.Now().UnixMilli()-start, "ms")
	pk, err = groth16.DummySetup(cs)
	start = time.Now().UnixMilli()
	_, err = groth16.Prove(cs, pk, wtness)
	require.NoError(t, err)
	fmt.Println("prove time", time.Now().UnixMilli()-start, "ms")
	fmt.Println("compiling...")
	p := profile.Start()
	cs, err = frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
	p.Stop()
	fmt.Println(cs.GetNbConstraints(), "scs constraints")

	//test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

func TestLongestZerosChunk(t *testing.T) {
	data, err := os.ReadFile(TestCase + "data.bin")
	require.NoError(t, err)

	chunk, largestChunk := 0, 0
	for i := range data {
		if data[i] == 0 {
			chunk++
		} else {
			if chunk > largestChunk {
				largestChunk = chunk
			}
			chunk = 0
		}
	}
	fmt.Println("largest chunk", largestChunk)
}
