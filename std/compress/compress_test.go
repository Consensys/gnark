package compress

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"math/big"
	"os"
	"testing"
)

// TODO Edge case where "compressed" is longer than original data

func TestHexToBinary(t *testing.T) {
	in, err := os.ReadFile("data.hex")
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
	require.NoError(t, os.WriteFile("data.bin", out.Bytes(), 0644))
}

func readHex(out *bytes.Buffer, b *[]byte, size int) error {
	for i := 0; i < size; i++ {
		var hi, lo byte
		var err error
		if hi, err = expectHexDigit(b); err != nil {
			return err
		}
		if lo, err = expectHexDigit(b); err != nil {
			return err
		}
		out.WriteByte(hi<<4 | lo)
	}
	return nil
}

func expectHexDigit(b *[]byte) (byte, error) {
	res, err := expect(b, '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
		'a', 'b', 'c', 'd', 'e', 'f')
	if err != nil {
		return 255, err
	}
	if res >= 'a' {
		res -= 'a' - 10
	} else {
		res -= '0'
	}
	return res, nil
}

func expectStar(b *[]byte, c byte) {
	_, err := expect(b, c)
	for err == nil {
		_, err = expect(b, c)
	}
}

func expectNumber(b *[]byte) (int, error) {
	digits := []byte{'0', '1', '2', '3', '4', '5', '6', '7', '8', '9'}
	var n int
	c, err := expect(b, digits...)
	n = int(c - '0')
	if err != nil {
		return n, err
	}
	c, err = expect(b, digits...)
	for err == nil {
		n *= 10
		n += int(c - '0')
		c, err = expect(b, digits...)
	}
	return n, nil
}

func expectString(b *[]byte, s string) error {
	for i := 0; i < len(s); i++ {
		c, err := expect(b, s[i])
		if err != nil {
			return err
		}
		if c != s[i] {
			return fmt.Errorf("expected %s, got %s", s, string(c))
		}
	}
	return nil
}

func expect(b *[]byte, cs ...byte) (byte, error) {
	if len(*b) == 0 {
		return 0, fmt.Errorf("end of input")
	}
	seen := (*b)[0]
	for _, c := range cs {
		if seen == c {
			*b = (*b)[1:]
			return seen, nil
		}
	}
	return seen, fmt.Errorf("unexpected %c", seen)
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
			//fmt.Println(i-i0, i0, i)
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
	in, err := os.ReadFile("data.bin")
	require.NoError(t, err)

	require.NoError(t, compressZeroCounter(&out, in))

	compressed := out.Bytes()

	require.NoError(t, os.WriteFile("data.zct", compressed, 0644))
	fmt.Printf("achieved %d%% compression", 100*len(compressed)/len(in))

	// decompress and check match
	var decompressed bytes.Buffer
	require.NoError(t, decompressZeroCounter(&decompressed, compressed))

	require.Equal(t, in, decompressed.Bytes())
}

func BytesToVars(d []byte) []frontend.Variable {
	byteDomain := fft.NewDomain(256)
	g := byteDomain.Generator
	vars := make([]frontend.Variable, len(d))
	for i := range d {
		var b big.Int
		b.SetUint64(uint64(d[i]))
		var x fr.Element
		x.Exp(g, &b)
		vars[i] = x
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

		//InputIndex:   IntsToVars(inputIndex),
		//ZerosToWrite: IntsToVars(zerosToWrite),
	}
}

func IntsToVars(slice []int) []frontend.Variable {
	vars := make([]frontend.Variable, len(slice))
	for i := range slice {
		vars[i] = frontend.Variable(slice[i])
	}
	return vars
}

func (c *decompressionProofCircuit) hollow() *decompressionProofCircuit {
	return &decompressionProofCircuit{
		DataBytes:       make([]frontend.Variable, len(c.DataBytes)),
		CompressedBytes: make([]frontend.Variable, len(c.CompressedBytes)),
		//InputIndex:      make([]frontend.Variable, len(c.InputIndex)),
		//ZerosToWrite:    make([]frontend.Variable, len(c.ZerosToWrite)),
	}
}

// f(X) := X^256 - 1 / X - 1 = X^255 + X^254 + ... + X + 1 =
// (X^128 + 1)(X^64 + 1)...(X^2+1)(X+1)
// b :=  \zeta^i where \zeta^256 = 1
// if i \neq 0, then f(b) = 0
// if i = 0, then f(b) = 256
// so ByteIsZero computes f(b)/256
func ByteIsZero(api frontend.API, b frontend.Variable) frontend.Variable {
	bPow := b
	res := api.Inverse(256) // TODO does gnark precompute this automatically?
	for i := 0; i < 8; i++ {
		res = api.Mul(res, api.Add(bPow, 1))
		if i+1 < 8 {
			bPow = api.Mul(bPow, bPow)
		}
	}
	return res
}

// only for bn254
func (c *decompressionProofCircuit) Define(api frontend.API) error {
	// TODO assert that compressed bytes are actually bytes

	bytesDomain := fft.NewDomain(256)

	data, compressed := c.DataBytes, c.CompressedBytes
	inputIndex := make([]frontend.Variable, len(c.DataBytes)) //, zerosToWrite := c.InputIndex, c.ZerosToWrite
	zerosToWrite := make([]frontend.Variable, len(c.DataBytes))

	//indexDomain := fft.NewDomain(uint64(len(data)))
	api.AssertIsEqual(data[0], compressed[0])

	// this is insanely inefficient TODO replace with an efficient lookup method
	compressedMap := test_vector_utils.Map{
		Keys:   make([]frontend.Variable, len(compressed)),
		Values: make([]frontend.Variable, len(compressed)),
	}
	for i := range compressed {
		compressedMap.Keys[i] = frontend.Variable(i)
		compressedMap.Values[i] = compressed[i]
	}

	currentInput := compressed[0]
	inputLookAhead := compressed[1]
	prevInputZero := frontend.Variable(0)
	currentInputZero := ByteIsZero(api, currentInput)
	zerosToWrite[0] = api.Mul(currentInputZero, inputLookAhead)
	api.Println("zerosToWrite[ 0 ] =", DecodeByte(api, zerosToWrite[0]))

	//prevInput := compressed[0]
	inputIndex[0] = 0
	for i := 1; i < len(data); i++ {
		prevInputZero = currentInputZero
		//fmt.Println("data[", i, "] =", data[i])

		// input index
		noMoreZerosToWrite := ByteIsZero(api, zerosToWrite[i-1]) // z
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
		diff := api.MulAcc(1, prevInputZero, coeff)
		api.Println("diff", diff)
		inputIndex[i] = api.Add(inputIndex[i-1], diff)
		api.Println("inputIndex[", i, "] =", inputIndex[i])
		// Current input
		currentInput = compressedMap.Get(api, inputIndex[i])
		inputLookAhead = compressedMap.Get(api, api.Add(inputIndex[i], 1))
		api.Println("currentInput[", i, "] =", DecodeByte(api, currentInput))
		api.Println("inputLookAhead[", i, "] =", DecodeByte(api, inputLookAhead))
		currentInputZero = ByteIsZero(api, currentInput)

		// zeros to write
		oneFewerZeroToWrite := api.Mul(zerosToWrite[i-1], bytesDomain.GeneratorInv)
		coeff = api.Sub(inputLookAhead, 1)
		coeff = api.MulAcc(1, coeff, currentInputZero)
		coeff = api.Sub(coeff, oneFewerZeroToWrite) // this and the previous line could be a single plonk constraint
		zerosToWrite[i] = api.MulAcc(oneFewerZeroToWrite, noMoreZerosToWrite, coeff)

		api.Println("zerosToWrite[", i, "] =", DecodeByte(api, zerosToWrite[i]))

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

			// output
			if zerosToWrite[i-1] == 0 {
				assert.Equal(t, compressed[inputIndex[i]], data[i])
			} else {
				assert.Equal(t, byte(0), data[i])
			}*/

		api.AssertIsEqual(data[i], currentInput)

		//prevInput = currentInput
	}

	return nil
}

func DecodeByte(api frontend.API, b frontend.Variable) frontend.Variable {
	g := fft.NewDomain(256).Generator
	keys := make([]frontend.Variable, 256)
	values := make([]frontend.Variable, 256)
	gPow := frontend.Variable(1)
	for i := range keys {
		keys[i] = gPow
		values[i] = i
		gPow = api.Mul(gPow, g)
	}
	return test_vector_utils.Map{Keys: keys, Values: values}.Get(api, b)
}

func TestCreateProof(t *testing.T) {
	data, err := hex.DecodeString("0000002b23dd5f0000")
	require.NoError(t, err)
	assignment := newDecompressionProofCircuitBn254(t, data)
	circuit := assignment.hollow()
	circuit.hollow() // noop todo remove
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithCurves(ecc.BN254), test.WithBackends(backend.GROTH16))
}

type byteIsZeroTestCircuit struct {
	ActualValues []byte
	Values       []frontend.Variable
}

func (c *byteIsZeroTestCircuit) Define(api frontend.API) error {
	for i := range c.ActualValues {
		isZero := ByteIsZero(api, c.Values[i])
		if c.ActualValues[i] == 0 {
			api.AssertIsEqual(isZero, 1)
		} else {
			api.AssertIsEqual(isZero, 0)
		}
	}
	return nil
}

func (c *byteIsZeroTestCircuit) hollow() *byteIsZeroTestCircuit {
	return &byteIsZeroTestCircuit{
		ActualValues: c.ActualValues,
		Values:       make([]frontend.Variable, len(c.Values)),
	}
}

func TestByteIsZero(t *testing.T) {
	actualValues := []byte{0, 1, 2, 0, 3, 4, 0, 5, 6, 7, 244}
	values := BytesToVars(actualValues)
	assignment := &byteIsZeroTestCircuit{
		ActualValues: actualValues,
		Values:       values,
	}
	circuit := assignment.hollow()
	test.NewAssert(t).ProverSucceeded(circuit, assignment, test.WithCurves(ecc.BN254))
}
