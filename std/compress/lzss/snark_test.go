package lzss

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/lookup/logderivlookup"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"sync"
	"testing"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

func TestNoCompressionSnark(t *testing.T) {

	d, err := os.ReadFile("./testdata/test_cases/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	compressor, err := NewCompressor(dict, NoCompression)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict, BestCompression)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            BestCompression,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func Test4ZerosBackref(t *testing.T) {

	shortBackRefType, longBackRefType, _ := initBackRefTypes(0, BestCompression)

	testDecompressionSnark(t, nil, BestCompression, 0, backref{
		address: 0,
		length:  2,
		bType:   shortBackRefType,
	}, backref{
		address: 1,
		length:  1,
		bType:   longBackRefType,
	},
	)
}

func Test255_254_253(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{255, 254, 253}, nil)
}

func Test3c2943Snark(t *testing.T) {
	d, err := os.ReadFile("./testdata/test_cases/3c2943/data.bin")
	assert.NoError(t, err)

	dict := getDictionary()

	testCompressionRoundTripSnark(t, d, dict)
}

// Fuzz test the decompression
func FuzzSnark(f *testing.F) {
	f.Fuzz(func(t *testing.T, input, dict []byte) {
		if len(input) > maxInputSize {
			t.Skip("input too large")
		}
		if len(dict) > maxDictSize {
			t.Skip("dict too large")
		}
		if len(input) == 0 {
			t.Skip("input too small")
		}
		testCompressionRoundTripSnark(t, input, dict)
	})
}

func testCompressionRoundTripSnark(t *testing.T, d, dict []byte) {

	level := BestCompression
	if len(d) > 1000 {
		level = GoodCompression
	}

	compressor, err := NewCompressor(dict, level)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict, level)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            level,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func testDecompressionSnark(t *testing.T, dict []byte, level Level, compressedStream ...interface{}) {
	var bb bytes.Buffer
	w := bitio.NewWriter(&bb)
	bb.Write([]byte{0, byte(level)})
	i := 0
	for _, c := range compressedStream {
		switch v := c.(type) {
		case byte:
			assert.NoError(t, w.WriteByte(v))
			i++
		case int:
			assert.True(t, v >= 0 && v <= 255)
			assert.NoError(t, w.WriteByte(byte(v)))
			i++
		case []byte:
			for _, b := range v {
				assert.NoError(t, w.WriteByte(b))
			}
			i += len(v)
		case backref:
			v.writeTo(w, i)
			i += v.length
		default:
			panic("not implemented")
		}
	}
	assert.NoError(t, w.Close())
	c := bb.Bytes()
	d, err := DecompressGo(c, dict)
	require.NoError(t, err)
	cStream := ReadIntoStream(c, dict, BestCompression)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		Level:            BestCompression,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func TestReadBytes(t *testing.T) {
	expected := []byte{0, 254, 0, 0}
	circuit := &readBytesCircuit{
		Words:      make([]frontend.Variable, 8*len(expected)),
		WordNbBits: 1,
		Expected:   expected,
	}
	words := compress.NewStreamFromBytes(expected)
	words = words.BreakUp(2)
	assignment := &readBytesCircuit{
		Words: test_vector_utils.ToVariableSlice(words.D),
	}
	test.NewAssert(t).SolvingSucceeded(circuit, assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type readBytesCircuit struct {
	Words      []frontend.Variable
	WordNbBits int
	Expected   []byte
}

func (c *readBytesCircuit) Define(api frontend.API) error {
	byts := combineIntoBytes(api, c.Words, c.WordNbBits)
	for i := range c.Expected {
		api.AssertIsEqual(c.Expected[i], byts[i*8])
	}
	return nil
}

type assertWithTableCircuit struct {
	C []frontend.Variable
	N int
}

func (c *assertWithTableCircuit) Define(api frontend.API) error {
	table := logderivlookup.New(api)

	for i := 0; i < c.N; i++ {
		table.Insert(0)
	}

	_ = table.Lookup(c.C...)

	return nil
}

type assertWithConstraintCircuit struct {
	C []frontend.Variable
	N int
}

func (c *assertWithConstraintCircuit) Define(api frontend.API) error {

	var check func(frontend.Variable)

	switch c.N {
	case 2:
		check = api.AssertIsBoolean
	case 4:
		check = api.AssertIsCrumb
	default:
		return errors.New("not implemented")
	}

	for _, x := range c.C {
		check(x)
	}
	return nil
}

func TestCompareAssertions(t *testing.T) {

	nums := bytes.Repeat([]byte{0}, 2400000)

	var wg sync.WaitGroup
	tst := func(name string, circuit frontend.Circuit) {
		cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, circuit)
		assert.NoError(t, err)
		fmt.Println(name, cs.GetNbConstraints())
		wg.Done()
	}

	wg.Add(4)
	go tst("table_2", &assertWithTableCircuit{
		C: test_vector_utils.ToVariableSlice(nums),
		N: 2,
	})
	go tst("table_4", &assertWithTableCircuit{
		C: test_vector_utils.ToVariableSlice(nums),
		N: 4,
	})
	go tst("constraint_2", &assertWithConstraintCircuit{
		C: test_vector_utils.ToVariableSlice(nums),
		N: 2,
	})
	tst("constraint_4", &assertWithConstraintCircuit{
		C: test_vector_utils.ToVariableSlice(nums),
		N: 4,
	})
	wg.Wait()
}
