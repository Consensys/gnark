package lzss

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/hash/mimc"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/icza/bitio"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test1ZeroSnark(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0}, nil)
}

func Test0To10Explicit(t *testing.T) {
	testCompressionRoundTripSnark(t, []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, nil)
}

func Test3ZerosBackref(t *testing.T) {

	shortBackRefType, longBackRefType, _ := initBackRefTypes(0, BestCompression)

	testDecompressionSnark(t, nil, 0, backref{
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
	// read "average_block.hex" file
	d, err := os.ReadFile("../test_cases/3c2943/data.bin")
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

	compressionMode := BestCompression
	if len(d) > 1000 {
		compressionMode = GoodCompression
	}

	compressor, err := NewCompressor(dict, compressionMode)
	require.NoError(t, err)
	c, err := compressor.Compress(d)
	require.NoError(t, err)

	cStream := ReadIntoStream(c, dict, compressionMode)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		CompressionMode:  compressionMode,
	}
	assignment := &DecompressionTestCircuit{
		C:       test_vector_utils.ToVariableSlice(cStream.D),
		CLength: cStream.Len(),
	}

	test.NewAssert(t).CheckCircuit(circuit, test.WithValidAssignment(assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func testDecompressionSnark(t *testing.T, dict []byte, compressedStream ...interface{}) {
	var bb bytes.Buffer
	w := bitio.NewWriter(&bb)
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
	d, err := DecompressGo(c, dict, BestCompression)
	require.NoError(t, err)
	cStream := ReadIntoStream(c, dict, BestCompression)

	circuit := &DecompressionTestCircuit{
		C:                make([]frontend.Variable, cStream.Len()),
		D:                d,
		Dict:             dict,
		CheckCorrectness: true,
		CompressionMode:  BestCompression,
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

type DecompressionTestCircuit struct {
	C                []frontend.Variable
	D                []byte
	Dict             []byte
	CLength          frontend.Variable
	CheckCorrectness bool
	CompressionMode  CompressionMode
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)) // TODO Try smaller constants
	api.Println("maxLen(dBack)", len(dBack))
	dLen, err := Decompress(api, c.C, c.CLength, dBack, c.Dict, c.CompressionMode)
	if err != nil {
		return err
	}
	if c.CheckCorrectness {
		api.Println("got len", dLen, "expected", len(c.D))
		api.AssertIsEqual(len(c.D), dLen)
		for i := range c.D {
			api.Println("decompressed at", i, "->", dBack[i], "expected", c.D[i], "dBack", dBack[i])
			api.AssertIsEqual(c.D[i], dBack[i])
		}
	}
	return nil
}

func BenchCompressionE2ECompilation(dict []byte, name string) (constraint.ConstraintSystem, error) {
	d, err := os.ReadFile(name + "/data.bin")
	if err != nil {
		return nil, err
	}

	// compress

	compressor, err := NewCompressor(dict, GoodCompression)
	if err != nil {
		return nil, err
	}

	c, err := compressor.Compress(d)
	if err != nil {
		return nil, err
	}

	cStream := ReadIntoStream(c, dict, GoodCompression)

	circuit := compressionCircuit{
		C:               make([]frontend.Variable, cStream.Len()),
		D:               make([]frontend.Variable, len(d)),
		Dict:            make([]byte, len(dict)),
		CompressionMode: GoodCompression,
	}

	var start int64
	resetTimer := func() {
		end := time.Now().UnixMilli()
		if start != 0 {
			fmt.Println(end-start, "ms")
		}
		start = end
	}

	// compilation
	fmt.Println("compilation")
	p := profile.Start()
	resetTimer()
	cs, err := frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &circuit, frontend.WithCapacity(70620000*2))
	if err != nil {
		return nil, err
	}
	p.Stop()
	fmt.Println(1+len(d)/1024, "KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*600000)/len(d), "constraints for 600KB at", float64(p.NbConstraints())/float64(len(d)), "constraints per uncompressed byte")
	resetTimer()

	outFile, err := os.OpenFile("../test_cases/"+name+"/e2e_cs.gz", os.O_CREATE, 0600)
	closeFile := func() {
		if err := outFile.Close(); err != nil {
			panic(err)
		}
	}
	defer closeFile()

	if err != nil {
		return nil, err
	}
	gz := gzip.NewWriter(outFile)
	closeZip := func() {
		if err := gz.Close(); err != nil {
			panic(err)
		}
	}
	defer closeZip()

	_, err = cs.WriteTo(gz)

	return cs, err
}

type compressionCircuit struct {
	CChecksum, DChecksum frontend.Variable `gnark:",public"`
	C                    []frontend.Variable
	D                    []frontend.Variable
	Dict                 []byte
	CLen, DLen           frontend.Variable
	CompressionMode      CompressionMode
}

func (c *compressionCircuit) Define(api frontend.API) error {

	fmt.Println("packing")
	cPacked := compress.Pack(api, c.C, int(c.CompressionMode))
	dPacked := compress.Pack(api, c.D, 8)

	fmt.Println("computing checksum")
	if err := checkSnark(api, cPacked, c.CLen, c.CChecksum); err != nil {
		return err
	}
	if err := checkSnark(api, dPacked, c.DLen, c.DChecksum); err != nil {
		return err
	}

	fmt.Println("decompressing")
	dComputed := make([]frontend.Variable, len(c.D))
	if dComputedLen, err := Decompress(api, c.C, c.CLen, dComputed, c.Dict, c.CompressionMode); err != nil {
		return err
	} else {
		api.AssertIsEqual(dComputedLen, c.DLen)
		for i := range c.D {
			api.AssertIsEqual(c.D[i], dComputed[i]) // could do this much more efficiently in groth16 using packing :(
		}
	}

	return nil
}

func check(s compress.Stream, padTo int) (checksum fr.Element, err error) {

	s.D = append(s.D, make([]int, padTo-len(s.D))...)

	csb := s.Checksum(hash.MIMC_BN254.New(), fr.Bits)
	checksum.SetBytes(csb)
	return
}

func checkSnark(api frontend.API, e []frontend.Variable, eLen, checksum frontend.Variable) error {
	hsh, err := mimc.NewMiMC(api)
	if err != nil {
		return err
	}
	hsh.Write(e...)
	hsh.Write(eLen)
	api.AssertIsEqual(hsh.Sum(), checksum)
	return nil
}
