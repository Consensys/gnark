package main

import (
	"fmt"
	goCompress "github.com/consensys/compress"
	goLzss "github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress/lzss"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test/unsafekzg"
	"os"
	"time"
)

const name = "../testdata/large"

func checkError(err error) {
	if err != nil {
		panic(err)
	}
}

func getCircuits() (circuit, assignment lzss.CompressionCircuit, err error) {
	//d, err := os.ReadFile(name + "/data.bin")
	//if err != nil { return }
	d := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	dict, err := os.ReadFile("../testdata/dict_naive")
	if err != nil {
		return
	}

	// compress

	level := goLzss.GoodCompression

	compressor, err := goLzss.NewCompressor(dict, level)
	if err != nil {
		return
	}

	c, err := compressor.Compress(d)
	if err != nil {
		return
	}

	cStream, err := goCompress.NewStream(c, uint8(level))
	if err != nil {
		return
	}

	circuit = lzss.CompressionCircuit{
		C:     make([]frontend.Variable, cStream.Len()),
		D:     make([]frontend.Variable, len(d)),
		Dict:  dict,
		Level: level,
	}

	cSum, err := checksumStream(cStream, cStream.Len())
	if err != nil {
		return
	}

	dStream, err := goCompress.NewStream(d, 8)
	if err != nil {
		return
	}
	dSum, err := checksumStream(dStream, len(d))
	if err != nil {
		return
	}

	assignment = lzss.CompressionCircuit{
		CChecksum: cSum,
		DChecksum: dSum,
		C:         test_vector_utils.ToVariableSlice(cStream.D),
		D:         test_vector_utils.ToVariableSlice(d),
		CLen:      cStream.Len(),
		DLen:      len(d),
	}

	return
}

func main() {

	circuit, assignment, err := getCircuits()
	checkError(err)

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
	checkError(err)

	p.Stop()
	fmt.Println(1+len(circuit.D)/1024, "KB:", p.NbConstraints(), "constraints")
	resetTimer()

	// setup
	fmt.Println("setup")
	ckzg, lkzg, err := unsafekzg.NewSRS(cs)
	checkError(err)

	pk, _, err := plonk.Setup(cs, ckzg, lkzg)
	checkError(err)
	resetTimer()

	// proof
	fmt.Println("proof")

	wt, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	checkError(err)

	_, err = plonk.Prove(cs, pk, wt)
	checkError(err)
	resetTimer()
}

func checksumStream(s goCompress.Stream, padTo int) (checksum fr.Element, err error) {

	s.D = append(s.D, make([]int, padTo-len(s.D))...)

	csb := s.Checksum(hash.MIMC_BN254.New(), fr.Bits)
	checksum.SetBytes(csb)
	return
}
