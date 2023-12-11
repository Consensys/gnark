package main

import (
	"fmt"
	goCompress "github.com/consensys/compress"
	goLzss "github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
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

func main() {
	d, err := os.ReadFile(name + "/data.bin")
	checkError(err)

	dict, err := os.ReadFile("../testdata/dict_naive")
	checkError(err)

	// compress

	level := goLzss.GoodCompression

	compressor, err := goLzss.NewCompressor(dict, level)
	checkError(err)

	c, err := compressor.Compress(d)
	checkError(err)

	cStream, err := goCompress.NewStream(c, uint8(level))
	checkError(err)

	circuit := lzss.CompressionCircuit{
		C:     make([]frontend.Variable, cStream.Len()),
		D:     make([]frontend.Variable, len(d)),
		Dict:  dict,
		Level: level,
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
	checkError(err)

	p.Stop()
	fmt.Println(1+len(d)/1024, "KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*600000)/len(d), "constraints for 600KB at", float64(p.NbConstraints())/float64(len(d)), "constraints per uncompressed byte")
	resetTimer()

	// setup
	fmt.Println("setup")
	resetTimer()
	ckzg, lkzg, err := unsafekzg.NewSRS(cs)
	checkError(err)

	pk, _, err := plonk.Setup(cs, ckzg, lkzg)
	checkError(err)

	// proof
	fmt.Println("proof")
	resetTimer()

	cSum, err := lzss.StreamChecksum(cStream, cStream.Len())
	checkError(err)

	dStream, err := goCompress.NewStream(d, 8)
	checkError(err)
	dSum, err := lzss.StreamChecksum(dStream, len(d))
	checkError(err)

	assignment := lzss.CompressionCircuit{
		CChecksum: cSum,
		DChecksum: dSum,
		C:         test_vector_utils.ToVariableSlice(cStream.D),
		D:         test_vector_utils.ToVariableSlice(d),
		CLen:      cStream.Len(),
		DLen:      len(d),
	}

	wt, err := frontend.NewWitness(&assignment, ecc.BLS12_377.ScalarField())
	checkError(err)

	_, err = plonk.Prove(cs, pk, wt)
	checkError(err)
}
