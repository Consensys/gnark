package lzss

import (
	"compress/gzip"
	"fmt"
	goCompress "github.com/consensys/compress"
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/hash/mimc"
	"os"
	"time"
)

type DecompressionTestCircuit struct {
	C                []frontend.Variable
	D                []byte
	Dict             []byte
	CLength          frontend.Variable
	CheckCorrectness bool
	Level            lzss.Level
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dBack := make([]frontend.Variable, len(c.D)) // TODO Try smaller constants
	dLen, err := Decompress(api, c.C, c.CLength, dBack, c.Dict, c.Level)
	if err != nil {
		return err
	}
	if c.CheckCorrectness {
		api.AssertIsEqual(len(c.D), dLen)
		for i := range c.D {
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

	level := lzss.GoodCompression

	compressor, err := lzss.NewCompressor(dict, level)
	if err != nil {
		return nil, err
	}

	c, err := compressor.Compress(d)
	if err != nil {
		return nil, err
	}

	cStream, err := goCompress.NewStream(c, uint8(level))
	if err != nil {
		return nil, err
	}

	circuit := compressionCircuit{
		C:     make([]frontend.Variable, cStream.Len()),
		D:     make([]frontend.Variable, len(d)),
		Dict:  make([]byte, len(dict)),
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
	if err != nil {
		return nil, err
	}
	p.Stop()
	fmt.Println(1+len(d)/1024, "KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*600000)/len(d), "constraints for 600KB at", float64(p.NbConstraints())/float64(len(d)), "constraints per uncompressed byte")
	resetTimer()

	outFile, err := os.OpenFile("./testdata/test_cases/"+name+"/e2e_cs.gz", os.O_CREATE, 0600)
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
	if _, err = cs.WriteTo(gz); err != nil {
		return nil, err
	}
	return cs, gz.Close()
}

type compressionCircuit struct {
	CChecksum, DChecksum frontend.Variable `gnark:",public"`
	C                    []frontend.Variable
	D                    []frontend.Variable
	Dict                 []byte
	CLen, DLen           frontend.Variable
	Level                lzss.Level
}

func (c *compressionCircuit) Define(api frontend.API) error {

	fmt.Println("packing")
	cPacked := compress.Pack(api, c.C, int(c.Level))
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
	if dComputedLen, err := Decompress(api, c.C, c.CLen, dComputed, c.Dict, c.Level); err != nil {
		return err
	} else {
		api.AssertIsEqual(dComputedLen, c.DLen)
		for i := range c.D {
			api.AssertIsEqual(c.D[i], dComputed[i]) // could do this much more efficiently in groth16 using packing :(
		}
	}

	return nil
}

func check(s goCompress.Stream, padTo int) (checksum fr.Element, err error) {

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
