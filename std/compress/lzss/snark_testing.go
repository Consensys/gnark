package lzss

import (
	"github.com/consensys/compress/lzss"
	"github.com/consensys/gnark/frontend"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
)

// TODO Make this match the new packing and checksumming scheme

type DecompressionTestCircuit struct {
	C                []frontend.Variable
	D                []byte
	Dict             []byte
	CLength          frontend.Variable
	CheckCorrectness bool
	Level            lzss.Level
}

func (c *DecompressionTestCircuit) Define(api frontend.API) error {
	dict := test_vector_utils.ToVariableSlice(lzss.AugmentDict(c.Dict))
	dBack := make([]frontend.Variable, len(c.D)) // TODO Try smaller constants
	dLen, err := Decompress(api, c.C, c.CLength, dBack, dict, c.Level)
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

/*
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

	cStream, err := compress.NewStream(c, uint8(level))
	if err != nil {
		return nil, err
	}

	circuit := TestCompressionCircuit{
		C:     make([]frontend.Variable, cStream.Len()),
		D:     make([]frontend.Variable, len(d)),
		Dict:  make([]frontend.Variable, len(lzss.AugmentDict(dict))),
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

type TestCompressionCircuit struct {
	CChecksum, DChecksum, DictChecksum frontend.Variable `gnark:",public"`
	C                                  []frontend.Variable
	D                                  []frontend.Variable
	Dict                               []frontend.Variable
	CLen, DLen                         frontend.Variable
	Level                              lzss.Level
}

func (c *TestCompressionCircuit) Define(api frontend.API) error {

	fmt.Println("packing")
	cPacked := compress2.Pack(api, c.C, int(c.Level))
	dPacked := compress2.Pack(api, c.D, 8)
	dictPacked := compress2.Pack(api, c.Dict, 8)

	fmt.Println("computing checksum")
	if err := compress2.AssertChecksumEquals(api, cPacked, c.CLen, c.CChecksum); err != nil {
		return err
	}
	if err := compress2.AssertChecksumEquals(api, dPacked, c.DLen, c.DChecksum); err != nil {
		return err
	}
	if err := compress2.AssertChecksumEquals(api, dictPacked, len(c.Dict), c.DictChecksum); err != nil {
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

func check(s compress.Stream, padTo int) (checksum fr.Element, err error) {

	s.D = append(s.D, make([]int, padTo-len(s.D))...)

	csb := s.Checksum(hash.MIMC_BLS12_377.New(), fr.Bits)
	checksum.SetBytes(csb)
	return
}
*/
