package lzss_v1

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/hash"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/std/compress"
	"github.com/consensys/gnark/std/hash/mimc"
	test_vector_utils "github.com/consensys/gnark/std/utils/test_vectors_utils"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
	"time"
)

func TestCompression1ZeroE2E(t *testing.T) {
	testCompressionE2E(t, []byte{0}, Settings{
		BackRefSettings: BackRefSettings{
			NbBitsAddress: 18,
			NbBitsLength:  8,
		},
	}, "1_zero")
}

func BenchmarkCompression26KBE2E(b *testing.B) {
	testCompressionE2E(b, nil, Settings{
		BackRefSettings: BackRefSettings{
			NbBitsAddress: 20,
			NbBitsLength:  8,
		},
	}, "3c2943")
}

func BenchmarkCompression600KBE2E(b *testing.B) {
	testCompressionE2E(b, nil, Settings{
		BackRefSettings: BackRefSettings{
			NbBitsAddress: 20,
			NbBitsLength:  8,
		},
	}, "large")
}

func testCompressionE2E(t assert.TestingT, d []byte, settings Settings, name string) {
	if d == nil {
		var err error
		d, err = os.ReadFile("../test_cases/" + name + "/data.bin")
		assert.NoError(t, err)
	}

	// compress

	c, err := Compress(d, settings)
	assert.NoError(t, err)

	cSum, err := check(c, len(c.D))
	assert.NoError(t, err)

	dSum, err := check(compress.NewStreamFromBytes(d), len(d))
	assert.NoError(t, err)

	circuit := compressionCircuit{
		C:        make([]frontend.Variable, c.Len()),
		D:        make([]frontend.Variable, len(d)),
		Settings: settings,
	}

	// solve the circuit or only compile it

	if t, ok := t.(*testing.T); ok {
		assignment := compressionCircuit{
			CChecksum: cSum,
			DChecksum: dSum,
			C:         test_vector_utils.ToVariableSlice(c.D),
			D:         test_vector_utils.ToVariableSlice(d),
			CLen:      c.Len(),
			DLen:      len(d),
		}
		test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
		return
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
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	assert.NoError(t, err)
	p.Stop()
	fmt.Println(1+len(d)/1024, "KB:", p.NbConstraints(), "constraints, estimated", (p.NbConstraints()*600000)/len(d), "constraints for 600KB at", float64(p.NbConstraints())/float64(len(d)), "constraints per uncompressed byte")
	assert.NoError(t, compress.GzWrite("../test_cases/"+name+"/e2e_cs.gz", cs))
	resetTimer()

	// setup
	fmt.Println("kzg setup")
	kzgSrs, err := test.NewKZGSRS(cs)
	resetTimer()
	fmt.Println("plonk setup")
	assert.NoError(t, err)
	_, _, err = plonk.Setup(cs, kzgSrs)
	assert.NoError(t, err)
	resetTimer()
}

type compressionCircuit struct {
	CChecksum, DChecksum frontend.Variable `gnark:",public"`
	C                    []frontend.Variable
	D                    []frontend.Variable
	CLen, DLen           frontend.Variable
	Settings             Settings
}

func (c *compressionCircuit) Define(api frontend.API) error {

	fmt.Println("packing")
	cPacked := Pack(api, c.C, c.Settings.WordNbBits())
	dPacked := Pack(api, c.D, 8)

	fmt.Println("computing checksum")
	if err := checkSnark(api, cPacked, c.CLen, c.CChecksum); err != nil {
		return err
	}
	if err := checkSnark(api, dPacked, c.DLen, c.DChecksum); err != nil {
		return err
	}

	fmt.Println("decompressing")
	dComputed := make([]frontend.Variable, len(c.D))
	if dComputedLen, err := DecompressGo(api, c.C, dComputed, c.CLen, c.Settings); err != nil {
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

func TestChecksum0(t *testing.T) {
	testChecksum(t, compress.Stream{D: []int{}, NbSymbs: 256})
}

func testChecksum(t *testing.T, d compress.Stream) {
	circuit := checksumTestCircuit{
		Inputs:   make([]frontend.Variable, d.Len()),
		InputLen: d.Len(),
	}

	sum, err := check(d, d.Len())
	assert.NoError(t, err)

	assignment := checksumTestCircuit{
		Inputs:   test_vector_utils.ToVariableSlice(d.D),
		InputLen: d.Len(),
		Sum:      sum,
	}
	test.NewAssert(t).SolvingSucceeded(&circuit, &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type checksumTestCircuit struct {
	Inputs   []frontend.Variable
	InputLen frontend.Variable
	Sum      frontend.Variable
}

func (c *checksumTestCircuit) Define(api frontend.API) error {
	if err := checkSnark(api, c.Inputs, len(c.Inputs), c.Sum); err != nil {
		return err
	}
	return nil
}
