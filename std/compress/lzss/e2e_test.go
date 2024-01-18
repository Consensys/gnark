package lzss

/* TODO Get test data for packing and the checksum from the zkevm monorepo
func TestCompression1ZeroE2E(t *testing.T) {
	testCompressionE2E(t, []byte{0}, nil, "1_zero")
}*/
/*
func BenchmarkCompression26KBE2E(b *testing.B) {
	_, err := BenchCompressionE2ECompilation(nil, "./testdata/3c2943")
	assert.NoError(b, err)
}

func testCompressionE2E(t *testing.T, d, dict []byte, name string) {
	if d == nil {
		var err error
		d, err = os.ReadFile("./testdata/" + name + "/data.bin")
		assert.NoError(t, err)
	}

	// compress

	level := lzss.GoodCompression
	compressor, err := lzss.NewCompressor(dict, level)
	assert.NoError(t, err)

	c, err := compressor.Compress(d)
	assert.NoError(t, err)

	cStream, err := goCompress.NewStream(c, uint8(level))
	assert.NoError(t, err)

	cSum, err := check(cStream, cStream.Len())
	assert.NoError(t, err)

	dStream, err := goCompress.NewStream(d, 8)
	assert.NoError(t, err)

	dSum, err := check(dStream, len(d))
	assert.NoError(t, err)

	dict = lzss.AugmentDict(dict)

	dictStream, err := goCompress.NewStream(dict, 8)
	assert.NoError(t, err)

	dictSum, err := check(dictStream, len(dict))
	assert.NoError(t, err)

	circuit := TestCompressionCircuit{
		C:     make([]frontend.Variable, cStream.Len()),
		D:     make([]frontend.Variable, len(d)),
		Dict:  make([]frontend.Variable, len(dict)),
		Level: level,
	}

	// solve the circuit or only compile it

	assignment := TestCompressionCircuit{
		CChecksum:    cSum,
		DChecksum:    dSum,
		DictChecksum: dictSum,
		C:            test_vector_utils.ToVariableSlice(cStream.D),
		D:            test_vector_utils.ToVariableSlice(d),
		Dict:         test_vector_utils.ToVariableSlice(dict),
		CLen:         cStream.Len(),
		DLen:         len(d),
	}
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

func TestChecksum0(t *testing.T) {
	testChecksum(t, goCompress.Stream{D: []int{}, NbSymbs: 256})
}

func testChecksum(t *testing.T, d goCompress.Stream) {
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
	test.NewAssert(t).CheckCircuit(&circuit, test.WithValidAssignment(&assignment), test.WithBackends(backend.PLONK), test.WithCurves(ecc.BLS12_377))
}

type checksumTestCircuit struct {
	Inputs   []frontend.Variable
	InputLen frontend.Variable
	Sum      frontend.Variable
}

func (c *checksumTestCircuit) Define(api frontend.API) error {
	if err := compress.AssertChecksumEquals(api, c.Inputs, len(c.Inputs), c.Sum); err != nil {
		return err
	}
	return nil
}
*/
