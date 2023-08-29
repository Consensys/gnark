package compress

/*
func TestCandidatesCompressionRate(t *testing.T) {
	zct, err := os.ReadFile(TestCase + "data.zct")
	require.NoError(t, err)

	var candidates [][]byte
	{
		candidatesHex, err := os.ReadFile(TestCase + "candidates.hex")
		require.NoError(t, err)
		candidatesHexSlice := strings.Split(string(candidatesHex), "\n")
		candidates = make([][]byte, len(candidatesHexSlice))
		for i, c := range candidatesHexSlice {
			candidates[i], err = hex.DecodeString(c)
			require.NoError(t, err)
		}
	}

	var out bytes.Buffer
	assert.Less(t, len(candidates), 256)
	out.WriteByte(byte(len(candidates)))
	for i := range candidates {
		out.WriteByte(byte(len(candidates[i])))
		out.Write(candidates[i])
	}

}

func compressWithCandidates()
*/
