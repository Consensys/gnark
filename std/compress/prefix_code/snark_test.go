package prefix_code

import (
	"encoding/csv"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"
	"github.com/consensys/gnark/test"
	"github.com/stretchr/testify/require"
	"os"
	"strconv"
	"testing"
)

func TestDecodeOneOne(t *testing.T) {
	assignment := huffmanTestCircuit{
		lengths:    []int{1},
		Bits:       []frontend.Variable{0},
		Symbols:    []frontend.Variable{0},
		BitsLen:    1,
		SymbolsLen: 1,
	}
	test.NewAssert(t).SolvingSucceeded(assignment.hollow(), &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func TestDecodeTwoOnes(t *testing.T) {
	assignment := huffmanTestCircuit{
		lengths:    []int{1},
		Bits:       []frontend.Variable{0, 0},
		Symbols:    []frontend.Variable{0, 0},
		BitsLen:    2,
		SymbolsLen: 2,
	}
	test.NewAssert(t).SolvingSucceeded(assignment.hollow(), &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

func BenchmarkDecodeBlob(b *testing.B) {
	// from current data, expand 114KB into 125KB
	csvfile, err := os.Open("sample-code.csv")
	require.NoError(b, err)
	csvRecs, err := csv.NewReader(csvfile).ReadAll()
	require.NoError(b, err)

	circuit := huffmanTestCircuit{
		lengths: getIntColumn(csvRecs, 1),
		Bits:    make([]frontend.Variable, 114*1024*8),
		Symbols: make([]frontend.Variable, 125*1024),
	}
	_ = circuit
	p := profile.Start()
	cs, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, &circuit)
	p.Stop()
	require.NoError(b, err)
	fmt.Println(cs.GetNbConstraints(), "constraints")
}

func TestDecodeTwoSymbs(t *testing.T) {
	assignment := huffmanTestCircuit{
		lengths:    []int{1, 2},
		Bits:       []frontend.Variable{0, 1, 0},
		Symbols:    []frontend.Variable{0, 1},
		BitsLen:    3,
		SymbolsLen: 2,
	}
	test.NewAssert(t).SolvingSucceeded(assignment.hollow(), &assignment, test.WithBackends(backend.PLONK), test.WithCurves(ecc.BN254))
}

type huffmanTestCircuit struct {
	lengths             []int
	Bits, Symbols       []frontend.Variable
	BitsLen, SymbolsLen frontend.Variable
}

func (c *huffmanTestCircuit) hollow() frontend.Circuit {
	return &huffmanTestCircuit{
		lengths: c.lengths,
		Bits:    make([]frontend.Variable, len(c.Bits)),
		Symbols: make([]frontend.Variable, len(c.Symbols)),
	}
}

func (c *huffmanTestCircuit) Define(api frontend.API) error {
	symbols := make([]frontend.Variable, len(c.Symbols))
	l, err := Decode(api, c.Bits, c.BitsLen, c.lengths, symbols)
	if err != nil {
		return err
	}
	api.AssertIsEqual(l, c.SymbolsLen)
	assert := frontend.Variable(1)
	for i := range symbols {
		assert = api.MulAcc(assert, api.Neg(assert), api.IsZero(api.Sub(l, i)))
		api.AssertIsEqual(api.Mul(api.Sub(symbols[i], c.Symbols[i]), assert), 0)
	}
	return nil
}

func getIntColumn(csvRecs [][]string, i int) []int {
	res := make([]int, len(csvRecs)-1)
	var err error
	for j := 1; j < len(csvRecs); j++ {
		if res[j-1], err = strconv.Atoi(csvRecs[j][i]); err != nil {
			panic(err)
		}
	}
	return res
}
