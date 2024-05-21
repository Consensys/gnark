package selector

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
	"testing"
)

type binaryMuxCircuit struct {
	Sel [4]frontend.Variable
	In  [10]frontend.Variable
	Out frontend.Variable
}

func (c *binaryMuxCircuit) Define(api frontend.API) error {

	out := binaryMuxRecursive(api, c.Sel[:], c.In[:])

	api.AssertIsEqual(out, c.Out)

	return nil
}

type binary7to1MuxCircuit struct {
	Sel [3]frontend.Variable
	In  [7]frontend.Variable
	Out frontend.Variable
}

func (c *binary7to1MuxCircuit) Define(api frontend.API) error {

	out := binaryMuxRecursive(api, c.Sel[:], c.In[:])

	api.AssertIsEqual(out, c.Out)

	return nil
}

func Test_binaryMuxRecursive(t *testing.T) {
	assert := test.NewAssert(t)

	assert.ProverSucceeded(&binaryMuxCircuit{}, &binaryMuxCircuit{
		Sel: [4]frontend.Variable{0, 0, 1, 0},
		In:  [10]frontend.Variable{100, 111, 122, 133, 144, 155, 166, 177, 188, 199},
		Out: 144,
	})

	assert.ProverSucceeded(&binaryMuxCircuit{}, &binaryMuxCircuit{
		Sel: [4]frontend.Variable{0, 0, 0, 0},
		In:  [10]frontend.Variable{100, 111, 122, 133, 144, 155, 166, 177, 188, 199},
		Out: 100,
	})

	assert.ProverSucceeded(&binaryMuxCircuit{}, &binaryMuxCircuit{
		Sel: [4]frontend.Variable{1, 0, 0, 1},
		In:  [10]frontend.Variable{100, 111, 122, 133, 144, 155, 166, 177, 188, 199},
		Out: 199,
	})

	assert.ProverSucceeded(&binaryMuxCircuit{}, &binaryMuxCircuit{
		Sel: [4]frontend.Variable{0, 1, 0, 0},
		In:  [10]frontend.Variable{100, 111, 122, 133, 144, 155, 166, 177, 188, 199},
		Out: 122,
	})

	assert.ProverSucceeded(&binaryMuxCircuit{}, &binaryMuxCircuit{
		Sel: [4]frontend.Variable{0, 0, 0, 1},
		In:  [10]frontend.Variable{100, 111, 122, 133, 144, 155, 166, 177, 188, 199},
		Out: 188,
	})

	// 7 to 1
	assert.ProverSucceeded(&binary7to1MuxCircuit{}, &binary7to1MuxCircuit{
		Sel: [3]frontend.Variable{0, 0, 1},
		In:  [7]frontend.Variable{5, 3, 10, 6, 0, 9, 1},
		Out: 0,
	})

	assert.ProverSucceeded(&binary7to1MuxCircuit{}, &binary7to1MuxCircuit{
		Sel: [3]frontend.Variable{0, 1, 1},
		In:  [7]frontend.Variable{5, 3, 10, 6, 0, 9, 1},
		Out: 1,
	})

	assert.ProverSucceeded(&binary7to1MuxCircuit{}, &binary7to1MuxCircuit{
		Sel: [3]frontend.Variable{0, 0, 0},
		In:  [7]frontend.Variable{5, 3, 10, 6, 0, 9, 1},
		Out: 5,
	})

	assert.ProverSucceeded(&binary7to1MuxCircuit{}, &binary7to1MuxCircuit{
		Sel: [3]frontend.Variable{1, 0, 1},
		In:  [7]frontend.Variable{5, 3, 10, 6, 0, 9, 1},
		Out: 9,
	})
}
