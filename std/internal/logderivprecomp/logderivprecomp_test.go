package logderivprecomp

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/std/internal/logderivarg"
	"github.com/consensys/gnark/test"
)

type TestXORCircuit struct {
	X, Y [100]frontend.Variable
	Res  [100]frontend.Variable
}

func (c *TestXORCircuit) Define(api frontend.API) error {
	tbl, err := New(api, xorHint, []uint{8})
	if err != nil {
		return err
	}
	for i := range c.X {
		res := tbl.Query(c.X[i], c.Y[i])
		api.AssertIsEqual(res[0], c.Res[i])
	}
	return nil
}

func xorHint(_ *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].Xor(inputs[0], inputs[1])
	return nil
}

func TestXor(t *testing.T) {
	assert := test.NewAssert(t)
	bound := big.NewInt(255)
	var xs, ys, ress [100]frontend.Variable
	for i := range xs {
		x, _ := rand.Int(rand.Reader, bound)
		y, _ := rand.Int(rand.Reader, bound)
		ress[i] = new(big.Int).Xor(x, y)
		xs[i] = x
		ys[i] = y
	}
	witness := &TestXORCircuit{X: xs, Y: ys, Res: ress}
	assert.ProverSucceeded(&TestXORCircuit{}, witness,
		test.WithBackends(backend.GROTH16),
		test.WithSolverOpts(solver.WithHints(xorHint)),
		test.NoFuzzing(),
		test.NoSerializationChecks(),
		test.WithCurves(ecc.BN254))
}

// OldXORCircuit uses the original Build function for comparison
type OldXORCircuit struct {
	X, Y []frontend.Variable
}

func (c *OldXORCircuit) Define(api frontend.API) error {
	// Build table manually (old approach)
	tmp := new(big.Int)
	shift := new(big.Int)
	table := make([]frontend.Variable, 65536)
	inputs := []*big.Int{big.NewInt(0), big.NewInt(0)}
	outputs := []*big.Int{new(big.Int)}
	for x := int64(0); x < 256; x++ {
		inputs[0].SetInt64(x)
		for y := int64(0); y < 256; y++ {
			shift.SetInt64(1 << 8)
			i := x | (y << 8)
			inputs[1].SetInt64(y)
			outputs[0].Xor(inputs[0], inputs[1])
			tblval := new(big.Int).SetInt64(i)
			shift.Lsh(shift, 8)
			tblval.Add(tblval, tmp.Mul(outputs[0], shift))
			table[i] = tblval
		}
	}

	// Compute queries (old approach - commit all query values)
	queries := make([]frontend.Variable, len(c.X))
	for i := range c.X {
		rets, err := api.Compiler().NewHint(xorHint, 1, c.X[i], c.Y[i])
		if err != nil {
			return err
		}
		shift := big.NewInt(1 << 8)
		packed := api.Add(c.X[i], api.Mul(c.Y[i], shift))
		shift.Lsh(shift, 8)
		packed = api.Add(packed, api.Mul(rets[0], shift))
		queries[i] = packed
	}

	return logderivarg.Build(api, logderivarg.AsTable(table), logderivarg.AsTable(queries))
}

// NewXORCircuit uses the new LogUp* approach
type NewXORCircuit struct {
	X, Y []frontend.Variable
}

func (c *NewXORCircuit) Define(api frontend.API) error {
	tbl, err := New(api, xorHint, []uint{8})
	if err != nil {
		return err
	}
	for i := range c.X {
		tbl.Query(c.X[i], c.Y[i])
	}
	return nil
}

func TestPrecomputedConstraintComparison(t *testing.T) {
	configs := []struct {
		name       string
		numQueries int
	}{
		{"10 queries", 10},
		{"50 queries", 50},
		{"100 queries", 100},
		{"500 queries", 500},
	}

	fmt.Println("\nLogUp* Constraint Comparison for Precomputed Tables (SCS/PLONK)")
	fmt.Println("================================================================")

	for _, cfg := range configs {
		// Old approach
		oldCircuit := &OldXORCircuit{
			X: make([]frontend.Variable, cfg.numQueries),
			Y: make([]frontend.Variable, cfg.numQueries),
		}
		oldCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, oldCircuit)
		if err != nil {
			t.Fatalf("failed to compile old circuit: %v", err)
		}

		// New approach (LogUp*)
		newCircuit := &NewXORCircuit{
			X: make([]frontend.Variable, cfg.numQueries),
			Y: make([]frontend.Variable, cfg.numQueries),
		}
		newCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, newCircuit)
		if err != nil {
			t.Fatalf("failed to compile new circuit: %v", err)
		}

		oldCount := oldCS.GetNbConstraints()
		newCount := newCS.GetNbConstraints()
		saved := oldCount - newCount
		pct := float64(saved) / float64(oldCount) * 100

		fmt.Printf("\n%s:\n", cfg.name)
		fmt.Printf("  Old (Build):              %d constraints\n", oldCount)
		fmt.Printf("  New (BuildIndexedPrecomp): %d constraints\n", newCount)
		fmt.Printf("  Saved: %d constraints (%.1f%%)\n", saved, pct)
	}
}
