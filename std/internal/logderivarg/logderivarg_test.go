package logderivarg

import (
	"fmt"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test"
)

// IndexedConstantCircuit tests BuildIndexedConstant with a small table
type IndexedConstantCircuit struct {
	Indices   []frontend.Variable
	TableSize int
}

func (c *IndexedConstantCircuit) Define(api frontend.API) error {
	return BuildIndexedConstant(api, c.TableSize, c.Indices)
}

func TestBuildIndexedConstantBasic(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with table size 8 and various indices
	tableSize := 8
	indices := []frontend.Variable{0, 1, 2, 3, 4, 5, 6, 7}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254), test.WithoutSmallfieldCheck())
}

func TestBuildIndexedConstantRepeatedIndices(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with repeated indices (common in range checks)
	tableSize := 8
	indices := []frontend.Variable{0, 0, 1, 1, 2, 2, 3, 3, 7, 7, 7}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254), test.WithoutSmallfieldCheck())
}

func TestBuildIndexedConstantSingleIndex(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with a single index
	tableSize := 16
	indices := []frontend.Variable{5}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254), test.WithoutSmallfieldCheck())
}

func TestBuildIndexedConstantLargeTable(t *testing.T) {
	assert := test.NewAssert(t)

	// Test with a larger table (2^8 = 256 entries)
	tableSize := 256
	indices := make([]frontend.Variable, 100)
	for i := range indices {
		indices[i] = i % tableSize
	}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254), test.WithoutSmallfieldCheck())
}

func TestBuildIndexedConstantAllSameIndex(t *testing.T) {
	assert := test.NewAssert(t)

	// Test where all indices are the same
	tableSize := 8
	indices := make([]frontend.Variable, 10)
	for i := range indices {
		indices[i] = 3
	}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithCurves(ecc.BN254), test.WithoutSmallfieldCheck())
}

// Test invalid assignment - index out of bounds
type IndexedConstantInvalidCircuit struct {
	Index     frontend.Variable
	TableSize int
}

func (c *IndexedConstantInvalidCircuit) Define(api frontend.API) error {
	return BuildIndexedConstant(api, c.TableSize, []frontend.Variable{c.Index})
}

func TestBuildIndexedConstantInvalidIndex(t *testing.T) {
	assert := test.NewAssert(t)

	tableSize := 8
	// Valid witness
	validWitness := &IndexedConstantInvalidCircuit{
		Index:     5,
		TableSize: tableSize,
	}
	// Invalid witness - index out of bounds
	invalidWitness := &IndexedConstantInvalidCircuit{
		Index:     10, // out of bounds for table size 8
		TableSize: tableSize,
	}

	circuit := &IndexedConstantInvalidCircuit{
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit,
		test.WithValidAssignment(validWitness),
		test.WithInvalidAssignment(invalidWitness),
		test.WithCurves(ecc.BN254),
		test.WithoutSmallfieldCheck())
}

// Test small field support
func TestBuildIndexedConstantSmallField(t *testing.T) {
	assert := test.NewAssert(t)

	tableSize := 8
	indices := []frontend.Variable{0, 1, 2, 3, 4, 5, 6, 7, 0, 1}

	circuit := &IndexedConstantCircuit{
		Indices:   make([]frontend.Variable, len(indices)),
		TableSize: tableSize,
	}
	witness := &IndexedConstantCircuit{
		Indices:   indices,
		TableSize: tableSize,
	}

	assert.CheckCircuit(circuit, test.WithValidAssignment(witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

// Test hint function directly
func TestCountIndexedHint(t *testing.T) {
	tests := []struct {
		name       string
		tableSize  int
		indices    []int64
		wantCounts []int64
		wantErr    bool
	}{
		{
			name:       "basic",
			tableSize:  4,
			indices:    []int64{0, 1, 2, 3},
			wantCounts: []int64{1, 1, 1, 1},
		},
		{
			name:       "repeated",
			tableSize:  4,
			indices:    []int64{0, 0, 1, 1, 1},
			wantCounts: []int64{2, 3, 0, 0},
		},
		{
			name:       "empty indices",
			tableSize:  4,
			indices:    []int64{},
			wantCounts: []int64{0, 0, 0, 0},
		},
		{
			name:      "out of bounds",
			tableSize: 4,
			indices:   []int64{5},
			wantErr:   true,
		},
		{
			name:      "negative index",
			tableSize: 4,
			indices:   []int64{-1},
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			inputs := make([]*big.Int, 1+len(tt.indices))
			inputs[0] = big.NewInt(int64(tt.tableSize))
			for i, idx := range tt.indices {
				inputs[1+i] = big.NewInt(idx)
			}

			outputs := make([]*big.Int, tt.tableSize)
			for i := range outputs {
				outputs[i] = new(big.Int)
			}

			err := countIndexedHint(nil, inputs, outputs)

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			for i, want := range tt.wantCounts {
				if outputs[i].Int64() != want {
					t.Errorf("output[%d] = %d, want %d", i, outputs[i].Int64(), want)
				}
			}
		})
	}
}

// OldApproachCircuit uses the original Build function for comparison
type OldApproachCircuit struct {
	Indices   []frontend.Variable
	TableSize int
}

func (c *OldApproachCircuit) Define(api frontend.API) error {
	// Build table [0, 1, 2, ..., n-1]
	table := make([]frontend.Variable, c.TableSize)
	for i := 0; i < c.TableSize; i++ {
		table[i] = i
	}
	return Build(api, AsTable(table), AsTable(c.Indices))
}

// TestConstraintComparison compares constraint counts between old and new approaches
func TestConstraintComparison(t *testing.T) {
	configs := []struct {
		name      string
		tableSize int
		numLimbs  int
	}{
		{"Small (8 entries, 10 limbs)", 8, 10},
		{"Medium (256 entries, 50 limbs)", 256, 50},
		{"Large (2^10 entries, 100 limbs)", 1 << 10, 100},
		{"Typical RC (2^16 entries, 16 limbs)", 1 << 16, 16},
	}

	fmt.Println("\nLogUp* Constraint Comparison (SCS/PLONK)")
	fmt.Println("========================================")

	for _, cfg := range configs {
		// Old approach
		oldCircuit := &OldApproachCircuit{
			Indices:   make([]frontend.Variable, cfg.numLimbs),
			TableSize: cfg.tableSize,
		}
		oldCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, oldCircuit)
		if err != nil {
			t.Fatalf("failed to compile old circuit: %v", err)
		}

		// New approach
		newCircuit := &IndexedConstantCircuit{
			Indices:   make([]frontend.Variable, cfg.numLimbs),
			TableSize: cfg.tableSize,
		}
		newCS, err := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, newCircuit)
		if err != nil {
			t.Fatalf("failed to compile new circuit: %v", err)
		}

		oldCount := oldCS.GetNbConstraints()
		newCount := newCS.GetNbConstraints()
		saved := oldCount - newCount
		pct := float64(saved) / float64(oldCount) * 100

		oldVars := oldCS.GetNbInternalVariables()
		newVars := newCS.GetNbInternalVariables()
		savedVars := oldVars - newVars

		fmt.Printf("\n%s:\n", cfg.name)
		fmt.Printf("  Table size: %d, Limbs: %d\n", cfg.tableSize, cfg.numLimbs)
		fmt.Printf("  Old (Build):              %d constraints, %d internal vars\n", oldCount, oldVars)
		fmt.Printf("  New (BuildIndexedConstant): %d constraints, %d internal vars\n", newCount, newVars)
		fmt.Printf("  Saved: %d constraints (%.1f%%), %d internal vars\n", saved, pct, savedVars)
	}
}
