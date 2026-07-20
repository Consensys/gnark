package uintexp

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/uints"
)

// expAddChainCircuit performs a chain of N dependent additions in exponent
// encoding: expected cost N + boundary (≈4k).
type expAddChainCircuit[W Width] struct {
	A, B     frontend.Variable
	Expected frontend.Variable
	N        int
}

func (c *expAddChainCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	acc := f.ValueOf(c.A)
	b := f.ValueOf(c.B)
	for i := 0; i < c.N; i++ {
		acc = f.Add(acc, b)
	}
	api.AssertIsEqual(f.Value(acc), c.Expected)
	return nil
}

// expCounterCircuit increments a counter by a constant N times: expected cost
// is the boundary only, independent of N.
type expCounterCircuit[W Width] struct {
	A        frontend.Variable
	Expected frontend.Variable
	N        int
}

func (c *expCounterCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	acc := f.ValueOf(c.A)
	for i := 0; i < c.N; i++ {
		acc = f.AddConstant(acc, 1)
	}
	api.AssertIsEqual(f.Value(acc), c.Expected)
	return nil
}

// uintsAddChainCircuit is the baseline: the same dependent add chain using
// std/math/uints (U32, its narrowest long type).
type uintsAddChainCircuit struct {
	A, B     frontend.Variable
	Expected frontend.Variable
	N        int
}

func (c *uintsAddChainCircuit) Define(api frontend.API) error {
	uf, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	acc := uf.ValueOf(c.A)
	b := uf.ValueOf(c.B)
	for i := 0; i < c.N; i++ {
		acc = uf.Add(acc, b)
	}
	api.AssertIsEqual(uf.ToValue(acc), c.Expected)
	return nil
}

// partitionAddChainCircuit is a hand-rolled mod-2^16 baseline: native add
// followed by dropping the carry with bitslice.Partition on every step.
type partitionAddChainCircuit struct {
	A, B     frontend.Variable
	Expected frontend.Variable
	N        int
}

func (c *partitionAddChainCircuit) Define(api frontend.API) error {
	acc := c.A
	for i := 0; i < c.N; i++ {
		s := api.Add(acc, c.B)
		lo, _ := bitslice.Partition(api, s, 16, bitslice.WithNbDigits(17))
		acc = lo
	}
	api.AssertIsEqual(acc, c.Expected)
	return nil
}

// TestConstraintCounts regression-guards the headline costs: ~1 constraint
// per dependent add and 0 constraints per constant increment.
func TestConstraintCounts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping constraint count test in short mode")
	}
	const n = 100

	// dependent add chain: N adds + encode/decode boundary
	chain, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, &expAddChainCircuit[U16]{N: n})
	if err != nil {
		t.Fatal(err)
	}
	nbChain := chain.GetNbConstraints()
	t.Logf("u16 exponent add chain, n=%d: %d constraints (%.2f/add + boundary)", n, nbChain, float64(nbChain-4*16)/n)
	if nbChain < n {
		t.Fatalf("suspicious constraint count %d < n", nbChain)
	}
	if nbChain > n+8*16 {
		t.Fatalf("add chain regressed: %d constraints for %d adds (boundary budget 8k)", nbChain, n)
	}

	// constant counter: constraint count must not depend on N
	counter100, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, &expCounterCircuit[U16]{N: 100})
	if err != nil {
		t.Fatal(err)
	}
	counter1000, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, &expCounterCircuit[U16]{N: 1000})
	if err != nil {
		t.Fatal(err)
	}
	nb100, nb1000 := counter100.GetNbConstraints(), counter1000.GetNbConstraints()
	t.Logf("u16 constant counter: n=100 -> %d constraints, n=1000 -> %d constraints", nb100, nb1000)
	if nb100 != nb1000 {
		t.Fatalf("AddConstant is no longer free: %d constraints for n=100 vs %d for n=1000", nb100, nb1000)
	}
}

// BenchmarkAddChainConstraints reports the constraint counts of an n-step
// dependent wrapping-add chain for the exponent encoding vs the limb-based
// baselines, over KoalaBear (R1CS and SCS) and BLS12-377 (R1CS).
//
// Reading the numbers: the uintexp counts are complete -- the encoding uses
// no lookups and no commitments. The uints and partition baselines rely on
// commitment-based range checks/lookup tables (hence the wide-committer shim
// on KoalaBear), whose cost partly lives in committed witness columns and
// prover work that GetNbConstraints does not surface; their constraint
// counts are therefore lower bounds.
func BenchmarkAddChainConstraints(b *testing.B) {
	const n = 1000
	exp := &expAddChainCircuit[U16]{N: n}
	counter := &expCounterCircuit[U16]{N: n}
	limb := &uintsAddChainCircuit{N: n}
	part := &partitionAddChainCircuit{N: n}

	report := func(b *testing.B, name string, nb int) {
		b.ReportMetric(float64(nb), name+"_total")
		b.ReportMetric(float64(nb)/n, name+"_per_add")
	}

	b.Run("koalabear-r1cs", func(b *testing.B) {
		// note: the uintexp circuits compile with the plain builder -- the
		// encoding needs no committer/lookup support. The uints and
		// partition baselines need the wide-committer shim for their lookup
		// tables and range checks.
		cExp, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, exp)
		if err != nil {
			b.Fatal(err)
		}
		cCnt, err := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, counter)
		if err != nil {
			b.Fatal(err)
		}
		cLimb, err := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(r1cs.NewBuilder), limb)
		if err != nil {
			b.Fatal(err)
		}
		cPart, err := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(r1cs.NewBuilder), part)
		if err != nil {
			b.Fatal(err)
		}
		report(b, "exp_u16", cExp.GetNbConstraints())
		report(b, "exp_counter", cCnt.GetNbConstraints())
		report(b, "uints_u32", cLimb.GetNbConstraints())
		report(b, "partition_u16", cPart.GetNbConstraints())
	})

	b.Run("koalabear-scs", func(b *testing.B) {
		cExp, err := frontend.CompileU32(koalabear.Modulus(), scs.NewBuilder, exp)
		if err != nil {
			b.Fatal(err)
		}
		cLimb, err := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(scs.NewBuilder), limb)
		if err != nil {
			b.Fatal(err)
		}
		report(b, "exp_u16", cExp.GetNbConstraints())
		report(b, "uints_u32", cLimb.GetNbConstraints())
	})

	b.Run("bls12377-r1cs", func(b *testing.B) {
		cExp, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, exp)
		if err != nil {
			b.Fatal(err)
		}
		cLimb, err := frontend.Compile(ecc.BLS12_377.ScalarField(), r1cs.NewBuilder, limb)
		if err != nil {
			b.Fatal(err)
		}
		report(b, "exp_u16", cExp.GetNbConstraints())
		report(b, "uints_u32", cLimb.GetNbConstraints())
	})
}
