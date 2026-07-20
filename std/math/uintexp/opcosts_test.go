package uintexp

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/internal/widecommitter"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/bitslice"
	"github.com/consensys/gnark/std/math/uints"
	"github.com/consensys/gnark/std/rangecheck"
)

// expOpCircuit applies the given op in a dependent chain of length N so that
// the marginal cost per op can be read off as a constraint-count difference.
type expOpCircuit[W Width] struct {
	Op       string
	N        int
	A, B     frontend.Variable
	Sel      frontend.Variable
	Expected frontend.Variable
	In       []frontend.Variable
}

// expMulScalar computes [s]a, i.e. the encoding of a*s mod 2^k, by
// square-and-multiply over the encoded value with the bits of the plain
// scalar s. Cost: k booleanity + ~3 constraints per bit (square, bit*base
// select, accumulator multiply).
func expMulScalar[W Width](api frontend.API, f *Field[W], a Uint[W], s frontend.Variable) Uint[W] {
	var w W
	k := w.NbBits()
	bs := bits.ToBinary(api, s, bits.WithNbDigits(k))
	base := f.enforce(a)
	acc := frontend.Variable(1)
	for i := k - 1; i >= 0; i-- {
		acc = api.Mul(acc, acc)
		// select(bs[i], base, 1) = bs[i]*(base-1) + 1: one constraint as base
		// is a variable
		term := api.Add(api.Mul(bs[i], api.Sub(base, 1)), 1)
		acc = api.Mul(acc, term)
	}
	return f.packInternal(acc)
}

func (c *expOpCircuit[W]) Define(api frontend.API) error {
	f, err := New[W](api)
	if err != nil {
		return err
	}
	acc := f.ValueOf(c.A)
	b := f.ValueOf(c.B)
	switch c.Op {
	case "mul":
		for i := 0; i < c.N; i++ {
			acc = expMulScalar(api, f, acc, c.B)
		}
	case "add":
		for i := 0; i < c.N; i++ {
			acc = f.Add(acc, b)
		}
	case "add-constant":
		for i := 0; i < c.N; i++ {
			acc = f.AddConstant(acc, 3)
		}
	case "neg":
		for i := 0; i < c.N; i++ {
			acc = f.Neg(acc)
		}
	case "sub":
		for i := 0; i < c.N; i++ {
			acc = f.Sub(acc, b)
		}
	case "lsh1":
		for i := 0; i < c.N; i++ {
			acc = f.Lsh(acc, 1)
		}
	case "select":
		for i := 0; i < c.N; i++ {
			acc = f.Select(c.Sel, acc, b)
		}
	case "is-zero":
		s := frontend.Variable(0)
		for i := 0; i < c.N; i++ {
			s = api.Add(s, f.IsZero(f.AddConstant(acc, uint64(i))))
		}
		api.AssertIsEqual(api.Mul(s, 0), 0)
	case "encode":
		// encode+add per step; subtract the add cost offline
		for i := 0; i < c.N; i++ {
			acc = f.Add(acc, f.ValueOf(c.In[i]))
		}
	case "decode":
		// AddConstant makes N distinct encodings for free, so the marginal
		// cost is the decode alone
		s := frontend.Variable(0)
		for i := 0; i < c.N; i++ {
			s = api.Add(s, f.Value(f.AddConstant(acc, uint64(i))))
		}
		api.AssertIsEqual(api.Mul(s, 0), 0)
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	api.AssertIsEqual(f.Value(acc), c.Expected)
	return nil
}

// uintsOpCircuit is the equivalent chain using std/math/uints (U32, its
// narrowest long type).
type uintsOpCircuit struct {
	Op       string
	N        int
	A, B     frontend.Variable
	Expected frontend.Variable
	In       []frontend.Variable
}

func (c *uintsOpCircuit) Define(api frontend.API) error {
	uf, err := uints.New[uints.U32](api)
	if err != nil {
		return err
	}
	acc := uf.ValueOf(c.A)
	b := uf.ValueOf(c.B)
	switch c.Op {
	case "add":
		for i := 0; i < c.N; i++ {
			acc = uf.Add(acc, b)
		}
	case "add-constant":
		three := uints.NewU32(3)
		for i := 0; i < c.N; i++ {
			acc = uf.Add(acc, three)
		}
	case "xor":
		for i := 0; i < c.N; i++ {
			acc = uf.Xor(acc, b)
		}
	case "and":
		for i := 0; i < c.N; i++ {
			acc = uf.And(acc, b)
		}
	case "rshift1":
		for i := 0; i < c.N; i++ {
			acc = uf.Rshift(acc, 1)
		}
	case "lrot3":
		for i := 0; i < c.N; i++ {
			acc = uf.Lrot(acc, 3)
		}
	case "encode":
		for i := 0; i < c.N; i++ {
			acc = uf.Add(acc, uf.ValueOf(c.In[i]))
		}
	case "decode":
		s := frontend.Variable(0)
		for i := 0; i < c.N; i++ {
			acc = uf.Add(acc, b) // make a fresh value; add cost subtracted offline
			s = api.Add(s, uf.ToValue(acc))
		}
		api.AssertIsEqual(api.Mul(s, 0), 0)
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	api.AssertIsEqual(uf.ToValue(acc), c.Expected)
	return nil
}

// limbOpCircuit is the width-matched limb baseline: values live as plain
// range-checked variables of the SAME width k as the exponent encoding, with
// carries dropped via bitslice.Partition (the approach uints takes bytewise,
// specialized to u8/u16). XOR keeps values in byte form and uses the uints
// byte lookup tables.
type limbOpCircuit struct {
	K        int // 8 or 16
	Op       string
	N        int
	A, B     frontend.Variable
	Sel      frontend.Variable
	Expected frontend.Variable
	In       []frontend.Variable
}

func (c *limbOpCircuit) Define(api frontend.API) error {
	k := uint(c.K)
	mod := frontend.Variable(1 << k)
	acc := c.A
	wrap := func(v frontend.Variable, nbDigits int) frontend.Variable {
		lo, _ := bitslice.Partition(api, v, k, bitslice.WithNbDigits(nbDigits))
		return lo
	}
	switch c.Op {
	case "mul":
		// acc = acc*B mod 2^k. For k=8 the 16-bit product fits any supported
		// field; for k=16 the 32-bit product may overflow a small field, so
		// split the multiplier into bytes (24-bit partials).
		for i := 0; i < c.N; i++ {
			if c.K == 8 {
				acc = wrap(api.Mul(acc, c.B), 16)
			} else {
				b0, b1 := bitslice.Partition(api, c.B, 8, bitslice.WithNbDigits(c.K))
				t := api.Add(api.Mul(acc, b0), api.Mul(api.Mul(acc, b1), 1<<8))
				acc = wrap(t, c.K+9)
			}
		}
	case "add":
		for i := 0; i < c.N; i++ {
			acc = wrap(api.Add(acc, c.B), c.K+1)
		}
	case "add-constant":
		for i := 0; i < c.N; i++ {
			acc = wrap(api.Add(acc, 3), c.K+1)
		}
	case "neg":
		for i := 0; i < c.N; i++ {
			acc = wrap(api.Sub(mod, acc), c.K+1)
		}
	case "sub":
		for i := 0; i < c.N; i++ {
			acc = wrap(api.Add(acc, api.Sub(mod, c.B)), c.K+1)
		}
	case "rshift1":
		for i := 0; i < c.N; i++ {
			_, hi := bitslice.Partition(api, acc, 1, bitslice.WithNbDigits(c.K))
			acc = hi
		}
	case "select":
		for i := 0; i < c.N; i++ {
			acc = api.Select(c.Sel, acc, c.B)
		}
	case "is-zero":
		s := frontend.Variable(0)
		for i := 0; i < c.N; i++ {
			s = api.Add(s, api.IsZero(api.Sub(acc, i)))
		}
		api.AssertIsEqual(api.Mul(s, 0), 0)
	case "xor":
		// byte-resident xor via the uints lookup tables
		bts, err := uints.NewBytes(api)
		if err != nil {
			return err
		}
		nbBytes := c.K / 8
		accB := make([]uints.U8, nbBytes)
		bB := make([]uints.U8, nbBytes)
		rest := acc
		restB := c.B
		for j := 0; j < nbBytes; j++ {
			var lo frontend.Variable
			lo, rest = bitslice.Partition(api, rest, 8, bitslice.WithNbDigits(c.K-8*j))
			accB[j] = bts.ValueOf(lo)
			lo, restB = bitslice.Partition(api, restB, 8, bitslice.WithNbDigits(c.K-8*j))
			bB[j] = bts.ValueOf(lo)
		}
		for i := 0; i < c.N; i++ {
			for j := 0; j < nbBytes; j++ {
				accB[j] = bts.Xor(accB[j], bB[j])
			}
		}
		s := frontend.Variable(0)
		for j := 0; j < nbBytes; j++ {
			s = api.Add(s, api.Mul(bts.Value(accB[j]), 1<<(8*j)))
		}
		acc = s
	case "encode":
		// "encoding" in limb-land is the range check on ingress
		rc := rangecheck.New(api)
		s := frontend.Variable(0)
		for i := 0; i < c.N; i++ {
			rc.Check(c.In[i], c.K)
			s = api.Add(s, c.In[i])
		}
		api.AssertIsEqual(api.Mul(s, 0), 0)
	case "decode":
		// the plain variable is already the value
	default:
		return fmt.Errorf("unknown op %q", c.Op)
	}
	api.AssertIsEqual(api.Mul(acc, 0), api.Mul(c.Expected, 0))
	return nil
}

// TestOpCosts prints the marginal per-op constraint cost of uintexp (u8) and
// uints (U32) over KoalaBear for both builders. The marginal cost is measured
// as (C(2N)-C(N))/N, which cancels boundary and table-setup costs.
//
// NB: the uints numbers on KoalaBear are lower bounds -- its lookup-based ops
// need the wide-committer shim and part of their cost lives in committed
// witness columns not counted by GetNbConstraints.
func TestOpCosts(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping op cost report in short mode")
	}
	const n = 32

	compileExpW := func(builder string, c frontend.Circuit, op string) int {
		switch builder {
		case "r1cs":
			cc, e := frontend.CompileU32(koalabear.Modulus(), r1cs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		case "scs":
			cc, e := frontend.CompileU32(koalabear.Modulus(), scs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		}
		return 0
	}
	compileExp := func(builder string, op string, nOps int) int {
		return compileExpW(builder, &expOpCircuit[U8]{Op: op, N: nOps, In: make([]frontend.Variable, nOps)}, op)
	}
	compileExp16 := func(builder string, op string, nOps int) int {
		return compileExpW(builder, &expOpCircuit[U16]{Op: op, N: nOps, In: make([]frontend.Variable, nOps)}, op)
	}
	compileLimb := func(k int) func(builder string, op string, nOps int) int {
		return func(builder string, op string, nOps int) int {
			c := &limbOpCircuit{K: k, Op: op, N: nOps, In: make([]frontend.Variable, nOps)}
			switch builder {
			case "r1cs":
				cc, e := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(r1cs.NewBuilder), c)
				if e != nil {
					t.Fatal(op, e)
				}
				return cc.GetNbConstraints()
			case "scs":
				cc, e := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(scs.NewBuilder), c)
				if e != nil {
					t.Fatal(op, e)
				}
				return cc.GetNbConstraints()
			}
			return 0
		}
	}
	compileLimb8, compileLimb16 := compileLimb(8), compileLimb(16)
	compileUints := func(builder string, op string, nOps int) int {
		c := &uintsOpCircuit{Op: op, N: nOps, In: make([]frontend.Variable, nOps)}
		switch builder {
		case "r1cs":
			cc, e := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(r1cs.NewBuilder), c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		case "scs":
			cc, e := frontend.CompileU32(koalabear.Modulus(), widecommitter.From(scs.NewBuilder), c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		}
		return 0
	}

	marginal := func(compile func(string, string, int) int, builder, op string) float64 {
		c1 := compile(builder, op, n)
		c2 := compile(builder, op, 2*n)
		return float64(c2-c1) / n
	}

	compileExpBN254 := func(builder string, op string, nOps int) int {
		c := &expOpCircuit[U8]{Op: op, N: nOps, In: make([]frontend.Variable, nOps)}
		switch builder {
		case "r1cs":
			cc, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		case "scs":
			cc, e := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		}
		return 0
	}
	compileLimbBN254 := func(builder string, op string, nOps int) int {
		c := &limbOpCircuit{K: 8, Op: op, N: nOps, In: make([]frontend.Variable, nOps)}
		switch builder {
		case "r1cs":
			cc, e := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		case "scs":
			cc, e := frontend.Compile(ecc.BN254.ScalarField(), scs.NewBuilder, c)
			if e != nil {
				t.Fatal(op, e)
			}
			return cc.GetNbConstraints()
		}
		return 0
	}

	expOps := []string{"add", "add-constant", "mul", "neg", "sub", "lsh1", "select", "is-zero", "encode", "decode"}
	uintsOps := []string{"add", "add-constant", "xor", "and", "rshift1", "lrot3", "encode", "decode"}

	for _, builder := range []string{"r1cs", "scs"} {
		t.Logf("=== bn254 / %s ===", builder)
		expAdd := marginal(compileExpBN254, builder, "add")
		t.Logf("%-14s %10s", "op", "exp u8")
		for _, op := range expOps {
			m := marginal(compileExpBN254, builder, op)
			note := ""
			if op == "encode" {
				m -= expAdd
				note = " (add cost subtracted)"
			}
			t.Logf("%-14s %10.2f%s", op, m, note)
		}
		t.Logf("%-14s %10s", "op", "limb u8 (width-matched)")
		for _, op := range []string{"add", "add-constant", "mul", "neg", "sub", "rshift1", "select", "is-zero", "xor", "encode", "decode"} {
			t.Logf("%-14s %10.2f", op, marginal(compileLimbBN254, builder, op))
		}
	}

	for _, builder := range []string{"r1cs", "scs"} {
		t.Logf("=== koalabear / %s ===", builder)
		t.Logf("%-14s %10s", "op", "uintexp u8")
		expAdd := marginal(compileExp, builder, "add")
		expAdd16 := marginal(compileExp16, builder, "add")
		for _, op := range expOps {
			m := marginal(compileExp, builder, op)
			m16 := marginal(compileExp16, builder, op)
			note := ""
			if op == "encode" {
				m -= expAdd
				m16 -= expAdd16
				note = " (add cost subtracted)"
			}
			t.Logf("%-14s %10.2f (u8) %10.2f (u16)%s", op, m, m16, note)
		}
		t.Logf("%-14s %10s", "op", "limb u8/u16 (width-matched old method)")
		limbOps := []string{"add", "add-constant", "mul", "neg", "sub", "rshift1", "select", "is-zero", "xor", "encode", "decode"}
		for _, op := range limbOps {
			m8 := marginal(compileLimb8, builder, op)
			m16 := marginal(compileLimb16, builder, op)
			t.Logf("%-14s %10.2f (u8) %10.2f (u16)", op, m8, m16)
		}
		t.Logf("%-14s %10s", "op", "uints U32")
		uAdd := marginal(compileUints, builder, "add")
		for _, op := range uintsOps {
			m := marginal(compileUints, builder, op)
			note := ""
			if op == "encode" || op == "decode" {
				m -= uAdd
				note = " (add cost subtracted)"
			}
			t.Logf("%-14s %10.2f%s", op, m, note)
		}
	}
}
