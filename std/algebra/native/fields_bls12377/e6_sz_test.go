package fields_bls12377

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs"
	"github.com/consensys/gnark/frontend/cs/scs"
)

func randomE6() bls12377.E6 {
	var e bls12377.E6
	e.SetRandom()
	return e
}

// --- E6.Mul SZ correctness ---

type e6MulSZCircuit struct{ A, B, C E6 }

func (c *e6MulSZCircuit) Define(api frontend.API) error {
	var r E6
	r.Mul(api, c.A, c.B)
	r.AssertIsEqual(api, c.C)
	return nil
}

func TestE6MulSZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a, b := randomE6(), randomE6()
	var c bls12377.E6
	c.Mul(&a, &b)

	circuit := &e6MulSZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e6MulSZCircuit{}
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)
	w, _ := frontend.NewWitness(witness, field)
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("E6.Mul SZ solve failed: %v", err)
	}

	// wrong result
	var cWrong bls12377.E6
	cWrong.SetRandom()
	bad := &e6MulSZCircuit{}
	bad.A.Assign(&a)
	bad.B.Assign(&b)
	bad.C.Assign(&cWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("E6.Mul SZ should reject wrong result")
	}
}

func corruptHintOutput(h solver.Hint, output int) solver.Hint {
	return func(field *big.Int, inputs, outputs []*big.Int) error {
		if err := h(field, inputs, outputs); err != nil {
			return err
		}
		outputs[output].Add(outputs[output], big.NewInt(1))
		return nil
	}
}

func zeroHintOutput(_ *big.Int, _ []*big.Int, outputs []*big.Int) error {
	for i := range outputs {
		outputs[i].SetUint64(0)
	}
	return nil
}

func commitmentInputCountHint(field *big.Int, inputs, outputs []*big.Int) error {
	outputs[0].SetInt64(int64(len(inputs)))
	outputs[0].Mod(outputs[0], field)
	return nil
}

func negBLS12377Base(v int64) *big.Int {
	res := big.NewInt(v)
	res.Neg(res)
	res.Mod(res, bls12377.ID.BaseField())
	return res
}

func TestE6MulSZRejectsCorruptedQuotientHint(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a, b := randomE6(), randomE6()
	var c bls12377.E6
	c.Mul(&a, &b)

	circuit := &e6MulSZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e6MulSZCircuit{}
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatal(err)
	}

	err = ccs.IsSolved(w, solver.OverrideHint(
		solver.GetHintID(mulE6SZHint),
		corruptHintOutput(mulE6SZHint, 6),
	))
	if err == nil {
		t.Fatal("E6.Mul SZ should reject a corrupted quotient hint")
	}
}

func TestE6MulSZRejectsForgedInputsWhenCommitted(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	circuit := &e6MulSZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	// Before committing a and b, the commitment hint sees depth + c + q:
	// 1 + 6 + 5 inputs. The forged a(X)=X-r, b(X)=1, c=q=0 would pass.
	const oldChallenge = 12
	var a, b, c bls12377.E6
	a.B0.A0.SetBigInt(negBLS12377Base(oldChallenge))
	a.B1.A0.SetOne()
	b.SetOne()

	witness := &e6MulSZCircuit{}
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatal(err)
	}

	err = ccs.IsSolved(w,
		solver.OverrideHint(solver.GetHintID(mulE6SZHint), zeroHintOutput),
		solver.OverrideHint(solver.GetHintID(cs.Bsb22CommitmentComputePlaceholder), commitmentInputCountHint),
	)
	if err == nil {
		t.Fatal("E6.Mul SZ should bind the challenge to multiplication inputs")
	}
}

// --- E6.Square SZ correctness ---

type e6SquareSZCircuit struct{ A, C E6 }

func (c *e6SquareSZCircuit) Define(api frontend.API) error {
	var r E6
	r.Square(api, c.A)
	r.AssertIsEqual(api, c.C)
	return nil
}

func TestE6SquareSZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a := randomE6()
	var c bls12377.E6
	c.Square(&a)

	circuit := &e6SquareSZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e6SquareSZCircuit{}
	witness.A.Assign(&a)
	witness.C.Assign(&c)
	w, _ := frontend.NewWitness(witness, field)
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("E6.Square SZ solve failed: %v", err)
	}

	var cWrong bls12377.E6
	cWrong.SetRandom()
	bad := &e6SquareSZCircuit{}
	bad.A.Assign(&a)
	bad.C.Assign(&cWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("E6.Square SZ should reject wrong result")
	}
}

// --- E6.MulBy01 SZ correctness ---

type e6MulBy01SZCircuit struct {
	A      E6
	C0, C1 E2
	Res    E6
}

func (c *e6MulBy01SZCircuit) Define(api frontend.API) error {
	r := c.A
	r.MulBy01(api, c.C0, c.C1)
	r.AssertIsEqual(api, c.Res)
	return nil
}

func TestE6MulBy01SZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a := randomE6()
	var c0, c1 bls12377.E2
	c0.SetRandom()
	c1.SetRandom()

	// compute expected result natively
	var sparse bls12377.E6
	sparse.B0 = c0
	sparse.B1 = c1
	var res bls12377.E6
	res.Mul(&a, &sparse)

	circuit := &e6MulBy01SZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e6MulBy01SZCircuit{}
	witness.A.Assign(&a)
	witness.C0.Assign(&c0)
	witness.C1.Assign(&c1)
	witness.Res.Assign(&res)
	w, _ := frontend.NewWitness(witness, field)
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("E6.MulBy01 SZ solve failed: %v", err)
	}

	var resWrong bls12377.E6
	resWrong.SetRandom()
	bad := &e6MulBy01SZCircuit{}
	bad.A.Assign(&a)
	bad.C0.Assign(&c0)
	bad.C1.Assign(&c1)
	bad.Res.Assign(&resWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("E6.MulBy01 SZ should reject wrong result")
	}
}

// --- E6 SZ constraint counts ---

func TestE6SZConstraintCount(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	t.Log("=== E6 SCS Constraint Counts (Schwartz-Zippel) ===")

	for _, tc := range []struct {
		name    string
		circuit frontend.Circuit
	}{
		{"E6.Mul", &e6MulSZCircuit{}},
		{"E6.Square", &e6SquareSZCircuit{}},
		{"E6.MulBy01", &e6MulBy01SZCircuit{}},
	} {
		ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, tc.circuit)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		t.Logf("  %-20s %d SCS", tc.name, ccs.GetNbConstraints())
	}
}
