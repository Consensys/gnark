package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
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

	fmt.Println("=== E6 SCS Constraint Counts (Schwartz-Zippel) ===")

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
		fmt.Printf("  %-20s %d SCS\n", tc.name, ccs.GetNbConstraints())
	}
}
