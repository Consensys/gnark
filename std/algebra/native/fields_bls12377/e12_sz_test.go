package fields_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	bls12377 "github.com/consensys/gnark-crypto/ecc/bls12-377"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/scs"
)

type e12MulNCircuit struct {
	N    int
	A, B []E12
	C    []E12
}

func (c *e12MulNCircuit) Define(api frontend.API) error {
	for i := 0; i < c.N; i++ {
		var r E12
		r.Mul(api, c.A[i], c.B[i])
		r.AssertIsEqual(api, c.C[i])
	}
	return nil
}

func newE12MulNCircuit(n int) *e12MulNCircuit {
	return &e12MulNCircuit{N: n, A: make([]E12, n), B: make([]E12, n), C: make([]E12, n)}
}

func randomE12() bls12377.E12 {
	var e bls12377.E12
	e.SetRandom()
	return e
}

func assignE12Circuit(a, b, c bls12377.E12) (aCirc, bCirc, cCirc E12) {
	aCirc.Assign(&a)
	bCirc.Assign(&b)
	cCirc.Assign(&c)
	return
}

// TestE12MulSZCorrectness verifies that the SZ multiplication path produces
// correct results by compiling with scs.NewBuilder (which supports Committer,
// triggering the SZ path) and solving with native gnark-crypto values.
func TestE12MulSZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	// random test vectors
	a := randomE12()
	b := randomE12()
	var c bls12377.E12
	c.Mul(&a, &b)

	circuit := newE12MulNCircuit(1)
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	aCirc, bCirc, cCirc := assignE12Circuit(a, b, c)
	witness := &e12MulNCircuit{
		N: 1,
		A: []E12{aCirc},
		B: []E12{bCirc},
		C: []E12{cCirc},
	}
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("SZ mul solve failed: %v", err)
	}

	// also test with wrong result (should fail)
	var cWrong bls12377.E12
	cWrong.SetRandom()
	_, _, cWrongCirc := assignE12Circuit(a, b, cWrong)
	badWitness := &e12MulNCircuit{
		N: 1,
		A: []E12{aCirc},
		B: []E12{bCirc},
		C: []E12{cWrongCirc},
	}
	w2, _ := frontend.NewWitness(badWitness, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("SZ mul should reject wrong result")
	}
}

func TestE12MulSZRejectsCorruptedQuotientHint(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a := randomE12()
	b := randomE12()
	var c bls12377.E12
	c.Mul(&a, &b)

	circuit := newE12MulNCircuit(1)
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	aCirc, bCirc, cCirc := assignE12Circuit(a, b, c)
	witness := &e12MulNCircuit{
		N: 1,
		A: []E12{aCirc},
		B: []E12{bCirc},
		C: []E12{cCirc},
	}
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatal(err)
	}

	err = ccs.IsSolved(w, solver.OverrideHint(
		solver.GetHintID(mulE12SZHint),
		corruptHintOutput(mulE12SZHint, 12),
	))
	if err == nil {
		t.Fatal("E12.Mul SZ should reject a corrupted quotient hint")
	}
}

// TestE12MulSZMultiple verifies multiple SZ multiplications batched with
// a single commitment.
func TestE12MulSZMultiple(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	n := 4
	circuit := newE12MulNCircuit(n)
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	witness := newE12MulNCircuit(n)
	for i := 0; i < n; i++ {
		a := randomE12()
		b := randomE12()
		var c bls12377.E12
		c.Mul(&a, &b)
		witness.A[i].Assign(&a)
		witness.B[i].Assign(&b)
		witness.C[i].Assign(&c)
	}
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("SZ mul multiple solve failed: %v", err)
	}
}

// TestE12SquareSZCorrectness verifies the SZ square path.
func TestE12SquareSZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()

	a := randomE12()
	var c bls12377.E12
	c.Square(&a)

	circuit := &e12SquareNCircuit{N: 1, A: make([]E12, 1), C: make([]E12, 1)}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatalf("compile: %v", err)
	}

	witness := &e12SquareNCircuit{N: 1, A: make([]E12, 1), C: make([]E12, 1)}
	witness.A[0].Assign(&a)
	witness.C[0].Assign(&c)
	w, err := frontend.NewWitness(witness, field)
	if err != nil {
		t.Fatalf("witness: %v", err)
	}
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("SZ square solve failed: %v", err)
	}

	// wrong result should fail
	var cWrong bls12377.E12
	cWrong.SetRandom()
	bad := &e12SquareNCircuit{N: 1, A: make([]E12, 1), C: make([]E12, 1)}
	bad.A[0].Assign(&a)
	bad.C[0].Assign(&cWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("SZ square should reject wrong result")
	}
}

type e12SquareNCircuit struct {
	N int
	A []E12
	C []E12
}

func (c *e12SquareNCircuit) Define(api frontend.API) error {
	for i := 0; i < c.N; i++ {
		var r E12
		r.Square(api, c.A[i])
		r.AssertIsEqual(api, c.C[i])
	}
	return nil
}

type e12MulBy01234NCircuit struct {
	N int
	A []E12
	X [][5]E2
}

func (c *e12MulBy01234NCircuit) Define(api frontend.API) error {
	for i := 0; i < c.N; i++ {
		c.A[i].MulBy01234(api, c.X[i])
	}
	return nil
}

type e12MulBy034NCircuit struct {
	N      int
	A      []E12
	C3, C4 []E2
}

func (c *e12MulBy034NCircuit) Define(api frontend.API) error {
	for i := 0; i < c.N; i++ {
		c.A[i].MulBy034(api, c.C3[i], c.C4[i])
	}
	return nil
}

// --- E12.MulBy034 SZ correctness ---

type e12MulBy034SZCircuit struct {
	A      E12
	C3, C4 E2
	Res    E12
}

func (c *e12MulBy034SZCircuit) Define(api frontend.API) error {
	r := c.A
	r.MulBy034(api, c.C3, c.C4)
	r.AssertIsEqual(api, c.Res)
	return nil
}

func TestE12MulBy034SZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a := randomE12()
	var c3, c4 bls12377.E2
	c3.SetRandom()
	c4.SetRandom()

	var sparse bls12377.E12
	sparse.C0.B0.SetOne()
	sparse.C1.B0 = c3
	sparse.C1.B1 = c4
	var res bls12377.E12
	res.Mul(&a, &sparse)

	circuit := &e12MulBy034SZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e12MulBy034SZCircuit{}
	witness.A.Assign(&a)
	witness.C3.Assign(&c3)
	witness.C4.Assign(&c4)
	witness.Res.Assign(&res)
	w, _ := frontend.NewWitness(witness, field)
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("E12.MulBy034 SZ solve failed: %v", err)
	}

	var resWrong bls12377.E12
	resWrong.SetRandom()
	bad := &e12MulBy034SZCircuit{}
	bad.A.Assign(&a)
	bad.C3.Assign(&c3)
	bad.C4.Assign(&c4)
	bad.Res.Assign(&resWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("E12.MulBy034 SZ should reject wrong result")
	}
}

// --- E12.MulBy01234 SZ correctness ---

type e12MulBy01234SZCircuit struct {
	A   E12
	X   [5]E2
	Res E12
}

func (c *e12MulBy01234SZCircuit) Define(api frontend.API) error {
	r := c.A
	r.MulBy01234(api, c.X)
	r.AssertIsEqual(api, c.Res)
	return nil
}

func TestE12MulBy01234SZCorrectness(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	a := randomE12()
	var x [5]bls12377.E2
	for i := range x {
		x[i].SetRandom()
	}

	var sparse bls12377.E12
	sparse.C0.B0 = x[0]
	sparse.C0.B1 = x[1]
	sparse.C0.B2 = x[2]
	sparse.C1.B0 = x[3]
	sparse.C1.B1 = x[4]
	var res bls12377.E12
	res.Mul(&a, &sparse)

	circuit := &e12MulBy01234SZCircuit{}
	ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
	if err != nil {
		t.Fatal(err)
	}

	witness := &e12MulBy01234SZCircuit{}
	witness.A.Assign(&a)
	for i := range x {
		witness.X[i].Assign(&x[i])
	}
	witness.Res.Assign(&res)
	w, _ := frontend.NewWitness(witness, field)
	if err := ccs.IsSolved(w); err != nil {
		t.Fatalf("E12.MulBy01234 SZ solve failed: %v", err)
	}

	var resWrong bls12377.E12
	resWrong.SetRandom()
	bad := &e12MulBy01234SZCircuit{}
	bad.A.Assign(&a)
	for i := range x {
		bad.X[i].Assign(&x[i])
	}
	bad.Res.Assign(&resWrong)
	w2, _ := frontend.NewWitness(bad, field)
	if err := ccs.IsSolved(w2); err == nil {
		t.Fatal("E12.MulBy01234 SZ should reject wrong result")
	}
}

func TestE12MulSZConstraintCount(t *testing.T) {
	field := ecc.BW6_761.ScalarField()
	fmt.Println("=== E12 Multiplication SCS Constraint Counts (Schwartz-Zippel) ===")

	for _, n := range []int{1, 2, 4, 8, 16} {
		circuit := newE12MulNCircuit(n)
		ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
		if err != nil {
			t.Fatalf("compile N=%d: %v", n, err)
		}
		nb := ccs.GetNbConstraints()
		if n == 1 {
			fmt.Printf("  N=%2d: total=%d SCS\n", n, nb)
		} else {
			ccs1, _ := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, newE12MulNCircuit(1))
			marginal := (nb - ccs1.GetNbConstraints()) / (n - 1)
			fmt.Printf("  N=%2d: total=%d SCS, marginal/mul=%d\n", n, nb, marginal)
		}
	}

	fmt.Println("\n=== E12 MulBy01234 SCS Constraint Counts (Schwartz-Zippel) ===")
	for _, n := range []int{1, 2, 4} {
		circuit := &e12MulBy01234NCircuit{N: n, A: make([]E12, n), X: make([][5]E2, n)}
		ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
		if err != nil {
			t.Fatalf("compile mulby01234 N=%d: %v", n, err)
		}
		nb := ccs.GetNbConstraints()
		if n == 1 {
			fmt.Printf("  N=%2d: total=%d SCS\n", n, nb)
		} else {
			ccs1, _ := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, &e12MulBy01234NCircuit{N: 1, A: make([]E12, 1), X: make([][5]E2, 1)})
			marginal := (nb - ccs1.GetNbConstraints()) / (n - 1)
			fmt.Printf("  N=%2d: total=%d SCS, marginal/op=%d\n", n, nb, marginal)
		}
	}

	fmt.Println("\n=== E12 MulBy034 SCS Constraint Counts (Schwartz-Zippel) ===")
	for _, n := range []int{1, 2, 4, 8} {
		circuit := &e12MulBy034NCircuit{N: n, A: make([]E12, n), C3: make([]E2, n), C4: make([]E2, n)}
		ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
		if err != nil {
			t.Fatalf("compile mulby034 N=%d: %v", n, err)
		}
		nb := ccs.GetNbConstraints()
		if n == 1 {
			fmt.Printf("  N=%2d: total=%d SCS\n", n, nb)
		} else {
			ccs1, _ := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, &e12MulBy034NCircuit{N: 1, A: make([]E12, 1), C3: make([]E2, 1), C4: make([]E2, 1)})
			marginal := (nb - ccs1.GetNbConstraints()) / (n - 1)
			fmt.Printf("  N=%2d: total=%d SCS, marginal/op=%d\n", n, nb, marginal)
		}
	}

	fmt.Println("\n=== E12 Square SCS Constraint Counts (Schwartz-Zippel) ===")
	for _, n := range []int{1, 2, 4, 8} {
		circuit := &e12SquareNCircuit{N: n, A: make([]E12, n), C: make([]E12, n)}
		ccs, err := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, circuit)
		if err != nil {
			t.Fatalf("compile square N=%d: %v", n, err)
		}
		nb := ccs.GetNbConstraints()
		if n == 1 {
			fmt.Printf("  N=%2d: total=%d SCS\n", n, nb)
		} else {
			ccs1, _ := frontend.CompileGeneric[constraint.U64](field, scs.NewBuilder, &e12SquareNCircuit{N: 1, A: make([]E12, 1), C: make([]E12, 1)})
			marginal := (nb - ccs1.GetNbConstraints()) / (n - 1)
			fmt.Printf("  N=%2d: total=%d SCS, marginal/sq=%d\n", n, nb, marginal)
		}
	}
}
