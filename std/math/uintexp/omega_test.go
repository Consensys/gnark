package uintexp

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
)

var testModuli = map[string]*big.Int{
	"bn254":     ecc.BN254.ScalarField(),
	"bls12-377": ecc.BLS12_377.ScalarField(),
	"koalabear": koalabear.Modulus(),
	"babybear":  babybear.Modulus(),
}

func TestOmegaOrder(t *testing.T) {
	one := big.NewInt(1)
	for name, q := range testModuli {
		for _, k := range []int{8, 16} {
			w, err := omega(q, k)
			if err != nil {
				t.Fatalf("%s/k=%d: %v", name, k, err)
			}
			// ω^(2^k) == 1
			full := new(big.Int).Exp(w, new(big.Int).Lsh(one, uint(k)), q)
			if full.Cmp(one) != 0 {
				t.Fatalf("%s/k=%d: omega does not have order dividing 2^k", name, k)
			}
			// ω^(2^(k-1)) != 1 (order is exactly 2^k)
			half := new(big.Int).Exp(w, new(big.Int).Lsh(one, uint(k-1)), q)
			if half.Cmp(one) == 0 {
				t.Fatalf("%s/k=%d: omega has order less than 2^k", name, k)
			}
		}
	}
}

func TestOmegaInsufficientTwoAdicity(t *testing.T) {
	if _, err := omega(tinyfield.Modulus(), 8); err == nil {
		t.Fatal("expected error for tinyfield (2-adicity 1)")
	}
	if _, err := omega(koalabear.Modulus(), 25); err == nil {
		t.Fatal("expected error for koalabear width 25 (2-adicity 24)")
	}
	if _, err := omega(koalabear.Modulus(), 24); err != nil {
		t.Fatalf("koalabear width 24 should be supported: %v", err)
	}
}

func TestDecodeExpRoundTrip(t *testing.T) {
	for name, q := range testModuli {
		for _, k := range []int{8, 16} {
			w, err := omega(q, k)
			if err != nil {
				t.Fatal(err)
			}
			// fixed exponents covering the corners plus random ones
			exps := []uint64{0, 1, 2, (1 << (k - 1)), (1 << k) - 1}
			for i := 0; i < 20; i++ {
				r, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), uint(k)))
				exps = append(exps, r.Uint64())
			}
			for _, a := range exps {
				v := new(big.Int).Exp(w, new(big.Int).SetUint64(a), q)
				got, err := decodeExp(q, k, v)
				if err != nil {
					t.Fatalf("%s/k=%d/a=%d: %v", name, k, a, err)
				}
				if got.Uint64() != a {
					t.Fatalf("%s/k=%d: decodeExp(omega^%d) = %d", name, k, a, got.Uint64())
				}
			}
		}
	}
}

func TestDecodeExpRejectsNonSubgroup(t *testing.T) {
	for name, q := range testModuli {
		for _, k := range []int{8, 16} {
			// an element of order 2^(k+1): outside the order-2^k subgroup but
			// with a square inside it -- the adversarial case for soundness
			wBig, err := omega(q, k+1)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeExp(q, k, wBig); err == nil {
				t.Fatalf("%s/k=%d: decodeExp accepted an element of order 2^(k+1)", name, k)
			}
			// zero and out-of-range values
			if _, err := decodeExp(q, k, big.NewInt(0)); err == nil {
				t.Fatalf("%s/k=%d: decodeExp accepted 0", name, k)
			}
			if _, err := decodeExp(q, k, new(big.Int).Set(q)); err == nil {
				t.Fatalf("%s/k=%d: decodeExp accepted q", name, k)
			}
			// a random high-order element (whp not in the subgroup)
			r, _ := rand.Int(rand.Reader, q)
			if r.Sign() != 0 {
				if a, err := decodeExp(q, k, r); err == nil {
					// on the off chance r is in the subgroup, verify honesty
					w, _ := omega(q, k)
					v := new(big.Int).Exp(w, a, q)
					if v.Cmp(r) != 0 {
						t.Fatalf("%s/k=%d: decodeExp returned wrong dlog for random element", name, k)
					}
				}
			}
		}
	}
}

func TestDecodeHint(t *testing.T) {
	q := koalabear.Modulus()
	w, err := omega(q, 8)
	if err != nil {
		t.Fatal(err)
	}
	v := new(big.Int).Exp(w, big.NewInt(42), q)
	out := []*big.Int{new(big.Int)}
	if err := decodeHint(q, []*big.Int{big.NewInt(8), v}, out); err != nil {
		t.Fatal(err)
	}
	if out[0].Uint64() != 42 {
		t.Fatalf("decodeHint: got %s, want 42", out[0])
	}
	// wrong arity
	if err := decodeHint(q, []*big.Int{v}, out); err == nil {
		t.Fatal("expected arity error")
	}
	// non-subgroup value
	if err := decodeHint(q, []*big.Int{big.NewInt(8), big.NewInt(0)}, out); err == nil {
		t.Fatal("expected non-subgroup error")
	}
}
