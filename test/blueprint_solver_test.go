package test

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark/constraint"
)

func testBigIntoToElement[E constraint.Element](t *testing.T, modulus *big.Int) {
	// sample a random big.Int, convert it to an element, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver[E]{q: modulus}
	b := big.NewInt(0)
	for i := 0; i < 50; i++ {
		b.Rand(rand.New(rand.NewSource(time.Now().Unix())), s.q) //#nosec G404 -- This is a false positive
		e := s.toElement(b)
		b2 := s.ToBigInt(e)
		if b.Cmp(b2) != 0 {
			t.Fatal("b != b2")
		}
	}
}

func TestBigIntToElement(t *testing.T) {
	// t.Parallel()
	testBigIntoToElement[constraint.U64](t, ecc.BW6_761.ScalarField())
	testBigIntoToElement[constraint.U64](t, ecc.BN254.ScalarField())
	testBigIntoToElement[constraint.U32](t, babybear.Modulus())
}

func testBigIntToUint32Slice[E constraint.Element](t *testing.T, modulus *big.Int) {
	// sample a random big.Int, write it to a uint32 slice, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver[E]{q: modulus}
	var elementLen int // number of uint32 words in the element
	var e E
	switch any(e).(type) {
	case constraint.U32:
		elementLen = 1 // 2 * 1 uint32
	case constraint.U64:
		elementLen = 12 // 6 * 2 ([6]uint64) = 12 uint32
	}

	b1 := big.NewInt(0)
	b2 := big.NewInt(0)

	randSource := rand.New(rand.NewSource(time.Now().Unix())) //#nosec G404 -- This is a false positive

	for i := 0; i < 50; i++ {
		b1.Rand(randSource, s.q)
		b2.Rand(randSource, s.q)
		wb1 := wrappedBigInt{Int: b1, modulus: modulus}
		wb2 := wrappedBigInt{Int: b2, modulus: modulus}
		var to []uint32
		wb1.Compress(&to)
		wb2.Compress(&to)

		if len(to) != elementLen*2 {
			t.Fatal("wrong length: expected 2*len of constraint.Element (uint32 words)")
		}

		e1, n := s.Read(to)
		if n != elementLen {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		e2, n := s.Read(to[n:])
		if n != elementLen {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		rb1, rb2 := s.ToBigInt(e1), s.ToBigInt(e2)
		if rb1.Cmp(b1) != 0 || rb2.Cmp(b2) != 0 {
			t.Fatal("rb1 != b1 || rb2 != b2")
		}
	}
}

func TestBigIntToUint32Slice(t *testing.T) {
	t.Parallel()
	testBigIntToUint32Slice[constraint.U64](t, ecc.BW6_761.ScalarField())
	testBigIntToUint32Slice[constraint.U64](t, ecc.BN254.ScalarField())
	testBigIntToUint32Slice[constraint.U32](t, babybear.Modulus())
}
