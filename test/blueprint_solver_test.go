package test

import (
	"math/big"
	"math/rand"
	"testing"
	"time"

	"github.com/consensys/gnark-crypto/ecc"
)

func TestBigIntToElement(t *testing.T) {
	t.Parallel()
	// sample a random big.Int, convert it to an element, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver{q: ecc.BN254.ScalarField()}
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

func TestBigIntToUint32Slice(t *testing.T) {
	t.Parallel()
	// sample a random big.Int, write it to a uint32 slice, and back
	// to a big.Int, and check that it's the same
	s := blueprintSolver{q: ecc.BN254.ScalarField()}
	b1 := big.NewInt(0)
	b2 := big.NewInt(0)

	for i := 0; i < 50; i++ {
		b1.Rand(rand.New(rand.NewSource(time.Now().Unix())), s.q) //#nosec G404 -- This is a false positive
		b2.Rand(rand.New(rand.NewSource(time.Now().Unix())), s.q) //#nosec G404 -- This is a false positive
		wb1 := wrappedBigInt{b1}
		wb2 := wrappedBigInt{b2}
		var to []uint32
		wb1.Compress(&to)
		wb2.Compress(&to)

		if len(to) != 24 {
			t.Fatal("wrong length: expected 2*len of constraint.Element (uint32 words)")
		}

		e1, n := s.Read(to)
		if n != 12 {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		e2, n := s.Read(to[n:])
		if n != 12 {
			t.Fatal("wrong length: expected 1 len of constraint.Element (uint32 words)")
		}
		rb1, rb2 := s.ToBigInt(e1), s.ToBigInt(e2)
		if rb1.Cmp(b1) != 0 || rb2.Cmp(b2) != 0 {
			t.Fatal("rb1 != b1 || rb2 != b2")
		}
	}

}
