package test

import (
	"math/big"

	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/utils"
)

// blueprintSolver is a constraint.Solver that can be used to test a circuit
// it is a separate type to avoid method collisions with the engine.
type blueprintSolver[E constraint.Element] struct {
	internalVariables []*big.Int
	q                 *big.Int
}

// implements constraint.Solver

func (s *blueprintSolver[E]) SetValue(vID uint32, f E) {
	if int(vID) > len(s.internalVariables) {
		panic("out of bounds")
	}
	v := s.ToBigInt(f)
	s.internalVariables[vID].Set(v)
}

func (s *blueprintSolver[E]) GetValue(cID, vID uint32) E {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver[E]) GetCoeff(cID uint32) E {
	panic("not implemented in test.Engine")
}

func (s *blueprintSolver[E]) IsSolved(vID uint32) bool {
	panic("not implemented in test.Engine")
}

// implements constraint.Field

func (s *blueprintSolver[E]) FromInterface(i interface{}) E {
	b := utils.FromInterface(i)
	return s.toElement(&b)
}

func (s *blueprintSolver[E]) ToBigInt(f E) *big.Int {
	r := new(big.Int)
	fBytes := f.Bytes()
	r.SetBytes(fBytes[:])
	return r
}
func (s *blueprintSolver[E]) Mul(a, b E) E {
	ba, bb := s.ToBigInt(a), s.ToBigInt(b)
	ba.Mul(ba, bb).Mod(ba, s.q)
	return s.toElement(ba)
}
func (s *blueprintSolver[E]) Add(a, b E) E {
	ba, bb := s.ToBigInt(a), s.ToBigInt(b)
	ba.Add(ba, bb).Mod(ba, s.q)
	return s.toElement(ba)
}
func (s *blueprintSolver[E]) Sub(a, b E) E {
	ba, bb := s.ToBigInt(a), s.ToBigInt(b)
	ba.Sub(ba, bb).Mod(ba, s.q)
	return s.toElement(ba)
}
func (s *blueprintSolver[E]) Neg(a E) E {
	ba := s.ToBigInt(a)
	ba.Neg(ba).Mod(ba, s.q)
	return s.toElement(ba)
}
func (s *blueprintSolver[E]) Inverse(a E) (E, bool) {
	ba := s.ToBigInt(a)
	r := ba.ModInverse(ba, s.q)
	return s.toElement(ba), r != nil
}
func (s *blueprintSolver[E]) One() E {
	b := new(big.Int).SetUint64(1)
	return s.toElement(b)
}
func (s *blueprintSolver[E]) IsOne(a E) bool {
	b := s.ToBigInt(a)
	return b.IsUint64() && b.Uint64() == 1
}

func (s *blueprintSolver[E]) String(a E) string {
	b := s.ToBigInt(a)
	return b.String()
}

func (s *blueprintSolver[E]) Uint64(a E) (uint64, bool) {
	b := s.ToBigInt(a)
	return b.Uint64(), b.IsUint64()
}

func (s *blueprintSolver[E]) Read(calldata []uint32) (E, int) {
	// We encoded big.Int as constraint.Element on 12 uint32 words.
	var r E
	switch t := any(&r).(type) {
	case *constraint.U64:
		for i := 0; i < len(r); i++ {
			index := i * 2
			t[i] = uint64(calldata[index])<<32 | uint64(calldata[index+1])
		}
		return r, len(r) * 2
	case *constraint.U32:
		t[0] = uint32(calldata[0])
		return r, 1
	default:
		panic("unsupported type")
	}
}

func (s *blueprintSolver[E]) toElement(b *big.Int) E {
	return bigIntToElement[E](b)
}

func bigIntToElement[E constraint.Element](b *big.Int) E {
	if b.Sign() == -1 {
		panic("negative value")
	}
	bytes := b.Bytes()
	var bytesLen int
	var r E
	switch any(r).(type) {
	case constraint.U32:
		bytesLen = 4
	case constraint.U64:
		bytesLen = 48
	default:
		panic("unsupported type")
	}
	if len(bytes) > bytesLen {
		panic("value too big")
	}
	paddedBytes := make([]byte, bytesLen)
	copy(paddedBytes[bytesLen-len(bytes):], bytes[:])
	return constraint.NewElement[E](paddedBytes[:])
}

// wrappedBigInt is a wrapper around big.Int to implement the frontend.CanonicalVariable interface
type wrappedBigInt struct {
	*big.Int
	modulus *big.Int
}

func (w wrappedBigInt) Compress(to *[]uint32) {
	if w.modulus.Cmp(babybear.Modulus()) == 0 || w.modulus.Cmp(koalabear.Modulus()) == 0 {
		e := bigIntToElement[constraint.U32](w.Int)
		*to = append(*to, uint32(e[0]))
	} else {
		e := bigIntToElement[constraint.U64](w.Int)
		// append the uint32 words to the slice
		for i := 0; i < len(e); i++ {
			*to = append(*to, uint32(e[i]>>32))
			*to = append(*to, uint32(e[i]&0xffffffff))
		}
	}
}
