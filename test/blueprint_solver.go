package test

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/internal/utils"
)

// blueprintSolver is a constraint.Solver that can be used to test a circuit
// it is a separate type to avoid method collisions with the engine.
type blueprintSolver[E constraint.Element] struct {
	internalVariables []*big.Int
	q                 *big.Int
	rInv              *big.Int // R^-1 mod q for efficient Montgomery conversion
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

// ToBigInt converts element (Montgomery form) to canonical big.Int
func (s *blueprintSolver[E]) ToBigInt(f E) *big.Int {
	// Element is in Montgomery form, convert to canonical: canonical = f * R^-1 mod q
	fBytes := f.Bytes()
	montgomery := new(big.Int).SetBytes(fBytes[:])
	result := new(big.Int).Mul(montgomery, s.rInv)
	result.Mod(result, s.q)
	return result
}

// toMontBigInt extracts element bytes as Montgomery form big.Int (no conversion)
func (s *blueprintSolver[E]) toMontBigInt(f E) *big.Int {
	fBytes := f.Bytes()
	return new(big.Int).SetBytes(fBytes[:])
}

// montBigIntToElement converts Montgomery big.Int directly to element (no conversion)
func (s *blueprintSolver[E]) montBigIntToElement(mont *big.Int) E {
	bytes := mont.Bytes()
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
func (s *blueprintSolver[E]) Mul(a, b E) E {
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Mul(ba, bb).
		Mod(ba, s.q).
		Mul(ba, s.rInv).
		Mod(ba, s.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Add(a, b E) E {
	// Addition works the same in Montgomery form: (a*R + b*R) mod m = (a+b)*R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Add(ba, bb).Mod(ba, s.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Sub(a, b E) E {
	// Subtraction works the same in Montgomery form: (a*R - b*R) mod m = (a-b)*R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Sub(ba, bb).Mod(ba, s.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Neg(a E) E {
	// Negation works the same in Montgomery form: -(a*R) mod m = (-a)*R mod m
	ba := s.toMontBigInt(a)
	ba.Neg(ba).Mod(ba, s.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Inverse(a E) (E, bool) {
	r := s.toMontBigInt(a)
	r = r.ModInverse(r, s.q)
	if r == nil {
		var zero E
		return zero, false
	}
	r.Lsh(r, getLogR(s.q)).
		Mod(r, s.q)
	return s.toElement(r), true
}
func (s *blueprintSolver[E]) One() E {
	b := new(big.Int).SetUint64(1)
	return s.toElement(b)
}
func (s *blueprintSolver[E]) IsOne(a E) bool {
	return a == s.One()
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
	// Read canonical bytes from calldata, convert to Montgomery form element
	var r E
	var canonicalValue *big.Int
	var nWords int

	switch t := any(&r).(type) {
	case *constraint.U64:
		// Read canonical bytes from calldata
		for i := 0; i < len(r); i++ {
			index := i * 2
			t[i] = uint64(calldata[index])<<32 | uint64(calldata[index+1])
		}
		canonicalValue = new(big.Int).SetBytes(r.Bytes())
		nWords = len(r) * 2
	case *constraint.U32:
		t[0] = uint32(calldata[0])
		canonicalValue = new(big.Int).SetUint64(uint64(t[0]))
		nWords = 1
	default:
		panic("unsupported type")
	}

	// Convert canonical to Montgomery and return as element
	return s.toElement(canonicalValue), nWords
}

func (s *blueprintSolver[E]) toElement(b *big.Int) E {
	if b.Sign() == -1 {
		panic("negative value")
	}

	mont := new(big.Int).Lsh(b, getLogR(s.q))
	mont.Mod(mont, s.q)
	bytes := mont.Bytes()
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

// getLogR returns log2(R) for efficient shifting
func getLogR(modulus *big.Int) uint {
	if smallfields.IsSmallField(modulus) {
		return 32
	}
	// For large fields, R = 2^(nbLimbs * 64)
	nbBits := modulus.BitLen()
	nbLimbs := (nbBits + 63) / 64
	return uint(nbLimbs * 64)
}

// wrappedBigInt is a wrapper around big.Int to implement the frontend.CanonicalVariable interface
type wrappedBigInt struct {
	*big.Int
	modulus *big.Int
}

// Compress writes canonical bytes to calldata (no Montgomery conversion)
func (w wrappedBigInt) Compress(to *[]uint32) {
	if w.Sign() == -1 {
		panic("negative value")
	}

	bytes := w.Bytes()
	if smallfields.IsSmallField(w.modulus) {
		if len(bytes) > 4 {
			panic("value too big")
		}
		paddedBytes := make([]byte, 4)
		copy(paddedBytes[4-len(bytes):], bytes[:])
		e := constraint.NewElement[constraint.U32](paddedBytes[:])
		*to = append(*to, uint32(e[0]))
	} else {
		if len(bytes) > 48 {
			panic("value too big")
		}
		paddedBytes := make([]byte, 48)
		copy(paddedBytes[48-len(bytes):], bytes[:])
		e := constraint.NewElement[constraint.U64](paddedBytes[:])
		// append the uint32 words to the slice
		for i := 0; i < len(e); i++ {
			*to = append(*to, uint32(e[i]>>32))
			*to = append(*to, uint32(e[i]&0xffffffff))
		}
	}
}
