package test

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/internal/smallfields"
	"github.com/consensys/gnark/internal/utils"
)

// modulus encapsulates field modulus and Montgomery conversion parameters
type modulus[E constraint.Element] struct {
	q    *big.Int
	rInv *big.Int
	logR uint
}

// newModulus creates a typed modulus and computes Montgomery parameters
func newModulus[E constraint.Element](q *big.Int) *modulus[E] {
	res := &modulus[E]{q: q, rInv: big.NewInt(1)}
	if smallfields.IsSmallField(q) {
		res.logR = 32
	} else {
		nbBits := q.BitLen()
		nbLimbs := (nbBits + 63) / 64
		res.logR = uint(nbLimbs * 64)
	}
	res.rInv = res.rInv.
		Lsh(big.NewInt(1), res.logR).
		ModInverse(res.rInv, q)

	return res
}

// toMontBigInt extracts element bytes as Montgomery form big.Int (no conversion)
func (m *modulus[E]) toMontBigInt(f E) *big.Int {
	fBytes := f.Bytes()
	return new(big.Int).SetBytes(fBytes[:])
}

// montBigIntToElement converts Montgomery big.Int directly to element (no conversion)
func (m *modulus[E]) montBigIntToElement(mont *big.Int) E {
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

// ToBigInt converts element (Montgomery form) to canonical big.Int
func (m *modulus[E]) ToBigInt(f E) *big.Int {
	x := m.toMontBigInt(f)
	x.Mul(x, m.rInv).Mod(x, m.q)
	return x
}

// bigIntToElement converts canonical big.Int to Montgomery form element
func (m *modulus[E]) bigIntToElement(b *big.Int) E {
	if b.Sign() == -1 {
		panic("negative value")
	}
	x := new(big.Int).Lsh(b, m.logR)
	x.Mod(x, m.q)
	return m.montBigIntToElement(x)
}

// blueprintSolver is a constraint.Solver that can be used to test a circuit
// it is a separate type to avoid method collisions with the engine.
type blueprintSolver[E constraint.Element] struct {
	internalVariables []*big.Int
	*modulus[E]
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
	return s.bigIntToElement(&b)
}

// ToBigInt converts element (Montgomery form) to canonical big.Int
func (s *blueprintSolver[E]) ToBigInt(f E) *big.Int {
	x := s.toMontBigInt(f)
	x.
		Mul(x, s.modulus.rInv).
		Mod(x, s.modulus.q)
	return x
}

// toMontBigInt extracts element bytes as Montgomery form big.Int (no conversion)
func (s *blueprintSolver[E]) toMontBigInt(f E) *big.Int {
	fBytes := f.Bytes()
	return new(big.Int).SetBytes(fBytes[:])
}

func (s *blueprintSolver[E]) Mul(a, b E) E {
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Mul(ba, bb).
		Mod(ba, s.modulus.q).
		Mul(ba, s.modulus.rInv).
		Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Add(a, b E) E {
	// Addition works the same in Montgomery form: (a*R + b*R) mod m = (a+b)*R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Add(ba, bb).Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Sub(a, b E) E {
	// Subtraction works the same in Montgomery form: (a*R - b*R) mod m = (a-b)*R mod m
	ba, bb := s.toMontBigInt(a), s.toMontBigInt(b)
	ba.Sub(ba, bb).Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Neg(a E) E {
	// Negation works the same in Montgomery form: -(a*R) mod m = (-a)*R mod m
	ba := s.toMontBigInt(a)
	ba.Neg(ba).Mod(ba, s.modulus.q)
	return s.montBigIntToElement(ba)
}
func (s *blueprintSolver[E]) Inverse(a E) (E, bool) {
	r := s.toMontBigInt(a)
	r = r.ModInverse(r, s.modulus.q)
	if r == nil {
		var zero E
		return zero, false
	}
	r.Lsh(r, s.modulus.logR).
		Mod(r, s.modulus.q)
	return s.bigIntToElement(r), true
}
func (s *blueprintSolver[E]) One() E {
	b := new(big.Int).SetUint64(1)
	return s.bigIntToElement(b)
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
	return s.bigIntToElement(canonicalValue), nWords
}

// wrappedBigInt is a wrapper around big.Int to implement the frontend.CanonicalVariable interface
type wrappedBigInt[E constraint.Element] struct {
	*big.Int
	*modulus[E]
}

// Compress writes canonical bytes to calldata (no Montgomery conversion)
func (w wrappedBigInt[E]) Compress(to *[]uint32) {
	if w.Sign() == -1 {
		panic("negative value")
	}

	// Use montBigIntToElement to handle byte padding and type switching
	e := w.modulus.montBigIntToElement(w.Int)

	// Extract uint32 values from the element
	switch e := any(e).(type) {
	case constraint.U32:
		*to = append(*to, uint32(e[0]))
	case constraint.U64:
		// append the uint32 words to the slice
		for i := range e {
			*to = append(*to, uint32(e[i]>>32))
			*to = append(*to, uint32(e[i]&0xffffffff))
		}
	default:
		panic("unsupported type")
	}
}
