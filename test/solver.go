package test

import (
	"math/big"

	"github.com/consensys/gnark/constraint"
)

type blueprintSolver struct {
	internalVariables []*big.Int
	q                 *big.Int
}

// implements constraint.Solver

func (s *blueprintSolver) GetValue(cID, vID uint32) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) GetCoeff(cID uint32) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) SetValue(vID uint32, f constraint.Element) {
	if int(vID) < len(s.internalVariables) {
		v := s.ToBigInt(f)
		s.internalVariables[vID].Set(v)
	}
}
func (s *blueprintSolver) IsSolved(vID uint32) bool {
	panic("not implemented in test.Engine")
}

// implements constraint.Field

func (s *blueprintSolver) FromInterface(i interface{}) constraint.Element {
	panic("not implemented in test.Engine")
}

func (s *blueprintSolver) ToBigInt(f constraint.Element) *big.Int {
	r := new(big.Int)
	fBytes := f.Bytes()
	r.SetBytes(fBytes[:])
	return r
}
func (s *blueprintSolver) Mul(a, b constraint.Element) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) Add(a, b constraint.Element) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) Sub(a, b constraint.Element) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) Neg(a constraint.Element) constraint.Element {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) Inverse(a constraint.Element) (constraint.Element, bool) {
	panic("not implemented in test.Engine")
}
func (s *blueprintSolver) One() constraint.Element {
	b := new(big.Int).SetUint64(1)
	return s.toElement(b)
}
func (s *blueprintSolver) IsOne(a constraint.Element) bool {
	b := s.ToBigInt(a)
	return b.IsUint64() && b.Uint64() == 1
}

func (s *blueprintSolver) String(a constraint.Element) string {
	b := s.ToBigInt(a)
	return b.String()
}

func (s *blueprintSolver) Uint64(a constraint.Element) (uint64, bool) {
	b := s.ToBigInt(a)
	return b.Uint64(), b.IsUint64()
}

func (s *blueprintSolver) Read(calldata []uint32) (constraint.Element, int) {
	b, n := decodeUint32SliceToBigInt(calldata)
	return s.toElement(b), n
}

func (s *blueprintSolver) toElement(b *big.Int) constraint.Element {
	if b.Sign() == -1 {
		panic("negative value")
	}
	bytes := b.Bytes()
	if len(bytes) > 48 {
		panic("value too big")
	}
	var paddedBytes [48]byte
	copy(paddedBytes[48-len(bytes):], bytes[:])

	var r constraint.Element
	r.SetBytes(paddedBytes)

	return r

}
