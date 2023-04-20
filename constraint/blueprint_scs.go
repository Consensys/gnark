package constraint

import (
	"errors"
	"fmt"
)

var (
	errDivideByZero  = errors.New("division by 0")
	errBoolConstrain = errors.New("boolean constraint doesn't hold")
)

// BlueprintGenericSparseR1C implements Blueprint and BlueprintSparseR1C.
// Encodes
//
//	qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC == 0
type BlueprintGenericSparseR1C struct{}

func (b *BlueprintGenericSparseR1C) NbInputs() int {
	return 9 // number of fields in SparseR1C
}
func (b *BlueprintGenericSparseR1C) NbConstraints() int {
	return 1
}

func (b *BlueprintGenericSparseR1C) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		c.XA,
		c.XB,
		c.XC,
		c.QL,
		c.QR,
		c.QO,
		c.QM,
		c.QC,
		uint32(c.Commitment),
	}
}

func (b *BlueprintGenericSparseR1C) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()

	c.XA = calldata[0]
	c.XB = calldata[1]
	c.XC = calldata[2]
	c.QL = calldata[3]
	c.QR = calldata[4]
	c.QO = calldata[5]
	c.QM = calldata[6]
	c.QC = calldata[7]
	c.Commitment = CommitmentConstraint(calldata[8])
}

func (b *BlueprintGenericSparseR1C) Solve(s Solver, calldata []uint32) error {
	var c SparseR1C
	b.DecompressSparseR1C(&c, calldata)
	if c.Commitment != NOT {
		// a constraint of the form f_L - PI_2 = 0 or f_L = Comm.
		// these are there for enforcing the correctness of the commitment and can be skipped in solving time
		return nil
	}

	var ok bool

	// constraint has at most one unsolved wire.
	if !s.IsSolved(c.XA) {
		// we solve for L: u1L+u2R+u3LR+u4O+k=0 => L(u1+u3R)+u2R+u4O+k = 0
		u1 := s.GetCoeff(c.QL)
		den := s.GetValue(c.QM, c.XB)
		den = s.Add(den, u1)
		den, ok = s.Inverse(den)
		if !ok {
			return errDivideByZero
		}
		v1 := s.GetValue(c.QR, c.XB)
		v2 := s.GetValue(c.QO, c.XC)
		num := s.Add(v1, v2)
		num = s.Add(num, s.GetCoeff(c.QC))
		num = s.Mul(num, den)
		num = s.Neg(num)
		s.SetValue(c.XA, num)
	} else if !s.IsSolved(c.XB) {
		u2 := s.GetCoeff(c.QR)
		den := s.GetValue(c.QM, c.XA)
		den = s.Add(den, u2)
		den, ok = s.Inverse(den)
		if !ok {
			return errDivideByZero
		}

		v1 := s.GetValue(c.QL, c.XA)
		v2 := s.GetValue(c.QO, c.XC)

		num := s.Add(v1, v2)
		num = s.Add(num, s.GetCoeff(c.QC))
		num = s.Mul(num, den)
		num = s.Neg(num)
		s.SetValue(c.XB, num)

	} else if !s.IsSolved(c.XC) {
		// O we solve for O
		l := s.GetValue(c.QL, c.XA)
		r := s.GetValue(c.QR, c.XB)
		m0 := s.GetValue(c.QM, c.XA)
		m1 := s.GetValue(CoeffIdOne, c.XB)

		// o = - ((m0 * m1) + l + r + c.QC) / c.O
		o := s.Mul(m0, m1)
		o = s.Add(o, l)
		o = s.Add(o, r)
		o = s.Add(o, s.GetCoeff(c.QC))

		den := s.GetCoeff(c.QO)
		den, ok = s.Inverse(den)
		if !ok {
			return errDivideByZero
		}
		o = s.Mul(o, den)
		o = s.Neg(o)

		s.SetValue(c.XC, o)
	} else {
		// all wires are solved, we verify that the constraint hold.
		// this can happen when all wires are from hints or if the constraint is an assertion.
		return b.checkConstraint(&c, s)
	}
	return nil
}

func (b *BlueprintGenericSparseR1C) checkConstraint(c *SparseR1C, s Solver) error {
	l := s.GetValue(c.QL, c.XA)
	r := s.GetValue(c.QR, c.XB)
	m0 := s.GetValue(c.QM, c.XA)
	m1 := s.GetValue(CoeffIdOne, c.XB)
	m0 = s.Mul(m0, m1)
	o := s.GetValue(c.QO, c.XC)
	qC := s.GetCoeff(c.QC)

	t := s.Add(m0, l)
	t = s.Add(t, r)
	t = s.Add(t, o)
	t = s.Add(t, qC)

	if !t.IsZero() {
		return fmt.Errorf("qL⋅xa + qR⋅xb + qO⋅xc + qM⋅(xaxb) + qC != 0 → %s + %s + %s + %s + %s != 0",
			s.String(l),
			s.String(r),
			s.String(o),
			s.String(m0),
			s.String(qC),
		)
	}
	return nil
}

// BlueprintSparseR1CMul implements Blueprint, BlueprintSolvable and BlueprintSparseR1C.
// Encodes
//
//	qM⋅(xaxb)  == xc
type BlueprintSparseR1CMul struct{}

func (b *BlueprintSparseR1CMul) NbInputs() int {
	return 4
}
func (b *BlueprintSparseR1CMul) NbConstraints() int {
	return 1
}

func (b *BlueprintSparseR1CMul) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		c.XA,
		c.XB,
		c.XC,
		c.QM,
	}
}

func (b *BlueprintSparseR1CMul) Solve(s Solver, calldata []uint32) error {
	// qM⋅(xaxb)  == xc
	m0 := s.GetValue(calldata[3], calldata[0])
	m1 := s.GetValue(CoeffIdOne, calldata[1])

	m0 = s.Mul(m0, m1)

	s.SetValue(calldata[2], m0)
	return nil
}

func (b *BlueprintSparseR1CMul) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()
	c.XA = calldata[0]
	c.XB = calldata[1]
	c.XC = calldata[2]
	c.QO = CoeffIdMinusOne
	c.QM = calldata[3]
}

// BlueprintSparseR1CAdd implements Blueprint, BlueprintSolvable and BlueprintSparseR1C.
// Encodes
//
//	qL⋅xa + qR⋅xb + qC == xc
type BlueprintSparseR1CAdd struct{}

func (b *BlueprintSparseR1CAdd) NbInputs() int {
	return 6
}
func (b *BlueprintSparseR1CAdd) NbConstraints() int {
	return 1
}

func (b *BlueprintSparseR1CAdd) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		c.XA,
		c.XB,
		c.XC,
		c.QL,
		c.QR,
		c.QC,
	}
}

func (blueprint *BlueprintSparseR1CAdd) Solve(s Solver, calldata []uint32) error {
	// a + b + k == c
	a := s.GetValue(calldata[3], calldata[0])
	b := s.GetValue(calldata[4], calldata[1])
	k := s.GetCoeff(calldata[5])

	a = s.Add(a, b)
	a = s.Add(a, k)

	s.SetValue(calldata[2], a)
	return nil
}

func (b *BlueprintSparseR1CAdd) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()
	c.XA = calldata[0]
	c.XB = calldata[1]
	c.XC = calldata[2]
	c.QL = calldata[3]
	c.QR = calldata[4]
	c.QO = CoeffIdMinusOne
	c.QC = calldata[5]
}

// BlueprintSparseR1CBool implements Blueprint, BlueprintSolvable and BlueprintSparseR1C.
// Encodes
//
//	qL⋅xa + qM⋅(xa*xa)  == 0
//	that is v + -v*v == 0
type BlueprintSparseR1CBool struct{}

func (b *BlueprintSparseR1CBool) NbInputs() int {
	return 3
}
func (b *BlueprintSparseR1CBool) NbConstraints() int {
	return 1
}

func (b *BlueprintSparseR1CBool) CompressSparseR1C(c *SparseR1C) []uint32 {
	return []uint32{
		c.XA,
		c.QL,
		c.QM,
	}
}

func (blueprint *BlueprintSparseR1CBool) Solve(s Solver, calldata []uint32) error {
	// all wires are already solved, we just check the constraint.
	v1 := s.GetValue(calldata[1], calldata[0])
	v2 := s.GetValue(calldata[2], calldata[0])
	v := s.GetValue(CoeffIdOne, calldata[0])
	v = s.Mul(v, v2)
	v = s.Add(v1, v)
	if !v.IsZero() {
		return errBoolConstrain
	}
	return nil
}

func (b *BlueprintSparseR1CBool) DecompressSparseR1C(c *SparseR1C, calldata []uint32) {
	c.Clear()
	c.XA = calldata[0]
	c.XB = c.XA
	c.QL = calldata[1]
	c.QM = calldata[2]
}
