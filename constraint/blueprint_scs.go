package constraint

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

func (b *BlueprintSparseR1CMul) Solve(s Solver, calldata []uint32) {
	// qM⋅(xaxb)  == xc
	m0 := s.GetValue(calldata[3], calldata[0])
	m1 := s.GetValue(CoeffIdOne, calldata[1])

	m0 = s.Mul(m0, m1)

	s.SetValue(calldata[2], m0)
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

func (blueprint *BlueprintSparseR1CAdd) Solve(s Solver, calldata []uint32) {
	// a + b + k == c
	a := s.GetValue(calldata[3], calldata[0])
	b := s.GetValue(calldata[4], calldata[1])
	k := s.GetCoeff(calldata[5])

	a = s.Add(a, b)
	a = s.Add(a, k)

	s.SetValue(calldata[2], a)
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
