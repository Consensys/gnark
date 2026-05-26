package sw_octobear

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/octobear"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type g1AddAssignAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddAssignAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddAssign(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddAssignAffineG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac, bJac := distinctPointsG1(t)
	var a, b, c octobear.G1Affine
	a.FromJacobian(&aJac)
	b.FromJacobian(&bJac)
	aJac.AddAssign(&bJac)
	c.FromJacobian(&aJac)

	var witness g1AddAssignAffine
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1AddAssignAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type g1DoubleAffine struct {
	A G1Affine
	C G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAffine) Define(api frontend.API) error {
	expected := G1Affine{}
	expected.Double(api, circuit.A)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAffineG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac := randomPointG1(t)
	var a, c octobear.G1Affine
	a.FromJacobian(&aJac)
	aJac.DoubleAssign()
	c.FromJacobian(&aJac)

	var witness g1DoubleAffine
	witness.A.Assign(&a)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1DoubleAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type g1AddUnifiedAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddUnifiedAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddUnified(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddUnifiedAffineG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac, bJac := distinctPointsG1(t)
	var a, b, c octobear.G1Affine
	a.FromJacobian(&aJac)
	b.FromJacobian(&bJac)
	aJac.AddAssign(&bJac)
	c.FromJacobian(&aJac)

	var witness g1AddUnifiedAffine
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1AddUnifiedAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type g1DoubleAndAddAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1DoubleAndAddAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.DoubleAndAdd(api, &circuit.A, &circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestDoubleAndAddAffineG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac, bJac := distinctPointsG1(t)
	var a, b, c octobear.G1Affine
	a.FromJacobian(&aJac)
	b.FromJacobian(&bJac)
	aJac.DoubleAssign().AddAssign(&bJac)
	c.FromJacobian(&aJac)

	var witness g1DoubleAndAddAffine
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1DoubleAndAddAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

type g1AddBrierJoyeAffine struct {
	A, B G1Affine
	C    G1Affine `gnark:",public"`
}

func (circuit *g1AddBrierJoyeAffine) Define(api frontend.API) error {
	expected := circuit.A
	expected.AddBrierJoye(api, circuit.B)
	expected.AssertIsEqual(api, circuit.C)
	return nil
}

func TestAddBrierJoyeAffineG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac, bJac := distinctPointsG1(t)
	var a, b, c octobear.G1Affine
	a.FromJacobian(&aJac)
	b.FromJacobian(&bJac)
	aJac.AddAssign(&bJac)
	c.FromJacobian(&aJac)

	var witness g1AddBrierJoyeAffine
	witness.A.Assign(&a)
	witness.B.Assign(&b)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1AddBrierJoyeAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func TestAddBrierJoyeDoubleG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac := randomPointG1(t)
	var a, c octobear.G1Affine
	a.FromJacobian(&aJac)
	aJac.DoubleAssign()
	c.FromJacobian(&aJac)

	var witness g1AddBrierJoyeAffine
	witness.A.Assign(&a)
	witness.B.Assign(&a)
	witness.C.Assign(&c)

	assert.CheckCircuit(&g1AddBrierJoyeAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func TestAddBrierJoyeOppositeG1(t *testing.T) {
	assert := test.NewAssert(t)
	aJac := randomPointG1(t)
	var a octobear.G1Affine
	a.FromJacobian(&aJac)

	var negA octobear.G1Affine
	negA.Neg(&a)

	var witness g1AddBrierJoyeAffine
	witness.A.Assign(&a)
	witness.B.Assign(&negA)
	witness.C.X.SetZero()
	witness.C.Y.SetZero()

	assert.CheckCircuit(&g1AddBrierJoyeAffine{}, test.WithValidAssignment(&witness), test.WithoutCurveChecks(), test.WithSmallfieldCheck())
}

func randomPointG1(t *testing.T) octobear.G1Jac {
	t.Helper()
	_, g := octobear.Generators()
	var s octobear.G1Jac
	s.FromAffine(&g)
	for s.Z.IsZero() {
		// impossible path, keep non-zero point invariant
		s.FromAffine(&g)
	}
	return s
}

func distinctPointsG1(t *testing.T) (octobear.G1Jac, octobear.G1Jac) {
	t.Helper()
	a := randomPointG1(t)
	b := a
	b.DoubleAssign()
	return a, b
}
