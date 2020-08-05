package zkpschemes

const Groth16Setup = `

import (
	{{ template "import_curve" . }}
	"github.com/consensys/gnark/internal/utils/parallel"
	{{ template "import_backend" . }}
)

// ProvingKey is used by a Groth16 prover to encode a proof of a statement
type ProvingKey struct {
	// [α]1, [β]1, [δ]1
	// [A(t)]1, [B(t)]1, [Kpk(t)]1, [Z(t)]1
	G1 struct {
		Alpha, Beta, Delta curve.G1Affine
		A, B, Z            []curve.G1Affine
		K                  []curve.G1Affine // the indexes correspond to the private wires
	}

	// [β]2, [δ]2, [B(t)]2
	G2 struct {
		Beta, Delta curve.G2Affine
		B           []curve.G2Affine
	}
}

// VerifyingKey is used by a Groth16 verifier to verify the validity of a proof and a statement
type VerifyingKey struct {
	// e(α, β)
	E curve.PairingResult

	// -[γ]2, -[δ]2
	// note: storing GammaNeg and DeltaNeg instead of Gamma and Delta
	// see proof.Verify() for more details
	G2 struct {
		GammaNeg, DeltaNeg curve.G2Affine
	}

	// [Kvk]1
	G1 struct {
		K []curve.G1Affine // The indexes correspond to the public wires
	}

	PublicInputs []string // maps the name of the public input
}

// Setup constructs the SRS
func Setup(r1cs *backend_{{toLower .Curve}}.R1CS, pk *ProvingKey, vk *VerifyingKey) {

	/*
		Setup
		-----
		To build the verifying keys:
		- compile the r1cs system -> the number of gates is len(GateOrdering)+len(PureStructuralConstraints)+len(InpureStructuralConstraints)
		- loop through the ordered computational constraints (=gate in r1cs system structure), eValuate A(X), B(X), C(X) with simple formula (the gate number is the current iterator)
		- loop through the inpure structural constraints, eValuate A(X), B(X), C(X) with simple formula, the gate number is len(gateOrdering)+ current iterator
		- loop through the pure structural constraints, eValuate A(X), B(X), C(X) with simple formula, the gate number is len(gateOrdering)+len(InpureStructuralConstraints)+current iterator
	*/

	// get R1CS nb constraints, wires and public/private inputs
	nbWires := r1cs.NbWires
	nbPublicWires := r1cs.NbPublicWires
	nbConstraints := r1cs.NbConstraints

	// Setting group for fft
	gateGroup := backend_{{toLower .Curve}}.NewDomain( nbConstraints)

	// initialize proving key
	pk.G1.A = make([]curve.G1Affine, nbWires)
	pk.G1.B = make([]curve.G1Affine, nbWires)
	pk.G1.K = make([]curve.G1Affine, r1cs.NbWires-r1cs.NbPublicWires)
	pk.G1.Z = make([]curve.G1Affine, gateGroup.Cardinality)
	pk.G2.B = make([]curve.G2Affine, nbWires)

	// initialize verifying key
	vk.G1.K = make([]curve.G1Affine, nbPublicWires)

	// samples toxic waste
	toxicWaste := sampleToxicWaste()

	// Set public inputs in Verifying Key (Verify does not need the R1CS data structure)
	vk.PublicInputs = r1cs.PublicWires

	// setup the alpha, beta, gamma, delta part of verifying & proving key
	setupToxicWaste(pk, vk, toxicWaste)

	// setup Z part of the proving key
	setupWitnessPolynomial(pk, toxicWaste, gateGroup)

	// Setup coeffs to compute pk.G1.A, pk.G1.B, pk.G1.K
	A, B, C := setupABC(r1cs, gateGroup, toxicWaste)

	// Set the vector of points in the verifying & proving key from the coefficients
	setupKeyVectors(A, B, C, pk, vk, toxicWaste, r1cs)

}

// DummySetup fills a random ProvingKey
// used for test or benchmarking purposes
func DummySetup(r1cs *backend_{{toLower .Curve}}.R1CS, pk *ProvingKey) {
	// get R1CS nb constraints, wires and public/private inputs
	nbWires := r1cs.NbWires
	nbConstraints := r1cs.NbConstraints

	// Setting group for fft
	gateGroup := backend_{{toLower .Curve}}.NewDomain(nbConstraints)

	// initialize proving key
	pk.G1.A = make([]curve.G1Affine, nbWires)
	pk.G1.B = make([]curve.G1Affine, nbWires)
	pk.G1.K = make([]curve.G1Affine, r1cs.NbWires-r1cs.NbPublicWires)
	pk.G1.Z = make([]curve.G1Affine, gateGroup.Cardinality)
	pk.G2.B = make([]curve.G2Affine, nbWires)

	// samples toxic waste
	tw := sampleToxicWaste()

	
	var r1Jac curve.G1Jac
	var r1Aff curve.G1Affine
	r1Jac.ScalarMulByGen(&tw.alphaReg)
	r1Aff.FromJacobian(&r1Jac)
	var r2Jac curve.G2Jac
	var r2Aff curve.G2Affine
	r2Jac.ScalarMulByGen(&tw.alphaReg)
	r2Aff.FromJacobian(&r2Jac)
	for i := 0; i < nbWires; i++ {
		pk.G1.A[i] = r1Aff
		pk.G1.B[i] = r1Aff
		pk.G2.B[i] = r2Aff
	}
	for i := 0; i < len(pk.G1.Z); i++ {
		pk.G1.Z[i] = r1Aff
	}
	for i := 0; i < len(pk.G1.K); i++ {
		pk.G1.K[i] = r1Aff
	}
	pk.G1.Alpha = r1Aff
	pk.G1.Beta = r1Aff
	pk.G1.Delta = r1Aff
	pk.G2.Beta = r2Aff
	pk.G2.Delta = r2Aff

}

// toxicWaste toxic waste
type toxicWaste struct {

	// Montgomery form of params
	t, alpha, beta, gamma, delta fr.Element

	// Non Montgomery form of params
	alphaReg, betaReg, gammaReg, deltaReg big.Int
}

func sampleToxicWaste() toxicWaste {

	res := toxicWaste{}

	res.t.SetRandom()
	res.alpha.SetRandom()
	res.beta.SetRandom()
	res.gamma.SetRandom()
	res.delta.SetRandom()

	res.alpha.ToBigIntRegular(&res.alphaReg)
	res.beta.ToBigIntRegular(&res.betaReg)
	res.gamma.ToBigIntRegular(&res.gammaReg)
	res.delta.ToBigIntRegular(&res.deltaReg)

	return res
}

func setupToxicWaste(pk *ProvingKey, vk *VerifyingKey, tw toxicWaste) {

	

	var vkG2JacDeltaNeg, vkG2JacGammaNeg curve.G2Jac

	var pkG1Alpha, pkG1Beta, pkG1Delta curve.G1Jac
	var pkG2Beta, pkG2Delta curve.G2Jac

	// sets pk: [α]1, [β]1, [β]2, [δ]1, [δ]2
	pkG1Alpha.ScalarMulByGen(&tw.alphaReg)
	pk.G1.Alpha.FromJacobian(&pkG1Alpha)
	pkG1Beta.ScalarMulByGen(&tw.betaReg)
	pk.G1.Beta.FromJacobian(&pkG1Beta)
	pkG2Beta.ScalarMulByGen(&tw.betaReg)
	pk.G2.Beta.FromJacobian(&pkG2Beta)
	pkG1Delta.ScalarMulByGen(&tw.deltaReg)
	pk.G1.Delta.FromJacobian(&pkG1Delta)
	pkG2Delta.ScalarMulByGen(&tw.deltaReg)
	pk.G2.Delta.FromJacobian(&pkG2Delta)

	// sets vk: -[δ]2, -[γ]2
	vkG2JacDeltaNeg.ScalarMulByGen(&tw.deltaReg)
	vkG2JacGammaNeg.ScalarMulByGen(&tw.gammaReg)

	vkG2JacDeltaNeg.Neg(&vkG2JacDeltaNeg)
	vk.G2.DeltaNeg.FromJacobian(&vkG2JacDeltaNeg)
	vkG2JacGammaNeg.Neg(&vkG2JacGammaNeg)
	vk.G2.GammaNeg.FromJacobian(&vkG2JacGammaNeg)

	vk.E = curve.FinalExponentiation(curve.MillerLoop(pk.G1.Alpha, pk.G2.Beta))

}

func setupWitnessPolynomial(pk *ProvingKey, tw toxicWaste, g *backend_{{toLower .Curve}}.Domain) {

	

	var one fr.Element
	one.SetOne()

	var zdt fr.Element

	zdt.Exp(tw.t, new(big.Int).SetUint64(uint64(g.Cardinality))).
		Sub(&zdt, &one).
		Div(&zdt, &tw.delta) // sets Zdt to Zdt/delta

	Zdt := make([]big.Int, g.Cardinality)
	for i := 0; i < g.Cardinality; i++ {
		zdt.ToBigIntRegular(&Zdt[i])
		zdt.MulAssign(&tw.t)
	}

	// Z(t) = [(t^j*Zd(t) / delta)]
	parallel.Execute( g.Cardinality, func(start, end int) {
		var pkG1Z curve.G1Jac
		for j := start; j < end; j++ {
			pkG1Z.ScalarMulByGen(&Zdt[j])
			pk.G1.Z[j].FromJacobian(&pkG1Z)
		}
	})

}

func setupABC(r1cs *backend_{{toLower .Curve}}.R1CS, g *backend_{{toLower .Curve}}.Domain, tw toxicWaste) (A []fr.Element, B []fr.Element, C []fr.Element) {

	nbWires := r1cs.NbWires

	A = make([]fr.Element, nbWires)
	B = make([]fr.Element, nbWires)
	C = make([]fr.Element, nbWires)

	var one fr.Element
	one.SetOne()

	// evaluation of the i-th lagrange polynomial at t
	var ithLagrangePolt fr.Element

	// L0 = 1/n*(t^n-1)/(t-1), Li+1 = w*Li*(t-w^i)/(t-w^(i+1))
	var w, wi, tmp fr.Element
	w.Set(&g.Generator)
	wi.SetOne()

	// Setting L0
	ithLagrangePolt.Set(&tw.t)
	ithLagrangePolt.Exp(ithLagrangePolt, new(big.Int).SetUint64(uint64(g.Cardinality))).
		Sub(&ithLagrangePolt, &one)
	tmp.Set(&tw.t).Sub(&tmp, &one)
	ithLagrangePolt.Div(&ithLagrangePolt, &tmp).
		Mul(&ithLagrangePolt, &g.CardinalityInv)

	// Constraints
	for _, c := range r1cs.Constraints {

		for _, t := range c.L {
			backend_{{toLower .Curve}}.MulAdd(t, r1cs, &tmp, &ithLagrangePolt,&A[t.ConstraintID()])
		}
		for _, t := range c.R {
			backend_{{toLower .Curve}}.MulAdd(t, r1cs, &tmp, &ithLagrangePolt,&B[t.ConstraintID()])
		}
		for _, t := range c.O {
			backend_{{toLower .Curve}}.MulAdd(t, r1cs, &tmp, &ithLagrangePolt,&C[t.ConstraintID()])
		}

		// Li+1 = w*Li*(t-w^i)/(t-w^(i+1))
		ithLagrangePolt.MulAssign(&w)
		tmp.Sub(&tw.t, &wi)
		ithLagrangePolt.MulAssign(&tmp)
		wi.MulAssign(&w)
		tmp.Sub(&tw.t, &wi)
		ithLagrangePolt.Div(&ithLagrangePolt, &tmp)
	}
	return

}

func setupKeyVectors(A, B, C []fr.Element, pk *ProvingKey, vk *VerifyingKey, tw toxicWaste, r1cs *backend_{{toLower .Curve}}.R1CS) {

	

	// get R1CS nb constraints, wires and public/private inputs
	nbWires := r1cs.NbWires
	publicStartIndex := r1cs.NbWires - r1cs.NbPublicWires
	parallel.Execute( nbWires, func(start, end int) {
		var tt fr.Element
		var pkG1A, pkG1K, vkG1K curve.G1Jac
		var bpkG1A big.Int
		for i := start; i < end; i++ {
			pkG1A.ScalarMulByGen(A[i].ToBigIntRegular(&bpkG1A))
			pk.G1.A[i].FromJacobian(&pkG1A)

			A[i].MulAssign(&tw.beta)
			tt.Mul(&B[i], &tw.alpha)
			A[i].Add(&A[i], &tt).
				Add(&A[i], &C[i])

			if i < publicStartIndex {
				A[i].Div(&A[i], &tw.delta) //.FromMont()
				pkG1K.ScalarMulByGen(A[i].ToBigIntRegular(&bpkG1A))
				pk.G1.K[i].FromJacobian(&pkG1K)
			} else {
				A[i].Div(&A[i], &tw.gamma) //.FromMont()
				vkG1K.ScalarMulByGen(A[i].ToBigIntRegular(&bpkG1A))
				vk.G1.K[i-publicStartIndex].FromJacobian(&vkG1K)
			}
		}
	})

	// Set the points from the coefficients
	parallel.Execute( nbWires, func(start, end int) {
		var pkG1B curve.G1Jac
		var pkG2B curve.G2Jac
		var bB big.Int
		for i := start; i < end; i++ {
			B[i].ToBigIntRegular(&bB)
			pkG1B.ScalarMulByGen(&bB)
			pk.G1.B[i].FromJacobian(&pkG1B)
			pkG2B.ScalarMulByGen(&bB)
			pk.G2.B[i].FromJacobian(&pkG2B)
		}
	})

}


// IsDifferent returns true if provided vk is different than self
// this is used by groth16.Assert to ensure random sampling
func (vk *VerifyingKey) IsDifferent(_other interface{}) bool {
	vk2 := _other.(*VerifyingKey)
	for i := 0; i < len(vk.G1.K); i++ {
		if !vk.G1.K[i].IsInfinity() {
			if vk.G1.K[i].Equal(&vk2.G1.K[i]) {
				return false
			}
		}
	}

	return true
}

// IsDifferent returns true if provided pk is different than self
// this is used by groth16.Assert to ensure random sampling
func (pk *ProvingKey) IsDifferent(_other interface{}) bool {
	pk2 := _other.(*ProvingKey)

	if pk.G1.Alpha.Equal(&pk2.G1.Alpha) ||
	pk.G1.Beta.Equal(&pk2.G1.Beta) || 
	pk.G1.Delta.Equal(&pk2.G1.Delta) {
		return false 
	}

	for i := 0; i < len(pk.G1.K); i++ {
		if !pk.G1.K[i].IsInfinity() {
			if pk.G1.K[i].Equal(&pk2.G1.K[i]) {
				return false
			}
		}
	}

	return true
}


`
