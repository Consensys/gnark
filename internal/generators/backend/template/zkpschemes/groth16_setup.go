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
	gateGroup := backend_{{toLower .Curve}}.NewDomain(root, backend_{{toLower .Curve}}.MaxOrder, nbConstraints)

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

// toxicWaste toxic waste
type toxicWaste struct {

	// Montgomery form of params
	t, alpha, beta, gamma, delta fr.Element

	// Non Montgomery form of params
	alphaReg, betaReg, gammaReg, deltaReg fr.Element
}

func sampleToxicWaste() toxicWaste {

	res := toxicWaste{}

	res.t.SetRandom()
	res.alpha.SetRandom()
	res.beta.SetRandom()
	res.gamma.SetRandom()
	res.delta.SetRandom()

	res.alphaReg = res.alpha.ToRegular()
	res.betaReg = res.beta.ToRegular()
	res.gammaReg = res.gamma.ToRegular()
	res.deltaReg = res.delta.ToRegular()

	return res
}

func setupToxicWaste(pk *ProvingKey, vk *VerifyingKey, tw toxicWaste) {

	c := {{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}

	var vkG2JacDeltaNeg, vkG2JacGammaNeg curve.G2Jac

	var pkG1Alpha, pkG1Beta, pkG1Delta curve.G1Jac
	var pkG2Beta, pkG2Delta curve.G2Jac

	// sets pk: [α]1, [β]1, [β]2, [δ]1, [δ]2
	pkG1Alpha.ScalarMulByGen(c, tw.alphaReg).ToAffineFromJac(&pk.G1.Alpha)
	pkG1Beta.ScalarMulByGen(c, tw.betaReg).ToAffineFromJac(&pk.G1.Beta)
	pkG2Beta.ScalarMulByGen(c, tw.betaReg).ToAffineFromJac(&pk.G2.Beta)
	pkG1Delta.ScalarMulByGen(c, tw.deltaReg).ToAffineFromJac(&pk.G1.Delta)
	pkG2Delta.ScalarMulByGen(c, tw.deltaReg).ToAffineFromJac(&pk.G2.Delta)

	// sets vk: -[δ]2, -[γ]2
	vkG2JacDeltaNeg.ScalarMulByGen(c, tw.deltaReg)
	vkG2JacGammaNeg.ScalarMulByGen(c, tw.gammaReg)

	vkG2JacDeltaNeg.Neg(&vkG2JacDeltaNeg).
		ToAffineFromJac(&vk.G2.DeltaNeg)
	vkG2JacGammaNeg.Neg(&vkG2JacGammaNeg).
		ToAffineFromJac(&vk.G2.GammaNeg)

	vk.E = c.FinalExponentiation(c.MillerLoop(pk.G1.Alpha, pk.G2.Beta, &vk.E))

}

func setupWitnessPolynomial(pk *ProvingKey, tw toxicWaste, g *backend_{{toLower .Curve}}.Domain) {

	c := {{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}

	var one fr.Element
	one.SetOne()

	var zdt fr.Element

	zdt.Exp(tw.t, uint64(g.Cardinality)).
		Sub(&zdt, &one).
		Div(&zdt, &tw.delta) // sets Zdt to Zdt/delta

	Zdt := make([]fr.Element, g.Cardinality)
	for i := 0; i < g.Cardinality; i++ {
		Zdt[i] = zdt.ToRegular()
		zdt.MulAssign(&tw.t)
	}

	// Z(t) = [(t^j*Zd(t) / delta)]
	parallel.Execute( g.Cardinality, func(start, end int) {
		var pkG1Z curve.G1Jac
		for j := start; j < end; j++ {
			pkG1Z.ScalarMulByGen(c, Zdt[j])
			pkG1Z.ToAffineFromJac(&pk.G1.Z[j])
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
	ithLagrangePolt.Exp(ithLagrangePolt, uint64(g.Cardinality)).
		Sub(&ithLagrangePolt, &one)
	tmp.Set(&tw.t).Sub(&tmp, &one)
	ithLagrangePolt.Div(&ithLagrangePolt, &tmp).
		Mul(&ithLagrangePolt, &g.CardinalityInv)

	// Constraints
	for _, c := range r1cs.Constraints {

		for _, t := range c.L {
			tmp.Mul(&ithLagrangePolt, &t.Coeff)
			A[t.ID].Add(&A[t.ID], &tmp)
		}
		for _, t := range c.R {
			tmp.Mul(&ithLagrangePolt, &t.Coeff)
			B[t.ID].Add(&B[t.ID], &tmp)
		}
		for _, t := range c.O {
			tmp.Mul(&ithLagrangePolt, &t.Coeff)
			C[t.ID].Add(&C[t.ID], &tmp)
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

	c := {{- if eq .Curve "GENERIC"}}curve.GetCurve(){{- else}}curve.{{.Curve}}(){{- end}}

	// get R1CS nb constraints, wires and public/private inputs
	nbWires := r1cs.NbWires
	publicStartIndex := r1cs.NbWires - r1cs.NbPublicWires
	parallel.Execute( nbWires, func(start, end int) {
		var tt fr.Element
		var pkG1A, pkG1K, vkG1K curve.G1Jac
		for i := start; i < end; i++ {

			pkG1A.ScalarMulByGen(c, A[i].ToRegular()).
				ToAffineFromJac(&pk.G1.A[i])

			A[i].MulAssign(&tw.beta)
			tt.Mul(&B[i], &tw.alpha)
			A[i].Add(&A[i], &tt).
				Add(&A[i], &C[i])

			if i < publicStartIndex {
				A[i].Div(&A[i], &tw.delta).FromMont()
				pkG1K.ScalarMulByGen(c, A[i]).
					ToAffineFromJac(&pk.G1.K[i])
			} else {
				A[i].Div(&A[i], &tw.gamma).FromMont()
				vkG1K.ScalarMulByGen(c, A[i]).ToAffineFromJac(&vk.G1.K[i-publicStartIndex])
			}
		}
	})

	// Set the points from the coefficients
	parallel.Execute( nbWires, func(start, end int) {
		var pkG1B curve.G1Jac
		var pkG2B curve.G2Jac
		for i := start; i < end; i++ {
			B[i].FromMont()
			pkG1B.ScalarMulByGen(c, B[i]).
				ToAffineFromJac(&pk.G1.B[i])
			pkG2B.ScalarMulByGen(c, B[i]).
				ToAffineFromJac(&pk.G2.B[i])
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
