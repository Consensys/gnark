/*
Copyright © 2020 ConsenSys

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package groth16 exposes zkSNARK (Groth16) 3 algorithms: Setup, Prove and Verify
package groth16

import (
	"github.com/consensys/gnark/cs"
	"github.com/consensys/gnark/cs/fft"
	ecc "github.com/consensys/gnark/cs/internal/curve"
	"github.com/consensys/gnark/internal/pool"
)

// ProvingKey is used by a Groth16 prover to encode a proof of a statement
type ProvingKey struct {
	// [α]1, [β]1, [δ]1
	// [A(t)]1, [B(t)]1, [Kpk(t)]1, [Z(t)]1
	G1 struct {
		Alpha, Beta, Delta ecc.G1Affine
		A, B, Z            []ecc.G1Affine
		K                  []ecc.G1Affine // the indexes correspond to the private wires
	}

	// [β]2, [δ]2, [B(t)]2
	G2 struct {
		Beta, Delta ecc.G2Affine
		B           []ecc.G2Affine
	}
}

// VerifyingKey is used by a Groth16 verifier to verify the validity of a proof and a statement
type VerifyingKey struct {
	// e(α, β)
	E ecc.PairingResult

	// -[γ]2, -[δ]2
	// note: storing GammaNeg and DeltaNeg instead of Gamma and Delta
	// see proof.Verify() for more details
	G2 struct {
		GammaNeg, DeltaNeg ecc.G2Affine
	}

	// [Kvk]1
	G1 struct {
		K []ecc.G1Affine // The indexes correspond to the public wires
	}

	PublicInputsTracker []string // maps the name of the public input
}

// Setup constructs the SRS
func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *VerifyingKey) {

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
	nbWires := len(r1cs.WireTracker)
	nbPrivateWires := r1cs.PublicInputsStartIndex
	nbPublicWires := nbWires - nbPrivateWires
	nbConstraints := r1cs.NbConstraints()

	// Setting group for fft
	gateGroup := fft.NewSubGroup(root, ecc.MaxOrder, nbConstraints)

	// initialize proving key
	pk.G1.A = make([]ecc.G1Affine, nbWires)
	pk.G1.B = make([]ecc.G1Affine, nbWires)
	pk.G1.K = make([]ecc.G1Affine, nbPrivateWires)
	pk.G1.Z = make([]ecc.G1Affine, gateGroup.Cardinality)
	pk.G2.B = make([]ecc.G2Affine, nbWires)

	// initialize verifying key
	vk.G1.K = make([]ecc.G1Affine, nbPublicWires)

	// samples toxic waste
	toxicWaste := sampleToxicWaste()

	// Set the public input map
	setupPublicInputTracker(r1cs, vk)

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
	t, alpha, beta, gamma, delta ecc.Element

	// Non Montgomery form of params
	alphaReg, betaReg, gammaReg, deltaReg ecc.Element
}

func setupPublicInputTracker(r1cs *cs.R1CS, vk *VerifyingKey) {

	nbPublicInputs := len(r1cs.WireTracker) - r1cs.PublicInputsStartIndex
	vk.PublicInputsTracker = make([]string, nbPublicInputs)

	for i := 0; i < nbPublicInputs; i++ {
		vk.PublicInputsTracker[i] = r1cs.WireTracker[i+r1cs.PublicInputsStartIndex].Name
	}

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

	curve := ecc.GetCurve()

	var vkG2JacDeltaNeg, vkG2JacGammaNeg ecc.G2Jac

	var pkG1Alpha, pkG1Beta, pkG1Delta ecc.G1Jac
	var pkG2Beta, pkG2Delta ecc.G2Jac

	// sets pk: [α]1, [β]1, [β]2, [δ]1, [δ]2
	pkG1Alpha.ScalarMulByGen(curve, tw.alphaReg).ToAffineFromJac(&pk.G1.Alpha)
	pkG1Beta.ScalarMulByGen(curve, tw.betaReg).ToAffineFromJac(&pk.G1.Beta)
	pkG2Beta.ScalarMulByGen(curve, tw.betaReg).ToAffineFromJac(&pk.G2.Beta)
	pkG1Delta.ScalarMulByGen(curve, tw.deltaReg).ToAffineFromJac(&pk.G1.Delta)
	pkG2Delta.ScalarMulByGen(curve, tw.deltaReg).ToAffineFromJac(&pk.G2.Delta)

	// sets vk: -[δ]2, -[γ]2
	vkG2JacDeltaNeg.ScalarMulByGen(curve, tw.deltaReg)
	vkG2JacGammaNeg.ScalarMulByGen(curve, tw.gammaReg)

	vkG2JacDeltaNeg.Neg(&vkG2JacDeltaNeg).
		ToAffineFromJac(&vk.G2.DeltaNeg)
	vkG2JacGammaNeg.Neg(&vkG2JacGammaNeg).
		ToAffineFromJac(&vk.G2.GammaNeg)

	vk.E = curve.FinalExponentiation(curve.MillerLoop(pk.G1.Alpha, pk.G2.Beta, &vk.E))

}

func setupWitnessPolynomial(pk *ProvingKey, tw toxicWaste, g *fft.SubGroup) {

	curve := ecc.GetCurve()

	var one ecc.Element
	one.SetOne()

	var zdt ecc.Element

	zdt.Exp(tw.t, uint64(g.Cardinality)).
		Sub(&zdt, &one).
		Div(&zdt, &tw.delta) // sets Zdt to Zdt/delta

	Zdt := make([]ecc.Element, g.Cardinality)
	for i := 0; i < g.Cardinality; i++ {
		Zdt[i] = zdt.ToRegular()
		zdt.MulAssign(&tw.t)
	}

	// Z(t) = [(t^j*Zd(t) / delta)]
	pool.Execute(0, g.Cardinality, func(start, end int) {
		var pkG1Z ecc.G1Jac
		for j := start; j < end; j++ {
			pkG1Z.ScalarMulByGen(curve, Zdt[j])
			pkG1Z.ToAffineFromJac(&pk.G1.Z[j])
		}
	}, false)

}

func setupABC(r1cs *cs.R1CS, g *fft.SubGroup, tw toxicWaste) (A []ecc.Element, B []ecc.Element, C []ecc.Element) {

	nbWires := len(r1cs.WireTracker)

	A = make([]ecc.Element, nbWires)
	B = make([]ecc.Element, nbWires)
	C = make([]ecc.Element, nbWires)

	var one ecc.Element
	one.SetOne()

	// evaluation of the i-th lagrange polynomial at t
	var ithLagrangePolt ecc.Element

	// L0 = 1/n*(t^n-1)/(t-1), Li+1 = w*Li*(t-w^i)/(t-w^(i+1))
	var w, wi, tmp ecc.Element
	w.Set(&g.Generator)
	wi.SetOne()

	// Setting L0
	ithLagrangePolt.Set(&tw.t)
	ithLagrangePolt.Exp(ithLagrangePolt, uint64(g.Cardinality)).
		Sub(&ithLagrangePolt, &one)
	tmp.Set(&tw.t).Sub(&tmp, &one)
	ithLagrangePolt.Div(&ithLagrangePolt, &tmp).
		Mul(&ithLagrangePolt, &g.CardinalityInv)

	// Computational constraints
	for _, c := range r1cs.ComputationalGraph {

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

	// Other constraints
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

func setupKeyVectors(A, B, C []ecc.Element, pk *ProvingKey, vk *VerifyingKey, tw toxicWaste, r1cs *cs.R1CS) {

	curve := ecc.GetCurve()

	// get R1CS nb constraints, wires and public/private inputs
	nbWires := len(r1cs.WireTracker)
	nbPrivateWires := r1cs.PublicInputsStartIndex

	pool.Execute(0, nbWires, func(start, end int) {
		var tt ecc.Element
		var pkG1A, pkG1K, vkG1K ecc.G1Jac
		for i := start; i < end; i++ {

			pkG1A.ScalarMulByGen(curve, A[i].ToRegular()).
				ToAffineFromJac(&pk.G1.A[i])

			A[i].MulAssign(&tw.beta)
			tt.Mul(&B[i], &tw.alpha)
			A[i].Add(&A[i], &tt).
				Add(&A[i], &C[i])

			if i < nbPrivateWires {
				A[i].Div(&A[i], &tw.delta).FromMont()
				pkG1K.ScalarMulByGen(curve, A[i]).
					ToAffineFromJac(&pk.G1.K[i])
			} else {
				A[i].Div(&A[i], &tw.gamma).FromMont()
				vkG1K.ScalarMulByGen(curve, A[i]).ToAffineFromJac(&vk.G1.K[i-nbPrivateWires])
			}
		}
	}, false)

	// Set the points from the coefficients
	pool.Execute(0, nbWires, func(start, end int) {
		var pkG1B ecc.G1Jac
		var pkG2B ecc.G2Jac
		for i := start; i < end; i++ {
			B[i].FromMont()
			pkG1B.ScalarMulByGen(curve, B[i]).
				ToAffineFromJac(&pk.G1.B[i])
			pkG2B.ScalarMulByGen(curve, B[i]).
				ToAffineFromJac(&pk.G2.B[i])
		}
	}, false)

}
