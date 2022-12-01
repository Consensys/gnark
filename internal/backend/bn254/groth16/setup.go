// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by gnark DO NOT EDIT

package groth16

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/pedersen"
	"github.com/consensys/gnark/frontend/compiled"
	"github.com/consensys/gnark/internal/backend/bn254/cs"
	"math/big"
	"math/bits"
)

// ProvingKey is used by a Groth16 prover to encode a proof of a statement
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type ProvingKey struct {
	// domain
	Domain fft.Domain

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

	// if InfinityA[i] == true, the point G1.A[i] == infinity
	InfinityA, InfinityB     []bool
	NbInfinityA, NbInfinityB uint64

	CommitmentKey pedersen.Key
}

// VerifyingKey is used by a Groth16 verifier to verify the validity of a proof and a statement
// Notation follows Figure 4. in DIZK paper https://eprint.iacr.org/2018/691.pdf
type VerifyingKey struct {
	// [α]1, [Kvk]1
	G1 struct {
		Alpha       curve.G1Affine
		Beta, Delta curve.G1Affine   // unused, here for compatibility purposes
		K           []curve.G1Affine // The indexes correspond to the public wires
	}

	// [β]2, [δ]2, [γ]2,
	// -[δ]2, -[γ]2: see proof.Verify() for more details
	G2 struct {
		Beta, Delta, Gamma curve.G2Affine
		deltaNeg, gammaNeg curve.G2Affine // not serialized
	}

	// e(α, β)
	e              curve.GT // not serialized
	CommitmentKey  pedersen.Key
	CommitmentInfo compiled.Info // since the verifier doesn't input a constraint system, this needs to be provided here
}

// Setup constructs the SRS
func Setup(r1cs *cs.R1CS, pk *ProvingKey, vk *VerifyingKey) error {
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
	nbWires := r1cs.NbInternalVariables + r1cs.NbPublicVariables + r1cs.NbSecretVariables

	nbPrivateCommittedWires := r1cs.CommitmentInfo.NbPrivateCommitted()
	nbPublicWires := r1cs.NbPublicVariables
	nbPrivateWires := r1cs.NbSecretVariables + r1cs.NbInternalVariables - nbPrivateCommittedWires

	if r1cs.CommitmentInfo.Is() { // the commitment itself is defined by a hint so the prover considers it private
		nbPublicWires++  // but the verifier will need to inject the value itself so on the groth16
		nbPrivateWires-- // level it must be considered public
	}

	// Setting group for fft
	domain := fft.NewDomain(uint64(len(r1cs.Constraints)))

	// samples toxic waste
	toxicWaste, err := sampleToxicWaste()
	if err != nil {
		return err
	}

	// Setup coeffs to compute pk.G1.A, pk.G1.B, pk.G1.K
	A, B, C := setupABC(r1cs, domain, toxicWaste)

	// To fill in the Proving and Verifying keys, we need to perform a lot of ecc scalar multiplication (with generator)
	// and convert the resulting points to affine
	// this is done using the curve.BatchScalarMultiplicationGX API, which takes as input the base point
	// (in our case the generator) and the list of scalars, and outputs a list of points (len(points) == len(scalars))
	// to use this batch call, we need to order our scalars in the same slice
	// we have 1 batch call for G1 and 1 batch call for G1
	// scalars are fr.Element in non montgomery form
	_, _, g1, g2 := curve.Generators()

	// ---------------------------------------------------------------------------------------------
	// G1 scalars

	// the G1 scalars are ordered (arbitrary) as follows:
	//
	// [[α], [β], [δ], [A(i)], [B(i)], [pk.K(i)], [Z(i)], [vk.K(i)]]
	// len(A) == len(B) == nbWires
	// len(pk.K) == nbPrivateWires
	// len(vk.K) == nbPublicWires
	// len(Z) == domain.Cardinality

	// compute scalars for pkK, vkK and ckK
	pkK := make([]fr.Element, nbPrivateWires)
	vkK := make([]fr.Element, nbPublicWires)
	ckK := make([]fr.Element, nbPrivateCommittedWires)

	var t0, t1 fr.Element

	vI, cI := 0, 0

	computeK := func(i int, coeff *fr.Element) { // TODO: Inline again
		t1.Mul(&A[i], &toxicWaste.beta)
		t0.Mul(&B[i], &toxicWaste.alpha)
		t1.Add(&t1, &t0).
			Add(&t1, &C[i]).
			Mul(&t1, coeff)
	}

	privateCommitted := r1cs.CommitmentInfo.GetPrivateCommitted()

	for i := range A {
		isCommittedPrivate := cI < len(privateCommitted) && i == privateCommitted[cI]
		isCommitment := r1cs.CommitmentInfo.Is() && i == r1cs.CommitmentInfo.CommitmentIndex
		isPublic := i < r1cs.NbPublicVariables

		if isPublic || isCommittedPrivate || isCommitment {
			computeK(i, &toxicWaste.gammaInv)

			if isCommittedPrivate {
				ckK[cI] = t1.ToRegular()
				cI++
			} else {
				vkK[vI] = t1.ToRegular()
				vI++
			}
		} else {
			computeK(i, &toxicWaste.deltaInv)
			pkK[i-vI-cI] = t1.ToRegular()
		}
	}

	// convert A and B to regular form
	for i := 0; i < nbWires; i++ {
		A[i].FromMont()
	}
	for i := 0; i < nbWires; i++ {
		B[i].FromMont()
	}

	// Z part of the proving key (scalars)
	Z := make([]fr.Element, domain.Cardinality)
	one := fr.One()
	var zdt fr.Element

	zdt.Exp(toxicWaste.t, new(big.Int).SetUint64(domain.Cardinality)).
		Sub(&zdt, &one).
		Mul(&zdt, &toxicWaste.deltaInv) // sets Zdt to Zdt/delta

	for i := 0; i < int(domain.Cardinality); i++ {
		Z[i] = zdt.ToRegular()
		zdt.Mul(&zdt, &toxicWaste.t)
	}

	// mark points at infinity and filter them
	pk.InfinityA = make([]bool, len(A))
	pk.InfinityB = make([]bool, len(B))

	n := 0
	for i, e := range A {
		if e.IsZero() {
			pk.InfinityA[i] = true
			continue
		}
		A[n] = A[i]
		n++
	}
	A = A[:n]
	pk.NbInfinityA = uint64(nbWires - n)
	n = 0
	for i, e := range B {
		if e.IsZero() {
			pk.InfinityB[i] = true
			continue
		}
		B[n] = B[i]
		n++
	}
	B = B[:n]
	pk.NbInfinityB = uint64(nbWires - n)

	// compute our batch scalar multiplication with g1 elements
	g1Scalars := make([]fr.Element, 0, (nbWires*3)+int(domain.Cardinality)+3)
	g1Scalars = append(g1Scalars, toxicWaste.alphaReg, toxicWaste.betaReg, toxicWaste.deltaReg)
	g1Scalars = append(g1Scalars, A...)
	g1Scalars = append(g1Scalars, B...)
	g1Scalars = append(g1Scalars, Z...)
	g1Scalars = append(g1Scalars, vkK...)
	g1Scalars = append(g1Scalars, pkK...)
	g1Scalars = append(g1Scalars, ckK...)

	g1PointsAff := curve.BatchScalarMultiplicationG1(&g1, g1Scalars)

	// sets pk: [α]1, [β]1, [δ]1
	pk.G1.Alpha = g1PointsAff[0]
	pk.G1.Beta = g1PointsAff[1]
	pk.G1.Delta = g1PointsAff[2]

	offset := 3
	pk.G1.A = g1PointsAff[offset : offset+len(A)]
	offset += len(A)

	pk.G1.B = g1PointsAff[offset : offset+len(B)]
	offset += len(B)

	pk.G1.Z = g1PointsAff[offset : offset+int(domain.Cardinality)]
	bitReverse(pk.G1.Z)

	offset += int(domain.Cardinality)

	// ---------------------------------------------------------------------------------------------
	// Commitment setup

	vk.G1.K = g1PointsAff[offset : offset+nbPublicWires]
	offset += nbPublicWires
	pk.G1.K = g1PointsAff[offset : offset+nbPrivateWires]
	offset += nbPrivateWires

	if nbPrivateCommittedWires != 0 {

		commitmentBasis := g1PointsAff[offset:]

		vk.CommitmentKey, err = pedersen.Setup(commitmentBasis)
		if err != nil {
			return err
		}
		pk.CommitmentKey = vk.CommitmentKey

	}

	vk.CommitmentInfo = r1cs.CommitmentInfo // unfortunate but necessary

	// ---------------------------------------------------------------------------------------------
	// G2 scalars

	// the G2 scalars are ordered as follow:
	//
	// [[B(i)], [β], [δ], [γ]]
	// len(B) == nbWires

	// compute our batch scalar multiplication with g2 elements
	g2Scalars := append(B, toxicWaste.betaReg, toxicWaste.deltaReg, toxicWaste.gammaReg)

	g2PointsAff := curve.BatchScalarMultiplicationG2(&g2, g2Scalars)

	pk.G2.B = g2PointsAff[:len(B)]

	// sets pk: [β]2, [δ]2
	pk.G2.Beta = g2PointsAff[len(B)+0]
	pk.G2.Delta = g2PointsAff[len(B)+1]

	// sets vk: [δ]2, [γ]2, -[δ]2, -[γ]2
	vk.G2.Delta = g2PointsAff[len(B)+1]
	vk.G2.Gamma = g2PointsAff[len(B)+2]
	vk.G2.deltaNeg.Neg(&vk.G2.Delta)
	vk.G2.gammaNeg.Neg(&vk.G2.Gamma)

	// ---------------------------------------------------------------------------------------------
	// Pairing: vk.e
	vk.G1.Alpha = pk.G1.Alpha
	vk.G2.Beta = pk.G2.Beta

	// unused, here for compatibility purposes
	vk.G1.Beta = pk.G1.Beta
	vk.G1.Delta = pk.G1.Delta

	vk.e, err = curve.Pair([]curve.G1Affine{pk.G1.Alpha}, []curve.G2Affine{pk.G2.Beta})
	if err != nil {
		return err
	}
	// set domain
	pk.Domain = *domain

	return nil
}

func setupABC(r1cs *cs.R1CS, domain *fft.Domain, toxicWaste toxicWaste) (A []fr.Element, B []fr.Element, C []fr.Element) {

	nbWires := r1cs.NbInternalVariables + r1cs.NbPublicVariables + r1cs.NbSecretVariables

	A = make([]fr.Element, nbWires)
	B = make([]fr.Element, nbWires)
	C = make([]fr.Element, nbWires)

	one := fr.One()

	// first we compute [t-w^i] and its inverse
	var w fr.Element
	w.Set(&domain.Generator)
	wi := fr.One()
	t := make([]fr.Element, len(r1cs.Constraints)+1)
	for i := 0; i < len(t); i++ {
		t[i].Sub(&toxicWaste.t, &wi)
		wi.Mul(&wi, &w) // TODO this is already pre computed in fft.Domain
	}
	tInv := fr.BatchInvert(t)

	// evaluation of the i-th lagrange polynomial at t
	var L fr.Element

	// L = 1/n*(t^n-1)/(t-1), Li+1 = w*Li*(t-w^i)/(t-w^(i+1))

	// Setting L0
	L.Exp(toxicWaste.t, new(big.Int).SetUint64(uint64(domain.Cardinality))).
		Sub(&L, &one)
	L.Mul(&L, &tInv[0]).
		Mul(&L, &domain.CardinalityInv)

	fmt.Println("L0 = ", L.Text(10))

	accumulate := func(res *fr.Element, t compiled.Term, value *fr.Element) {
		cID := t.CoeffID()
		switch cID {
		case compiled.CoeffIdZero:
			return
		case compiled.CoeffIdOne:
			res.Add(res, value)
		case compiled.CoeffIdMinusOne:
			res.Sub(res, value)
		case compiled.CoeffIdTwo:
			var buffer fr.Element
			buffer.Double(value)
			res.Add(res, &buffer)
		default:
			var buffer fr.Element
			buffer.Mul(&r1cs.Coefficients[cID], value)
			res.Add(res, &buffer)
		}
	}

	// each constraint is in the form
	// L * R == O
	// L, R and O being linear expressions
	// for each term appearing in the linear expression,
	// we compute term.Coefficient * L, and cumulate it in
	// A, B or C at the index of the variable
	for i, c := range r1cs.Constraints {

		for _, t := range c.L {
			accumulate(&A[t.WireID()], t, &L)
		}
		for _, t := range c.R {
			accumulate(&B[t.WireID()], t, &L)
		}
		for _, t := range c.O {
			accumulate(&C[t.WireID()], t, &L)
		}

		// Li+1 = w*Li*(t-w^i)/(t-w^(i+1))
		L.Mul(&L, &w)
		L.Mul(&L, &t[i])
		L.Mul(&L, &tInv[i+1])
	}
	return

}

// toxicWaste toxic waste
type toxicWaste struct {

	// Montgomery form of params
	t, alpha, beta, gamma, delta fr.Element
	gammaInv, deltaInv           fr.Element

	// Non Montgomery form of params
	alphaReg, betaReg, gammaReg, deltaReg fr.Element
}

func sampleToxicWaste() (toxicWaste, error) {

	res := toxicWaste{}

	for res.t.IsZero() {
		if _, err := res.t.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.alpha.IsZero() {
		if _, err := res.alpha.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.beta.IsZero() {
		if _, err := res.beta.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.gamma.IsZero() {
		if _, err := res.gamma.SetRandom(); err != nil {
			return res, err
		}
	}
	for res.delta.IsZero() {
		if _, err := res.delta.SetRandom(); err != nil {
			return res, err
		}
	}

	res.gammaInv.Inverse(&res.gamma)
	res.deltaInv.Inverse(&res.delta)

	res.alphaReg = res.alpha.ToRegular()
	res.betaReg = res.beta.ToRegular()
	res.gammaReg = res.gamma.ToRegular()
	res.deltaReg = res.delta.ToRegular()

	return res, nil
}

// DummySetup fills a random ProvingKey
// used for test or benchmarking purposes
func DummySetup(r1cs *cs.R1CS, pk *ProvingKey) error {
	// get R1CS nb constraints, wires and public/private inputs
	nbWires := r1cs.NbInternalVariables + r1cs.NbPublicVariables + r1cs.NbSecretVariables
	nbConstraints := len(r1cs.Constraints)

	// Setting group for fft
	domain := fft.NewDomain(uint64(nbConstraints))

	// count number of infinity points we would have had we a normal setup
	// in pk.G1.A, pk.G1.B, and pk.G2.B
	nbZeroesA, nbZeroesB := dummyInfinityCount(r1cs)

	// initialize proving key
	pk.G1.A = make([]curve.G1Affine, nbWires-nbZeroesA)
	pk.G1.B = make([]curve.G1Affine, nbWires-nbZeroesB)
	pk.G1.K = make([]curve.G1Affine, nbWires-r1cs.NbPublicVariables)
	pk.G1.Z = make([]curve.G1Affine, domain.Cardinality)
	pk.G2.B = make([]curve.G2Affine, nbWires-nbZeroesB)

	// set infinity markers
	pk.InfinityA = make([]bool, nbWires)
	pk.InfinityB = make([]bool, nbWires)
	pk.NbInfinityA = uint64(nbZeroesA)
	pk.NbInfinityB = uint64(nbZeroesB)
	for i := 0; i < nbZeroesA; i++ {
		pk.InfinityA[i] = true
	}
	for i := 0; i < nbZeroesB; i++ {
		pk.InfinityB[i] = true
	}

	// samples toxic waste
	toxicWaste, err := sampleToxicWaste()
	if err != nil {
		return err
	}

	var r1Jac curve.G1Jac
	var r1Aff curve.G1Affine
	var b big.Int
	g1, g2, _, _ := curve.Generators()
	r1Jac.ScalarMultiplication(&g1, toxicWaste.alphaReg.ToBigInt(&b))
	r1Aff.FromJacobian(&r1Jac)
	var r2Jac curve.G2Jac
	var r2Aff curve.G2Affine
	r2Jac.ScalarMultiplication(&g2, &b)
	r2Aff.FromJacobian(&r2Jac)
	for i := 0; i < len(pk.G1.A); i++ {
		pk.G1.A[i] = r1Aff
	}
	for i := 0; i < len(pk.G1.B); i++ {
		pk.G1.B[i] = r1Aff
	}
	for i := 0; i < len(pk.G2.B); i++ {
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

	pk.Domain = *domain

	return nil
}

// dummyInfinityCount helps us simulate the number of infinity points we have with the given R1CS
// in A and B as it directly impacts prover performance
func dummyInfinityCount(r1cs *cs.R1CS) (nbZeroesA, nbZeroesB int) {

	nbWires := r1cs.NbInternalVariables + r1cs.NbPublicVariables + r1cs.NbSecretVariables

	A := make([]bool, nbWires)
	B := make([]bool, nbWires)
	for _, c := range r1cs.Constraints {
		for _, t := range c.L {
			A[t.WireID()] = true
		}
		for _, t := range c.R {
			B[t.WireID()] = true
		}
	}
	for i := 0; i < nbWires; i++ {
		if !A[i] {
			nbZeroesA++
		}
		if !B[i] {
			nbZeroesB++
		}
	}
	return

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

// CurveID returns the curveID
func (pk *ProvingKey) CurveID() ecc.ID {
	return curve.ID
}

// CurveID returns the curveID
func (vk *VerifyingKey) CurveID() ecc.ID {
	return curve.ID
}

// NbPublicWitness returns the number of elements in the expected public witness
func (vk *VerifyingKey) NbPublicWitness() int {
	return (len(vk.G1.K) - 1)
}

// NbG1 returns the number of G1 elements in the VerifyingKey
func (vk *VerifyingKey) NbG1() int {
	return 3 + len(vk.G1.K)
}

// NbG2 returns the number of G2 elements in the VerifyingKey
func (vk *VerifyingKey) NbG2() int {
	return 3
}

// NbG1 returns the number of G1 elements in the ProvingKey
func (pk *ProvingKey) NbG1() int {
	return 3 + len(pk.G1.A) + len(pk.G1.B) + len(pk.G1.Z) + len(pk.G1.K)
}

// NbG2 returns the number of G2 elements in the ProvingKey
func (pk *ProvingKey) NbG2() int {
	return 2 + len(pk.G2.B)
}

// bitRerverse permutation as in fft.BitReverse , but with []curve.G1Affine
func bitReverse(a []curve.G1Affine) {
	n := uint(len(a))
	nn := uint(bits.UintSize - bits.TrailingZeros(n))

	for i := uint(0); i < n; i++ {
		irev := bits.Reverse(i) >> nn
		if irev > i {
			a[i], a[irev] = a[irev], a[i]
		}
	}
}
