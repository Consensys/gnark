package keys

import (
	"github.com/consensys/gnark/backend/groth16/setup/phase1"
	"github.com/consensys/gnark/backend/groth16/setup/phase2"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/fft"
	"github.com/consensys/gnark/backend/groth16/setup/utils"
)

type ProvingKey struct {
	Domain fft.Domain
	// [α]₁ , [β]₁, [δ]₁, [A(t)]₁, [B(t)]₁, [Kpk(t)]₁, [Z(t)]₁
	G1 struct {
		Alpha, Beta, Delta bn254.G1Affine
		A, B, Z            []bn254.G1Affine
		K                  []bn254.G1Affine // the indexes correspond to the private wires
	}

	// [β]₂ , [δ]₂, [B(t)]₂
	G2 struct {
		Beta, Delta bn254.G2Affine
		B           []bn254.G2Affine
	}

	// if InfinityA[i] == true, the point G1.A[i] == infinity
	InfinityA, InfinityB     []bool
	NbInfinityA, NbInfinityB uint64
}

type VerifyingKey struct {
	// [α]₁, [Kvk]₁
	G1 struct {
		Alpha, Beta, Delta bn254.G1Affine
		K                  []bn254.G1Affine
	}

	// [β]₂, [δ]₂, [γ]₂,
	G2 struct {
		Beta, Delta, Gamma bn254.G2Affine
	}
}

func ExtractKeys(srs1 *phase1.Contribution, srs2 *phase2.Contribution, evals *phase2.Evaluations, nConstraints int) (pk ProvingKey, vk VerifyingKey) {
	_, _, _, g2 := bn254.Generators()

	// Initialize PK
	pk.Domain = *fft.NewDomain(uint64(nConstraints))
	pk.G1.Alpha.Set(&srs1.Parameters.G1.AlphaTau[0])
	pk.G1.Beta.Set(&srs1.Parameters.G1.BetaTau[0])
	pk.G1.Delta.Set(&srs2.Parameters.G1.Delta)
	pk.G1.Z = srs2.Parameters.G1.Z
	utils.BitReverseG1(pk.G1.Z)

	pk.G1.K = srs2.Parameters.G1.L
	pk.G2.Beta.Set(&srs1.Parameters.G2.Beta)
	pk.G2.Delta.Set(&srs2.Parameters.G2.Delta)

	// Filter out infinity points
	nWires := len(evals.G1.A)
	pk.InfinityA = make([]bool, nWires)
	A := make([]bn254.G1Affine, nWires)
	j := 0
	for i, e := range evals.G1.A {
		if e.IsInfinity() {
			pk.InfinityA[i] = true
			continue
		}
		A[j] = evals.G1.A[i]
		j++
	}
	pk.G1.A = A[:j]
	pk.NbInfinityA = uint64(nWires - j)

	pk.InfinityB = make([]bool, nWires)
	B := make([]bn254.G1Affine, nWires)
	j = 0
	for i, e := range evals.G1.B {
		if e.IsInfinity() {
			pk.InfinityB[i] = true
			continue
		}
		B[j] = evals.G1.B[i]
		j++
	}
	pk.G1.B = B[:j]
	pk.NbInfinityB = uint64(nWires - j)

	B2 := make([]bn254.G2Affine, nWires)
	j = 0
	for i, e := range evals.G2.B {
		if e.IsInfinity() {
			// pk.InfinityB[i] = true should be the same as in B
			continue
		}
		B2[j] = evals.G2.B[i]
		j++
	}
	pk.G2.B = B2[:j]

	// Initialize VK
	vk.G1.Alpha.Set(&srs1.Parameters.G1.AlphaTau[0])
	vk.G1.Beta.Set(&srs1.Parameters.G1.BetaTau[0])
	vk.G1.Delta.Set(&srs2.Parameters.G1.Delta)
	vk.G2.Beta.Set(&srs1.Parameters.G2.Beta)
	vk.G2.Delta.Set(&srs2.Parameters.G2.Delta)
	vk.G2.Gamma.Set(&g2)
	vk.G1.K = evals.G1.VKK

	return pk, vk
}
