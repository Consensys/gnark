package utils

import (
	"math/big"
	"runtime"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type PublicKey struct {
	SG  bn254.G1Affine
	SXG bn254.G1Affine
	XR  bn254.G2Affine
}

// Returns [1, a, a², ..., aⁿ⁻¹ ] in Montgomery form
func Powers(a fr.Element, n int) []fr.Element {
	result := make([]fr.Element, n)
	result[0] = fr.NewElement(1)
	for i := 1; i < n; i++ {
		result[i].Mul(&result[i-1], &a)
	}
	return result
}

// Returns [aᵢAᵢ, ...] in G1
func ScaleG1(A []bn254.G1Affine, a []fr.Element) []bn254.G1Affine {
	var tmp big.Int
	result := make([]bn254.G1Affine, len(A))
	for i := 0; i < len(A); i++ {
		a[i].BigInt(&tmp)
		result[i].ScalarMultiplication(&A[i], &tmp)
	}
	return result
}

// Returns [aᵢAᵢ, ...] in G2
func ScaleG2(A []bn254.G2Affine, a []fr.Element) []bn254.G2Affine {
	var tmp big.Int
	result := make([]bn254.G2Affine, len(A))
	for i := 0; i < len(A); i++ {
		a[i].BigInt(&tmp)
		result[i].ScalarMultiplication(&A[i], &tmp)
	}
	return result
}

func EvalG1(scalars []fr.Element, points []bn254.G1Affine) *bn254.G1Jac {
	nc := runtime.NumCPU()

	var result bn254.G1Jac
	if _, err := result.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		panic("Failed to MultiExp")
	}
	return &result
}

func EvalG2(scalars []fr.Element, points []bn254.G2Affine) *bn254.G2Jac {
	nc := runtime.NumCPU()

	var result bn254.G2Jac
	if _, err := result.MultiExp(points, scalars, ecc.MultiExpConfig{NbTasks: nc / 2}); err != nil {
		panic("Failed to MultiExp")
	}
	return &result
}

// Check e(a₁, a₂) = e(b₁, b₂)
func SameRatio(a1, b1 bn254.G1Affine, a2, b2 bn254.G2Affine) bool {
	if !a1.IsInSubGroup() || !b1.IsInSubGroup() || !a2.IsInSubGroup() || !b2.IsInSubGroup() {
		panic("invalid point not in subgroup")
	}
	var na2 bn254.G2Affine
	na2.Neg(&a2)
	res, err := bn254.PairingCheck(
		[]bn254.G1Affine{a1, b1},
		[]bn254.G2Affine{na2, b2})
	if err != nil {
		panic(err)
	}
	return res
}

// returnsa = ∑ rᵢAᵢ, b = ∑ rᵢBᵢ
func Merge(A, B []bn254.G1Affine) (a, b bn254.G1Affine) {
	nc := runtime.NumCPU()
	r := make([]fr.Element, len(A))
	for i := 0; i < len(A); i++ {
		r[i].SetRandom()
	}
	a.MultiExp(A, r, ecc.MultiExpConfig{NbTasks: nc / 2})
	b.MultiExp(B, r, ecc.MultiExpConfig{NbTasks: nc / 2})
	return
}

// L1 = ∑ rᵢAᵢ, L2 = ∑ rᵢAᵢ₊₁ in G1
func LinearCombinationG1(A []bn254.G1Affine) (L1, L2 bn254.G1Affine) {
	nc := runtime.NumCPU()
	n := len(A)
	r := make([]fr.Element, n-1)
	for i := 0; i < n-1; i++ {
		r[i].SetRandom()
	}
	L1.MultiExp(A[:n-1], r, ecc.MultiExpConfig{NbTasks: nc / 2})
	L2.MultiExp(A[1:], r, ecc.MultiExpConfig{NbTasks: nc / 2})
	return
}

// L1 = ∑ rᵢAᵢ, L2 = ∑ rᵢAᵢ₊₁ in G2
func LinearCombinationG2(A []bn254.G2Affine) (L1, L2 bn254.G2Affine) {
	nc := runtime.NumCPU()
	n := len(A)
	r := make([]fr.Element, n-1)
	for i := 0; i < n-1; i++ {
		r[i].SetRandom()
	}
	L1.MultiExp(A[:n-1], r, ecc.MultiExpConfig{NbTasks: nc / 2})
	L2.MultiExp(A[1:], r, ecc.MultiExpConfig{NbTasks: nc / 2})
	return
}

// Generate R in G₂ as Hash(gˢ, gˢˣ, challenge, dst)
func GenR(sG1, sxG1 bn254.G1Affine, challenge []byte, dst byte) bn254.G2Affine {
	buffer := append(sG1.Marshal()[:], sxG1.Marshal()...)
	buffer = append(buffer, challenge...)
	spG2, err := bn254.HashToG2(buffer, []byte{dst})
	if err != nil {
		panic(err)
	}
	return spG2
}

func GenPublicKey(x fr.Element, challenge []byte, dst byte) PublicKey {
	var pk PublicKey
	_, _, g1, _ := bn254.Generators()

	var s fr.Element
	var sBi big.Int
	s.SetRandom()
	s.BigInt(&sBi)
	pk.SG.ScalarMultiplication(&g1, &sBi)

	// compute x*sG1
	var xBi big.Int
	x.BigInt(&xBi)
	pk.SXG.ScalarMultiplication(&pk.SG, &xBi)

	// generate R based on sG1, sxG1, challenge, and domain separation tag (tau, alpha or beta)
	R := GenR(pk.SG, pk.SXG, challenge, dst)

	// compute x*spG2
	pk.XR.ScalarMultiplication(&R, &xBi)
	return pk
}
