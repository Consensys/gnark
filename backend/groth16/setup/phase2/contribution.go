package phase2

import (
	"crypto/sha256"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16/setup/phase1"
	utils "github.com/consensys/gnark/backend/groth16/setup/utils"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
)

type Evaluations struct {
	G1 struct {
		A, B, VKK []bn254.G1Affine
	}
	G2 struct {
		B []bn254.G2Affine
	}
}

type Contribution struct {
	Parameters struct {
		G1 struct {
			Delta bn254.G1Affine
			L, Z  []bn254.G1Affine
		}
		G2 struct {
			Delta bn254.G2Affine
		}
	}
	PublicKey utils.PublicKey
	Hash      []byte
}

func (c2 *Contribution) PreparePhase(c1 *phase1.Contribution, r1cs *cs_bn254.R1CS) Evaluations {
	srs := c1.Parameters
	size := len(srs.G1.AlphaTau)
	if size < r1cs.GetNbConstraints() {
		panic("Number of constraints is larger than expected")
	}

	accumulateG1 := func(res *bn254.G1Affine, t constraint.Term, value *bn254.G1Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp bn254.G1Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	accumulateG2 := func(res *bn254.G2Affine, t constraint.Term, value *bn254.G2Affine) {
		cID := t.CoeffID()
		switch cID {
		case constraint.CoeffIdZero:
			return
		case constraint.CoeffIdOne:
			res.Add(res, value)
		case constraint.CoeffIdMinusOne:
			res.Sub(res, value)
		case constraint.CoeffIdTwo:
			res.Add(res, value).Add(res, value)
		default:
			var tmp bn254.G2Affine
			var vBi big.Int
			r1cs.Coefficients[cID].BigInt(&vBi)
			tmp.ScalarMultiplication(value, &vBi)
			res.Add(res, &tmp)
		}
	}

	// Prepare Lagrange coefficients of [τ...]₁, [τ...]₂, [ατ...]₁, [βτ...]₁
	coeffTau1 := utils.LagrangeCoeffsG1(srs.G1.Tau, size)
	coeffTau2 := utils.LagrangeCoeffsG2(srs.G2.Tau, size)
	coeffAlphaTau1 := utils.LagrangeCoeffsG1(srs.G1.AlphaTau, size)
	coeffBetaTau1 := utils.LagrangeCoeffsG1(srs.G1.BetaTau, size)

	internal, secret, public := r1cs.GetNbVariables()
	nWires := internal + secret + public
	var evals Evaluations
	evals.G1.A = make([]bn254.G1Affine, nWires)
	evals.G1.B = make([]bn254.G1Affine, nWires)
	evals.G2.B = make([]bn254.G2Affine, nWires)
	bA := make([]bn254.G1Affine, nWires)
	aB := make([]bn254.G1Affine, nWires)
	C := make([]bn254.G1Affine, nWires)
	for i, c := range r1cs.Constraints {
		// A
		for _, t := range c.L {
			accumulateG1(&evals.G1.A[t.WireID()], t, &coeffTau1[i])
			accumulateG1(&bA[t.WireID()], t, &coeffBetaTau1[i])
		}
		// B
		for _, t := range c.R {
			accumulateG1(&evals.G1.B[t.WireID()], t, &coeffTau1[i])
			accumulateG2(&evals.G2.B[t.WireID()], t, &coeffTau2[i])
			accumulateG1(&aB[t.WireID()], t, &coeffAlphaTau1[i])
		}
		// C
		for _, t := range c.O {
			accumulateG1(&C[t.WireID()], t, &coeffTau1[i])
		}
	}

	// Prepare default contribution
	_, _, g1, g2 := bn254.Generators()
	c2.Parameters.G1.Delta = g1
	c2.Parameters.G2.Delta = g2

	// Build Z in PK as τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	// τⁱ(τⁿ - 1)  = τ⁽ⁱ⁺ⁿ⁾ - τⁱ  for i ∈ [0, n-2]
	n := len(srs.G1.AlphaTau)
	c2.Parameters.G1.Z = make([]bn254.G1Affine, n)
	for i := 0; i < n-1; i++ {
		c2.Parameters.G1.Z[i].Sub(&srs.G1.Tau[i+n], &srs.G1.Tau[i])
	}
	// this is an extra point that is added for the sake of being compatible with gnark setup
	// evenutally it is multiplied by zero, hence it won't affect the resutl
	c2.Parameters.G1.Z[n-1].Set(&g1)

	// Evaluate L
	nPrivate := internal + secret
	c2.Parameters.G1.L = make([]bn254.G1Affine, nPrivate)
	evals.G1.VKK = make([]bn254.G1Affine, public)
	offset := public
	for i := 0; i < nWires; i++ {
		var tmp bn254.G1Affine
		tmp.Add(&bA[i], &aB[i])
		tmp.Add(&tmp, &C[i])
		if i < public {
			evals.G1.VKK[i].Set(&tmp)
		} else {
			c2.Parameters.G1.L[i-offset].Set(&tmp)
		}
	}
	// Set δ public key
	var delta fr.Element
	delta.SetOne()
	c2.PublicKey = utils.GenPublicKey(delta, nil, 1)

	// Hash initial contribution
	c2.Hash = HashContribution(c2)
	return evals
}

func (c *Contribution) Contribute(prev *Contribution) {
	// Sample toxic δ
	var delta, deltaInv fr.Element
	var deltaBI, deltaInvBI big.Int
	delta.SetRandom()
	deltaInv.Inverse(&delta)

	delta.BigInt(&deltaBI)
	deltaInv.BigInt(&deltaInvBI)

	// Set δ public key
	c.PublicKey = utils.GenPublicKey(delta, prev.Hash, 1)

	// Update δ
	c.Parameters.G1.Delta.ScalarMultiplication(&prev.Parameters.G1.Delta, &deltaBI)
	c.Parameters.G2.Delta.ScalarMultiplication(&prev.Parameters.G2.Delta, &deltaBI)

	// Update Z using δ⁻¹
	c.Parameters.G1.Z = make([]bn254.G1Affine, len(prev.Parameters.G1.Z))
	for i := 0; i < len(prev.Parameters.G1.Z); i++ {
		c.Parameters.G1.Z[i].ScalarMultiplication(&prev.Parameters.G1.Z[i], &deltaInvBI)
	}

	// Update Z using δ⁻¹
	c.Parameters.G1.L = make([]bn254.G1Affine, len(prev.Parameters.G1.L))
	for i := 0; i < len(prev.Parameters.G1.L); i++ {
		c.Parameters.G1.L[i].ScalarMultiplication(&prev.Parameters.G1.L[i], &deltaInvBI)
	}

	// 4. Hash contribution
	c.Hash = HashContribution(c)
}

func HashContribution(c *Contribution) []byte {
	sha := sha256.New()
	// Hash contribution
	toEncode := []interface{}{
		&c.PublicKey.SG,
		&c.PublicKey.SXG,
		&c.PublicKey.XR,
		&c.Parameters.G1.Delta,
		c.Parameters.G1.L,
		c.Parameters.G1.Z,
		&c.Parameters.G2.Delta,
	}

	enc := bn254.NewEncoder(sha)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			panic(err)
		}
	}
	return sha.Sum(nil)
}
