package phase1

import (
	"crypto/sha256"
	"math"
	"math/big"

	"github.com/consensys/gnark/backend/groth16/setup/utils"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type Contribution struct {
	Parameters struct {
		G1 struct {
			Tau      []bn254.G1Affine // {[τ⁰]₁, [τ¹]₁, [τ²]₁, …, [τ²ⁿ⁻²]₁}
			AlphaTau []bn254.G1Affine // {α[τ⁰]₁, α[τ¹]₁, α[τ²]₁, …, α[τⁿ⁻¹]₁}
			BetaTau  []bn254.G1Affine // {β[τ⁰]₁, β[τ¹]₁, β[τ²]₁, …, β[τⁿ⁻¹]₁}
		}
		G2 struct {
			Tau  []bn254.G2Affine // {[τ⁰]₂, [τ¹]₂, [τ²]₂, …, [τⁿ⁻¹]₂}
			Beta bn254.G2Affine   // [β]₂
		}
	}
	PublicKeys struct {
		Tau, Alpha, Beta utils.PublicKey
	}
	Hash []byte // sha256 hash
}

func (c *Contribution) Initialize(power int) {
	N := int(math.Pow(2, float64(power)))

	// Generate key pairs
	var tau, alpha, beta fr.Element
	tau.SetOne()
	alpha.SetOne()
	beta.SetOne()
	c.PublicKeys.Tau = utils.GenPublicKey(tau, nil, 1)
	c.PublicKeys.Alpha = utils.GenPublicKey(alpha, nil, 2)
	c.PublicKeys.Beta = utils.GenPublicKey(beta, nil, 3)

	// First contribution use generators
	_, _, g1, g2 := bn254.Generators()
	c.Parameters.G2.Beta.Set(&g2)
	c.Parameters.G1.Tau = make([]bn254.G1Affine, 2*N-1)
	c.Parameters.G2.Tau = make([]bn254.G2Affine, N)
	c.Parameters.G1.AlphaTau = make([]bn254.G1Affine, N)
	c.Parameters.G1.BetaTau = make([]bn254.G1Affine, N)
	for i := 0; i < len(c.Parameters.G1.Tau); i++ {
		c.Parameters.G1.Tau[i].Set(&g1)
	}
	for i := 0; i < len(c.Parameters.G2.Tau); i++ {
		c.Parameters.G2.Tau[i].Set(&g2)
		c.Parameters.G1.AlphaTau[i].Set(&g1)
		c.Parameters.G1.BetaTau[i].Set(&g1)
	}

	c.Parameters.G2.Beta.Set(&g2)

	// Compute hash of Contribution
	c.Hash = HashContribution(c)
}

func (c *Contribution) Contribute(prev *Contribution) {
	N := len(prev.Parameters.G2.Tau)

	// Generate key pairs
	var tau, alpha, beta fr.Element
	tau.SetRandom()
	alpha.SetRandom()
	beta.SetRandom()
	c.PublicKeys.Tau = utils.GenPublicKey(tau, prev.Hash[:], 1)
	c.PublicKeys.Alpha = utils.GenPublicKey(alpha, prev.Hash[:], 2)
	c.PublicKeys.Beta = utils.GenPublicKey(beta, prev.Hash[:], 3)

	// Compute powers of τ, ατ, and βτ
	taus := utils.Powers(tau, 2*N-1)
	alphaTau := make([]fr.Element, N)
	betaTau := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		alphaTau[i].Mul(&taus[i], &alpha)
		betaTau[i].Mul(&taus[i], &beta)
	}

	// Update using previous parameters
	c.Parameters.G1.Tau = utils.ScaleG1(prev.Parameters.G1.Tau, taus)
	c.Parameters.G2.Tau = utils.ScaleG2(prev.Parameters.G2.Tau, taus[0:N])
	c.Parameters.G1.AlphaTau = utils.ScaleG1(prev.Parameters.G1.AlphaTau, alphaTau)
	c.Parameters.G1.BetaTau = utils.ScaleG1(prev.Parameters.G1.BetaTau, betaTau)
	var betaBI big.Int
	beta.BigInt(&betaBI)
	c.Parameters.G2.Beta.ScalarMultiplication(&prev.Parameters.G2.Beta, &betaBI)

	// Compute hash of Contribution
	c.Hash = HashContribution(c)
}

func HashContribution(c *Contribution) []byte {
	sha := sha256.New()
	toEncode := []interface{}{
		&c.PublicKeys.Tau.SG,
		&c.PublicKeys.Tau.SXG,
		&c.PublicKeys.Tau.XR,
		&c.PublicKeys.Alpha.SG,
		&c.PublicKeys.Alpha.SXG,
		&c.PublicKeys.Alpha.XR,
		&c.PublicKeys.Beta.SG,
		&c.PublicKeys.Beta.SXG,
		&c.PublicKeys.Beta.XR,
		c.Parameters.G1.Tau,
		c.Parameters.G1.AlphaTau,
		c.Parameters.G1.BetaTau,
		c.Parameters.G2.Tau,
		&c.Parameters.G2.Beta,
	}

	enc := bn254.NewEncoder(sha)
	for _, v := range toEncode {
		if err := enc.Encode(v); err != nil {
			panic(err)
		}
	}
	return sha.Sum(nil)
}
