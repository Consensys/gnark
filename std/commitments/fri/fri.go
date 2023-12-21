package fri

import (
	"fmt"
	"math/big"
	"math/bits"

	"github.com/consensys/gnark-crypto/ecc"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/hash"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/accumulator/merkle"
)

// same constant as in gnark-crypto
const rho = 8
const logRho = 3
const nbRounds = 1

// Round a single round of interactions between prover and verifier for fri.
type Round struct {

	// interactions series of queries from the verifier, each query is answered with a
	// Merkle proof.
	Interactions [][2]merkle.MerkleProof

	// evaluation stores the evaluation of the fully folded polynomial.
	// The fully folded polynomial is constant, and is evaluated on a
	// a set of size \rho. Since the polynomial is supposed to be constant,
	// only one evaluation, corresponding to the polynomial, is given. Since
	// the prover cannot know in advance which entry the verifier will query,
	// providing a single evaluation (cf gnark-crypto).
	Evaluation frontend.Variable
}

// ProofOfProximity proof of proximity, attesting that
// a function is d-close to a low degree polynomial.
type ProofOfProximity struct {

	// rounds a round consists of completely folding a polynomial using FFT like structure, using
	// challenges sent by the verifier.
	Rounds []Round
}

// radixTwoFri empty structs implementing compressionFunction for
// the squaring function.
type RadixTwoFri struct {

	// hash function that is used for Fiat Shamir and for committing to
	// the oracles.
	h hash.FieldHasher

	// nbSteps number of interactions between the prover and the verifier
	nbSteps int

	// Size of the polynomial. The size of the evaluation domain will be
	// \rho * size.
	size uint64

	// rootDomain generator of the cyclic group of unity of size \rho * size
	genInv big.Int
}

// NewRadixTwoFri creates an FFT-like oracle proof of proximity.
// * h is the hash function that is used for the Merkle proofs
// * gen is the generator of the cyclic group of unity of size \rho * size
func NewRadixTwoFri(size uint64, h hash.FieldHasher, gen big.Int) RadixTwoFri {

	var res RadixTwoFri

	// computing the number of steps
	n := ecc.NextPowerOfTwo(size)
	nbSteps := bits.TrailingZeros(uint(n))
	res.nbSteps = nbSteps
	res.size = size

	// hash function
	res.h = h

	// generator
	res.genInv.Set(&gen)

	return res
}

// verifyProofOfProximitySingleRound verifies the proof of proximity (see gnark-crypto).
func (s RadixTwoFri) verifyProofOfProximitySingleRound(api frontend.API, salt frontend.Variable, proof Round) error {

	// Fiat Shamir transcript to derive the challenges
	// We take care that the namings fit on frSize bytes, to be consistent
	// with the snark circuit, where the names are interpreted as frontend.Variable,
	// with size on FrSize bytes.
	xis := make([]string, s.nbSteps+1)
	for i := 0; i < s.nbSteps; i++ {
		xis[i] = fmt.Sprintf("x%d", i)
	}
	xis[s.nbSteps] = "s0"
	fs := fiatshamir.NewTranscript(api, s.h, xis)
	xi := make([]frontend.Variable, s.nbSteps)

	// the salt is binded to the first challenge, to ensure the challenges
	// are different at each round.
	err := fs.Bind(xis[0], []frontend.Variable{salt})
	if err != nil {
		return err
	}

	for i := 0; i < s.nbSteps; i++ {
		err := fs.Bind(xis[i], []frontend.Variable{proof.Interactions[i][0].RootHash})
		if err != nil {
			return err
		}
		xi[i], err = fs.ComputeChallenge(xis[i])
		if err != nil {
			return err
		}
	}

	// derive the verifier queries. We derive a challenge, and reduce it
	// modulo the size of the domain (=\rho * size) to derive an initial
	// query position.
	err = fs.Bind(xis[s.nbSteps], []frontend.Variable{proof.Evaluation})
	if err != nil {
		return err
	}
	binSeed, err := fs.ComputeChallenge(xis[s.nbSteps])
	if err != nil {
		return err
	}
	bin := api.ToBinary(binSeed)
	bPos := api.FromBinary(bin[:logRho+s.nbSteps]...)

	si, err := api.NewHint(DeriveQueriesPositions, s.nbSteps, bPos, rho*s.size, s.nbSteps)
	if err != nil {
		return err
	}

	// prepare some data for the round checks...
	var accGInv big.Int
	accGInv.Set(&s.genInv)
	even := make([]frontend.Variable, s.nbSteps)
	odd := make([]frontend.Variable, s.nbSteps)
	c := make([]frontend.Variable, s.nbSteps)
	bsi := make([][]frontend.Variable, s.nbSteps)
	for i := 0; i < s.nbSteps; i++ {
		bsi[i] = api.ToBinary(si[i])
		c[i] = bsi[i][0]
		even[i] = api.Sub(si[i], c[i])
		odd[i] = api.Add(si[i], api.Sub(1, c[i]))
	}

	// constrain the query positions: si[i]/2 = f(si[i-1])
	// where f is the permutation sorted -> canonical
	curSize := s.size * rho / 2
	for i := 0; i < s.nbSteps-1; i++ {

		// s <- s_{i}/2
		s := api.FromBinary(bsi[i][1:]...)

		// a <- s_{i+1}/2
		a := api.FromBinary(bsi[i+1][1:]...)

		// b <- f^{-1}(f(s_{i+1})/2) where f : i -> curSize-1-i (it flips the order of the slice [x ... x] of size curSize)
		b := api.Sub(curSize-1, si[i+1])
		cc := api.ToBinary(b)
		b = api.FromBinary(cc[1:]...)
		b = api.Sub(curSize-1, b)
		u := api.Select(bsi[i+1][0], b, a)

		api.AssertIsEqual(u, s)
		curSize = curSize / 2
	}

	// for each round check the Merkle proof and the correctness of the folding
	for i := 0; i < s.nbSteps; i++ {

		// Merkle proofs
		proof.Interactions[i][0].VerifyProof(api, s.h, even[i])
		proof.Interactions[i][1].VerifyProof(api, s.h, odd[i])

		// correctness of the folding
		if i < s.nbSteps-1 {

			// g <- g^{si/2}
			g := exp(api, accGInv, bsi[i][1:])

			// solve the system...
			l := proof.Interactions[i][0].Path[0]
			r := proof.Interactions[i][1].Path[0]
			fe := api.Add(l, r)
			fo := api.Mul(api.Sub(l, r), g)
			fo = api.Div(api.Add(api.Mul(fo, xi[i]), fe), 2)

			// compute the folding
			ln := proof.Interactions[i+1][0].Path[0]
			rn := proof.Interactions[i+1][1].Path[0]
			fn := api.Select(c[i+1], rn, ln)
			api.AssertIsEqual(fn, fo)

			// accGinv <- accGinv^{2}
			accGInv.Mul(&accGInv, &accGInv).
				Mod(&accGInv, api.Compiler().Field())
		}
	}

	// last transition
	l := proof.Interactions[s.nbSteps-1][0].Path[0]
	r := proof.Interactions[s.nbSteps-1][1].Path[0]

	// g <- g^{si/2}
	g := exp(api, accGInv, bsi[s.nbSteps-1][1:])

	// solve the system and compute the last folding
	fe := api.Add(l, r)
	fo := api.Mul(api.Sub(l, r), g)
	fo = api.Mul(fo, xi[s.nbSteps-1])
	fo = api.Div(api.Add(fo, fe), 2)

	api.AssertIsEqual(fo, proof.Evaluation)

	return nil
}

// VerifyProofOfProximity verifies the proof, by checking each interaction one
// by one.
func (s RadixTwoFri) VerifyProofOfProximity(api frontend.API, proof ProofOfProximity) error {
	for i := 0; i < nbRounds; i++ {
		err := s.verifyProofOfProximitySingleRound(api, i, proof.Rounds[i])
		if err != nil {
			return err
		}
	}
	return nil
}
