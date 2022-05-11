package fri

import (
	"fmt"
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
	h hash.Hash

	// nbSteps number of interactions between the prover and the verifier
	nbSteps int

	// Size of the polynomial. The size of the evaluation domain will be
	// \rho * size.
	size uint64
}

// NewRadixTwoFri creates an FFT-like oracle proof of proximitys.
// The size
func NewRadixTwoFri(size uint64, h hash.Hash) RadixTwoFri {

	var res RadixTwoFri

	// computing the number of steps
	n := ecc.NextPowerOfTwo(size)
	nbSteps := bits.TrailingZeros(uint(n))
	res.nbSteps = nbSteps
	res.size = size

	// hash function
	res.h = h

	return res
}

// verifyProofOfProximitySingleRound verifies the proof of proximit (see gnark-crypto).
func (s RadixTwoFri) verifyProofOfProximitySingleRound(api frontend.API, salt frontend.Variable, proof Round) error {

	// Fiat Shamir transcript to derive the challenges
	// We take care that the namings fit on frSize bytes, to be consistent
	// with the snark circuit, where the names are interpreted as frontend.Variable,
	// with size on FrSize bytes.
	frSize := api.Curve().Info().Fr.Bytes
	xis := make([]string, s.nbSteps+1)
	for i := 0; i < s.nbSteps; i++ {
		xis[i] = paddNaming(fmt.Sprintf("x%d", i), frSize)
	}
	xis[s.nbSteps] = paddNaming("s0", frSize)
	fs := fiatshamir.NewTranscript(api, s.h, xis...)
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
	api.FromBinary(bin[:logRho+s.nbSteps]...)

	// _, err = api.NewHint(DeriveQueriesPositions, s.nbSteps, bPos, s.size, s.nbSteps)
	// if err != nil {
	// 	return err
	// }
	// for i := 0; i < len(si); i++ {
	// 	api.Println(si[i])
	// }

	return nil
}
