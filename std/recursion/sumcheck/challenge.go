package sumcheck

import (
	"fmt"
	"math/big"
	"slices"

	cryptofiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/emulated"
)

// getChallengeNames returns all the challenge names used in the sumcheck
// protocol given the prefix, number of claims and number of variables.
func getChallengeNames(prefix string, nbClaims int, nbVars int) []string {
	var challengeNames []string
	if nbClaims > 1 {
		challengeNames = []string{prefix + "comb"}
	}
	for i := 0; i < nbVars; i++ {
		challengeNames = append(challengeNames, fmt.Sprintf("%spSP.%d", prefix, i))
	}
	return challengeNames
}

// bindChallengeProver binds the values for challengeName using native Fiat-Shamir transcript.
func bindChallengeProver(fs *cryptofiatshamir.Transcript, challengeName string, values []*big.Int) error {
	for i := range values {
		buf := make([]byte, 32)
		values[i].FillBytes(buf)
		if err := fs.Bind(challengeName, buf); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

// deriveChallengeProver binds the values for challengeName and then returns the
// challenge using native Fiat-Shamir transcript. It also returns the rest of
// the challenge names for used in the protocol.
func deriveChallengeProver(fs *cryptofiatshamir.Transcript, challengeNames []string, values []*big.Int) (challenge *big.Int, restChallengeNames []string, err error) {
	if err = bindChallengeProver(fs, challengeNames[0], values); err != nil {
		return nil, nil, fmt.Errorf("bind: %w", err)
	}
	nativeChallenge, err := fs.ComputeChallenge(challengeNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("compute challenge %s: %w", challengeNames[0], err)
	}
	challenge = new(big.Int).SetBytes(nativeChallenge)
	return challenge, challengeNames[1:], nil
}

// bindChallenge binds the values for challengeName using in-circuit Fiat-Shamir transcript.
func (v *Verifier[FR]) bindChallenge(fs *fiatshamir.Transcript, challengeName string, values []emulated.Element[FR]) error {
	for i := range values {
		bts := v.f.ToBits(&values[i])
		slices.Reverse(bts)
		if err := fs.Bind(challengeName, bts); err != nil {
			return fmt.Errorf("bind challenge %s %d: %w", challengeName, i, err)
		}
	}
	return nil
}

// deriveChallenge binds the values for challengeName and then returns the
// challenge using in-circuit Fiat-Shamir transcript. It also returns the rest
// of the challenge names for used in the protocol.
func (v *Verifier[FR]) deriveChallenge(fs *fiatshamir.Transcript, challengeNames []string, values []emulated.Element[FR]) (challenge *emulated.Element[FR], restChallengeNames []string, err error) {
	var fr FR
	if err = v.bindChallenge(fs, challengeNames[0], values); err != nil {
		return nil, nil, fmt.Errorf("bind: %w", err)
	}
	nativeChallenge, err := fs.ComputeChallenge(challengeNames[0])
	if err != nil {
		return nil, nil, fmt.Errorf("compute challenge %s: %w", challengeNames[0], err)
	}
	// TODO: when implementing better way (construct from limbs instead of bits) then change
	chBts := bits.ToBinary(v.api, nativeChallenge, bits.WithNbDigits(fr.Modulus().BitLen()))
	challenge = v.f.FromBits(chBts...)
	return challenge, challengeNames[1:], nil
}
