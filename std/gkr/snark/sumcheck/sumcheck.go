package sumcheck

import (
	"fmt"
	fiatshamir "github.com/consensys/gnark/std/fiat-shamir"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
	"github.com/consensys/gnark/std/gkr/sumcheck"

	"github.com/consensys/gnark/frontend"
)

// Proof contains the circuit data of a sumcheck run EXCEPT WHAT IS REQUIRED FOR THE FINAL CHECK.
type Proof struct {
	// bN           int
	// bG           int
	// InitialClaim frontend.Variable
	HPolys []polynomial.Univariate
}

// AllocateProof allocates an empty sumcheck verifier
func AllocateProof(bN, bG, degHL, degHR, degHPrime int) Proof {
	hPolys := make([]polynomial.Univariate, bN+2*bG)
	for i := 0; i < bG; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHL)
	}
	for i := bG; i < 2*bG; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHR)
	}
	for i := 2 * bG; i < 2*bG+bN; i++ {
		hPolys[i] = polynomial.AllocateUnivariate(degHPrime)
	}

	return Proof{
		HPolys: hPolys,
	}
}

// Assign values for the sumcheck verifier
func (p *Proof) Assign(proof sumcheck.Proof) {
	if len(proof.PolyCoeffs) != len(p.HPolys) {
		panic(
			fmt.Sprintf("Inconsistent assignment lenght: expected %v, but got %v", len(p.HPolys), len(proof.PolyCoeffs)),
		)
	}
	for i, poly := range proof.PolyCoeffs {
		p.HPolys[i].Assign(poly)
	}
}

// AssertValid verifies a sumcheck instance EXCEPT FOR THE FINAL VERIFICATION.
func (p *Proof) AssertValid(cs frontend.API, initialClaim frontend.Variable, bG int, transcript *fiatshamir.Transcript, layers int) (
	hL, hR, hPrime []frontend.Variable,
	lastClaim frontend.Variable,
) {
	// initialize current claim:
	claimCurr := initialClaim
	hs := make([]frontend.Variable, len(p.HPolys))

	for i, poly := range p.HPolys {
		zeroAndOne := poly.ZeroAndOne(cs)
		cs.AssertIsEqual(zeroAndOne, claimCurr)
		challengeName := fmt.Sprintf("layers.%d.hpolys.%d", layers, i)
		transcript.Bind(challengeName, poly.Coefficients)
		var err error
		hs[i], err = transcript.ComputeChallenge(challengeName) // Hash the polynomial
		if err != nil {
			panic(err)
		}
		claimCurr = poly.Eval(cs, hs[i]) // Get new current claim
	}

	// A deep-copy to avoid reusing the same underlying slice for all writes
	hL = append([]frontend.Variable{}, hs[:bG]...)
	hR = append([]frontend.Variable{}, hs[bG:2*bG]...)
	hPrime = append([]frontend.Variable{}, hs[2*bG:]...)

	return hL, hR, hPrime, claimCurr
}

func getLeftRightSeed(cs frontend.API, challengeSeed []frontend.Variable) (frontend.Variable, frontend.Variable) {
	mid := len(challengeSeed) / 2
	challengeSeed0, challengeSeed1 := challengeSeed[:mid], challengeSeed[mid:]
	leftSeed := frontend.Variable(0)
	for i := range challengeSeed0 {
		leftSeed = cs.Add(leftSeed, challengeSeed0[i])
	}
	rightSeed := frontend.Variable(0)
	for i := range challengeSeed1 {
		rightSeed = cs.Add(rightSeed, challengeSeed1[i])
	}
	return leftSeed, rightSeed
}
