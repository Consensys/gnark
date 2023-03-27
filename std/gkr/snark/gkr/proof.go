package gkr

import (
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
	"github.com/consensys/gnark/std/gkr/snark/sumcheck"
	"github.com/consensys/gnark/std/hash/poseidon"

	"github.com/consensys/gnark/frontend"
)

const nLayers = 13

// Proof represents a GKR proof
// Only valid for the MiMC circuit
type Proof struct {
	SumcheckProofs []sumcheck.Proof
	ClaimsLeft     []frontend.Variable
	ClaimsRight    []frontend.Variable
}

// AllocateProof allocates a new proof gadget
func AllocateProof(bN int, circuit Circuit) Proof {
	nLayers := len(circuit.Layers)
	SumcheckProofs := make([]sumcheck.Proof, nLayers)
	ClaimsLeft := make([]frontend.Variable, nLayers)
	ClaimsRight := make([]frontend.Variable, nLayers)

	for i := range SumcheckProofs {
		SumcheckProofs[i] = sumcheck.AllocateProof(bN, circuit.Layers[i].BG, circuit.Layers[i].DegHL, circuit.Layers[i].DegHR, circuit.Layers[i].DegHPrime)
	}

	for i := range ClaimsLeft {
		ClaimsLeft[i] = 0
		ClaimsRight[i] = 0
	}

	return Proof{
		SumcheckProofs: SumcheckProofs,
		ClaimsLeft:     ClaimsLeft,
		ClaimsRight:    ClaimsRight,
	}
}

// AssertValid runs the GKR verifier
func (p *Proof) AssertValid(
	cs frontend.API,
	circuit Circuit,
	qInitial []frontend.Variable,
	qPrimeInitial []frontend.Variable,
	vInput, vOutput polynomial.MultilinearByValues,
) {
	// record the gkr start position
	cs.AddGKRInputsAndOutputsMarks(vInput.Table, vOutput.Table)
	qqPrime := append(append([]frontend.Variable{}, qInitial...), qPrimeInitial...)
	claim := vOutput.Eval(cs, qqPrime)
	hL, hR, hPrime, expectedTotalClaim := p.SumcheckProofs[nLayers-1].AssertValid(cs, claim, circuit.Layers[nLayers-1].BG)
	actualTotalClaim := circuit.Layers[nLayers-1].Combine(
		cs,
		qInitial, qPrimeInitial,
		hL, hR, hPrime,
		p.ClaimsLeft[nLayers-1], p.ClaimsRight[nLayers-1],
	)
	cs.AssertIsEqual(expectedTotalClaim, actualTotalClaim)

	var qL, qR, qPrime []frontend.Variable

	for layer := nLayers - 2; layer >= 0; layer-- {
		lambdaL := 1
		lambdaR := poseidon.Poseidon(cs, p.ClaimsLeft[layer+1], p.ClaimsRight[layer+1])
		claim = cs.Add(p.ClaimsLeft[layer+1], cs.Mul(lambdaR, p.ClaimsRight[layer+1]))

		// Updates qL and qR values to initialize the next round
		qL = hL
		qR = hR
		qPrime = hPrime

		// Verify the sumcheck
		hL, hR, hPrime, expectedTotalClaim = p.SumcheckProofs[layer].AssertValid(cs, claim, circuit.Layers[layer].BG)
		actualTotalClaim = circuit.Layers[layer].CombineWithLinearComb(
			cs,
			qL, qR, qPrime,
			hL, hR, hPrime,
			lambdaL, lambdaR,
			p.ClaimsLeft[layer], p.ClaimsRight[layer],
		)
		cs.AssertIsEqual(expectedTotalClaim, actualTotalClaim)
	}

	actualVL, actualVR := p.ClaimsLeft[0], p.ClaimsRight[0]
	expectedVL, expectedVR := vInput.EvalMixed(cs, hL, hR, hPrime)

	cs.AssertIsEqual(expectedVL, actualVL)
	cs.AssertIsEqual(expectedVR, actualVR)
}
