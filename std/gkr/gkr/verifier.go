package gkr

import (
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/polynomial"
	"github.com/consensys/gnark/std/gkr/sumcheck"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// Verifier contains all the data relevant for the verifier algorithm of GKR
type Verifier struct {
	bN      int
	circuit circuit.Circuit
}

// NewVerifier constructs a new verifier object
func NewVerifier(bN int, circuit circuit.Circuit) Verifier {
	return Verifier{
		bN:      bN,
		circuit: circuit,
	}
}

// Verify returns true if the GKR proof is valid
func (v *Verifier) Verify(
	proof Proof,
	inputs, outputs [][]fr.Element,
) bool {

	nLayers := len(v.circuit.Layers)

	qPrime, q := GetInitialQPrimeAndQAndInput(v.bN, v.circuit.Layers[nLayers-1].BGOutputs, inputs[0])
	var qL, qR []fr.Element

	claim := polynomial.EvaluateChunked(
		polynomial.AsChunkedBookKeepingTable(outputs),
		append(append([]fr.Element{}, q...), qPrime...),
	)

	sumcheckVerifier := sumcheck.Verifier{}
	valid, nextQPrime, nextQL, nextQR, totalClaim := sumcheckVerifier.Verify(
		claim,
		proof.SumcheckProofs[nLayers-1],
		v.bN, v.circuit.Layers[nLayers-1].BGInputs,
	)

	if !valid {
		// The sumcheck proof is broken
		return false
	}
	evalEq := polynomial.EvalEq(qPrime, nextQPrime)
	evaluated := circuit.EvaluateCombinator(
		&proof.ClaimsLeft[nLayers-1],
		&proof.ClaimsRight[nLayers-1],
		&evalEq,
		v.circuit.Layers[nLayers-1].Gates,
		v.evaluateStaticTables(nLayers-1, q, nextQL, nextQR),
	)

	if totalClaim != evaluated {
		// The sumcheck claim was inconsistent with the values claimed in the proof
		return false
	}

	for layer := nLayers - 2; layer >= 0; layer-- {
		// Compute the random linear comb of the claims
		var lambdaL fr.Element
		lambdaL.SetOne()
		lambdaR := common.GetChallenge([]fr.Element{proof.ClaimsLeft[layer+1], proof.ClaimsRight[layer+1]})
		claim = proof.ClaimsRight[layer+1]
		claim.Mul(&claim, &lambdaR)
		claim.Add(&claim, &proof.ClaimsLeft[layer+1])

		// Updates qL and qR values to initialize the next round
		qL = nextQL
		qR = nextQR
		qPrime = nextQPrime

		valid, nextQPrime, nextQL, nextQR, totalClaim = sumcheckVerifier.Verify(
			claim, proof.SumcheckProofs[layer],
			v.bN, v.circuit.Layers[layer].BGInputs,
		)
		if !valid {
			// The sumcheck proof is broken
			return false
		}

		eqEval := polynomial.EvalEq(qPrime, nextQPrime)
		if totalClaim != circuit.EvaluateCombinator(
			&proof.ClaimsLeft[layer],
			&proof.ClaimsRight[layer],
			&eqEval,
			v.circuit.Layers[layer].Gates,
			v.evaluateStaticTablesLinCombs(layer, qL, qR, nextQL, nextQR, lambdaL, lambdaR),
		) {
			// The sumcheck claim was inconsistent with the values claimed in the proof
			return false
		}
	}

	// Final check => Check consistency with the last claims
	// on vL and vR with the values given as inputs
	//vL, vR from inputs
	actualVL, actualVR := polynomial.EvaluateMixedChunked(
		polynomial.AsChunkedBookKeepingTable(inputs),
		nextQPrime, nextQL, nextQR)
	if actualVL != proof.ClaimsLeft[0] || actualVR != proof.ClaimsRight[0] {
		return false
	}

	return true
}

func (v *Verifier) evaluateStaticTables(layer int, q, nextQL, nextQR []fr.Element) []fr.Element {
	tables := v.circuit.Layers[layer].GetStaticTable(q)
	evals := make([]fr.Element, len(tables))
	for i := range tables {
		evals[i] = tables[i].Evaluate(append(nextQL, nextQR...))
	}
	return evals
}

func (v *Verifier) evaluateStaticTablesLinCombs(layer int, qL, qR, nextQL, nextQR []fr.Element, lambdaL, lambdaR fr.Element) []fr.Element {
	tablesL := v.circuit.Layers[layer].GetStaticTable(qL)
	tablesR := v.circuit.Layers[layer].GetStaticTable(qR)
	evals := make([]fr.Element, len(tablesL))
	for i := range tablesL {
		left := tablesL[i].Evaluate(append(nextQL, nextQR...))
		right := tablesR[i].Evaluate(append(nextQL, nextQR...))
		right.Mul(&right, &lambdaR)
		left.Mul(&left, &lambdaL)
		left.Add(&left, &right)
		evals[i] = left
	}
	return evals
}
