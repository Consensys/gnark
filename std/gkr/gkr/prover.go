package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	poseidon2 "github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"github.com/consensys/gnark/std/gkr/circuit"
	"github.com/consensys/gnark/std/gkr/common"
	"github.com/consensys/gnark/std/gkr/polynomial"
	"github.com/consensys/gnark/std/gkr/sumcheck"
	"github.com/consensys/gnark/std/hash/poseidon"
	"github.com/ethereum/go-ethereum/crypto"
)

// Prover contains all relevant data for a GKR prover
type Prover struct {
	bN          int
	circuit     circuit.Circuit
	assignment  circuit.Assignment
	initialHash *fr.Element
}

// Proof contains all the data for a GKR to be verified
type Proof struct {
	SumcheckProofs []sumcheck.Proof
	ClaimsLeft     []fr.Element
	ClaimsRight    []fr.Element
}

// NewProver returns a new prover
func NewProver(circuit circuit.Circuit, assignment circuit.Assignment, initialHash *fr.Element) Prover {
	bN := common.Log2Ceil(len(assignment.Values[0])*len(assignment.Values[0][0])) - circuit.Layers[0].BGInputs
	return Prover{
		bN:          bN,
		circuit:     circuit,
		assignment:  assignment,
		initialHash: initialHash,
	}
}

// GetInitialQPrimeAndQ returns the initial randomness of the protocol
func GetInitialQPrimeAndQ(bN, bG int) ([]fr.Element, []fr.Element) {
	q := make([]fr.Element, bG)
	qPrime := make([]fr.Element, bN)

	// actually compute qInitial and qPrimeInitial
	// TODO: Uses actual randomness
	for i := range q {
		q[i].SetUint64(uint64(i + 1))
	}

	for i := range qPrime {
		qPrime[i].SetUint64(uint64(i + 1))
	}

	return qPrime, q
}

// GetInitialQPrimeAndQAndInput it depends on the inputs
func GetInitialQPrimeAndQAndInput(bN, bG int, inputs []fr.Element) ([]fr.Element, []fr.Element) {
	q := make([]fr.Element, bG)
	qPrime := make([]fr.Element, bN)

	// actually compute qInitial and qPrimeInitial
	// TODO: Uses actual randomness
	for i := range q {
		q[i].SetUint64(uint64(i + 1))
	}

	bytesSeed := make([]byte, 0)
	for i := range inputs {
		b := inputs[i].Bytes()
		bytesSeed = append(bytesSeed, b[:]...)
	}
	seed := crypto.Keccak256Hash(bytesSeed).Bytes()
	for i := range qPrime {
		qPrime[i].SetBytes(seed)
		qPrime[i].Add(&qPrime[i], new(fr.Element).SetUint64(uint64(i+1)))
	}

	return qPrime, q
}

// GetInitialQPrimeAndQAndInitialHash it depends on the inputs
func GetInitialQPrimeAndQAndInitialHash(bN, bG int, initialHash *fr.Element) ([]fr.Element, []fr.Element) {
	q := make([]fr.Element, bG)
	qPrime := make([]fr.Element, bN)

	// actually compute qInitial and qPrimeInitial
	for i := range q {
		q[i] = *poseidon2.Poseidon(initialHash, new(fr.Element).SetUint64(uint64(i)))
	}

	for i := range qPrime {
		qPrime[i] = *poseidon2.Poseidon(initialHash, new(fr.Element).SetUint64(uint64(i)))
	}

	return qPrime, q
}

// GetBookKeepingTablesForInitialRound generates and prefold the book-keeping tables for a the initial GKR round
func (p *Prover) GetBookKeepingTablesForInitialRound(
	qPrime, q []fr.Element, nCore int,
) (
	vL, vR, eq []polynomial.BookKeepingTable,
	statics []polynomial.BookKeepingTable,
) {
	// For the initial round, we always take the last layer
	layer := len(p.circuit.Layers) - 1
	// Compute the static tables
	statics = p.circuit.Layers[layer].GetStaticTable(q)
	// And gate the remaining table
	vL = p.assignment.LayerAsBKTWithCopy(layer, nCore)
	vR = p.assignment.LayerAsBKTWithCopy(layer, nCore)
	eq = polynomial.GetChunkedEqTable(qPrime, len(vL), nCore)
	return vL, vR, eq, statics
}

// GetBookKeepingTablesForIntermediateRound generates and prefold the book-keeping tables for an intermediate round
func (p *Prover) GetBookKeepingTablesForIntermediateRound(
	layer int,
	qPrime, qL, qR []fr.Element,
	lambdaL, lambdaR fr.Element,
	nCore int,
) (
	vL, vR, eq []polynomial.BookKeepingTable,
	statics []polynomial.BookKeepingTable,
) {
	// First vL
	vL = p.assignment.LayerAsBKTWithCopy(layer, nCore)
	vR = p.assignment.LayerAsBKTWithCopy(layer, nCore)
	eq = polynomial.GetChunkedEqTable(qPrime, len(vL), nCore)

	// Get the static tables
	staticsL := p.circuit.Layers[layer].GetStaticTable(qL)
	staticsR := p.circuit.Layers[layer].GetStaticTable(qR)
	// Statics is placeholder for the last
	statics = make([]polynomial.BookKeepingTable, len(staticsL))

	// Then the staticTables in the order given by
	for i := range statics {
		statics[i] = polynomial.LinearCombinationOfBookKeepingTables(
			staticsL[i],
			staticsR[i],
			lambdaL,
			lambdaR,
		)
	}
	return vL, vR, eq, statics
}

// InitialRoundSumcheckProver returns a prover object for the initial round
func (p *Prover) InitialRoundSumcheckProver(qPrime []fr.Element, q []fr.Element, nCore int) sumcheck.MultiThreadedProver {
	layer := len(p.circuit.Layers)
	vL, vR, eq, statics := p.GetBookKeepingTablesForInitialRound(qPrime, q, nCore)
	return sumcheck.NewMultiThreadedProver(vL, vR, eq, p.circuit.Layers[layer-1].Gates, statics)
}

// IntermediateRoundsSumcheckProver returns a prover object for the intermediate round
func (p *Prover) IntermediateRoundsSumcheckProver(
	layer int,
	qPrime, qL, qR []fr.Element,
	lambdaL, lambdaR fr.Element,
	nCore int,
) sumcheck.MultiThreadedProver {
	vL, vR, eq, statics := p.GetBookKeepingTablesForIntermediateRound(layer, qPrime, qL, qR, lambdaL, lambdaR, nCore)
	return sumcheck.NewMultiThreadedProver(vL, vR, eq, p.circuit.Layers[layer].Gates, statics)
}

// Prove produces a GKR proof
func (p *Prover) Prove(nCore int, challenges ...string) Proof {
	// bG := p.circuit.bG
	nLayers := len(p.circuit.Layers)
	ClaimsLeft := make([]fr.Element, nLayers)
	ClaimsRight := make([]fr.Element, nLayers)
	SumcheckProofs := make([]sumcheck.Proof, nLayers)

	// Initial round, here we use the inputs layer as randomness, for specific inputs, we got specific assignment
	qPrime, q := GetInitialQPrimeAndQAndInitialHash(p.bN, p.circuit.Layers[nLayers-1].BGOutputs, p.initialHash)
	transcript := fiatshamir.NewTranscript(poseidon.NewPoseidon(), challenges...)
	qqPrime := append(q, qPrime...)
	bytes := make([]byte, 0)
	for i := range qqPrime {
		qqPrimeBytes := qqPrime[i].Bytes()
		bytes = append(bytes, qqPrimeBytes[:]...)
	}
	transcript.Bind(challenges[0], bytes)
	prover := p.InitialRoundSumcheckProver(qPrime, q, nCore)
	proof, qPrime, qL, qR, finalClaims := prover.Prove(nCore, &transcript, nLayers-1)
	SumcheckProofs[nLayers-1] = proof
	ClaimsLeft[nLayers-1], ClaimsRight[nLayers-1] = finalClaims[0], finalClaims[1]

	for layer := nLayers - 2; layer >= 0; layer-- {

		// Compute the random linear comb of the claims
		var lambdaL fr.Element
		lambdaL.SetOne()
		challengeName := fmt.Sprintf("layers.%d.next", layer)
		lambdaR := common.GetChallengeByTranscript([]fr.Element{ClaimsLeft[layer+1], ClaimsRight[layer+1]}, &transcript, challengeName)
		claim := ClaimsRight[layer+1]
		claim.Mul(&claim, &lambdaR)
		claim.Add(&claim, &ClaimsLeft[layer+1])

		// Intermediate round sumcheck and update the GKR proof
		prover := p.IntermediateRoundsSumcheckProver(layer, qPrime, qL, qR, lambdaL, lambdaR, nCore)
		SumcheckProofs[layer], qPrime, qL, qR, finalClaims = prover.Prove(nCore, &transcript, layer)
		ClaimsLeft[layer], ClaimsRight[layer] = finalClaims[0], finalClaims[1]
	}

	return Proof{
		SumcheckProofs: SumcheckProofs,
		ClaimsLeft:     ClaimsLeft,
		ClaimsRight:    ClaimsRight,
	}

}
