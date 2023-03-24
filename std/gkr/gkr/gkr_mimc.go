package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr/snark/gkr"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
)

type GkrCircuitSlice struct {
	Circuit                 gkr.Circuit
	Proof                   gkr.Proof
	QInitial, QInitialprime []frontend.Variable
	VInput, VOutput         polynomial.MultilinearByValues
}

type GkrCircuit [7]GkrCircuitSlice

func (g *GkrCircuit) AllocateGKRCircuit(bN int) {
	for i := range g {
		g[i] = AllocateGKRMimcTestCircuitBatch(bN, i)
	}
}

func (g *GkrCircuit) AssertValid(api frontend.API) {
	for _, c := range g {
		c.Proof.AssertValid(api, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	}
}

func AllocateGKRMimcTestCircuit(bN int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuit()
	return GkrCircuitSlice{
		Circuit:       circuit,
		Proof:         gkr.AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: make([]frontend.Variable, bN),
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func AllocateGKRMimcTestCircuitBatch(bN int, batch int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuitBatch(batch)
	qInitialPrime := make([]frontend.Variable, bN)
	for i := range qInitialPrime {
		qInitialPrime[i] = 0
	}
	return GkrCircuitSlice{
		Circuit:       circuit,
		Proof:         gkr.AllocateProof(bN, circuit),
		QInitial:      []frontend.Variable{},
		QInitialprime: qInitialPrime,
		VInput:        polynomial.AllocateMultilinear(bN + 1),
		VOutput:       polynomial.AllocateMultilinear(bN),
	}
}

func (c *GkrCircuitSlice) Assign(
	proof Proof,
	inputs [][]fr.Element,
	outputs [][]fr.Element,
	qInitialprime []fr.Element,
) {
	for k := range c.Proof.SumcheckProofs {
		c.Proof.SumcheckProofs[k].Assign(proof.SumcheckProofs[k])
		c.Proof.ClaimsLeft[k] = proof.ClaimsLeft[k]
		c.Proof.ClaimsRight[k] = proof.ClaimsRight[k]
	}
	for i := range qInitialprime {
		c.QInitialprime[i] = qInitialprime[i]
	}
	c.VInput.AssignFromChunkedBKT(inputs)
	c.VOutput.AssignFromChunkedBKT(outputs)
}

func (c *GkrCircuitSlice) Define(cs frontend.API) error {
	c.Proof.AssertValid(cs, c.Circuit, c.QInitial, c.QInitialprime, c.VInput, c.VOutput)
	return nil
}
