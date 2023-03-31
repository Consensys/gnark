package gkr

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/gkr/snark/gkr"
	"github.com/consensys/gnark/std/gkr/snark/polynomial"
)

type GkrCircuitSlice struct {
	Circuit         gkr.Circuit
	Proof           gkr.Proof
	bN              int
	VInput, VOutput polynomial.MultilinearByValues
}

type GkrCircuit [7]GkrCircuitSlice

func (g *GkrCircuit) AllocateGKRCircuit(bN int) {
	for i := range g {
		g[i] = AllocateGKRMimcTestCircuitBatch(bN, i)
	}
}

func (g *GkrCircuit) AssertValid(api frontend.API, committedVariable ...frontend.Variable) error {
	initialHash, err := api.Compiler().Commit(committedVariable...)
	if err != nil {
		return err
	}
	qPrimeInitial, qInitial := gkr.GetInitialQPrimeAndQAndInitialHash(api, g[0].bN, 0, initialHash)
	for _, c := range g {
		c.Proof.AssertValid(api, c.Circuit, c.VInput, c.VOutput, qPrimeInitial, qInitial)
	}
	return nil
}

func AllocateGKRMimcTestCircuit(bN int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuit()
	return GkrCircuitSlice{
		Circuit: circuit,
		Proof:   gkr.AllocateProof(bN, circuit),
		VInput:  polynomial.AllocateMultilinear(bN + 1),
		VOutput: polynomial.AllocateMultilinear(bN),
	}
}

func AllocateGKRMimcTestCircuitBatch(bN int, batch int) GkrCircuitSlice {
	circuit := gkr.CreateMimcCircuitBatch(batch)
	return GkrCircuitSlice{
		Circuit: circuit,
		Proof:   gkr.AllocateProof(bN, circuit),
		bN:      bN,
		VInput:  polynomial.AllocateMultilinear(bN + 1),
		VOutput: polynomial.AllocateMultilinear(bN),
	}
}

func (c *GkrCircuitSlice) Assign(
	proof Proof,
	inputs [][]fr.Element,
	outputs [][]fr.Element,
) {
	for k := range c.Proof.SumcheckProofs {
		c.Proof.SumcheckProofs[k].Assign(proof.SumcheckProofs[k])
		c.Proof.ClaimsLeft[k] = proof.ClaimsLeft[k]
		c.Proof.ClaimsRight[k] = proof.ClaimsRight[k]
	}
	c.VInput.AssignFromChunkedBKT(inputs)
	c.VOutput.AssignFromChunkedBKT(outputs)
}

func (c *GkrCircuitSlice) Define(cs frontend.API) error {
	initialHash, _ := cs.Compiler().Commit(c.VOutput.Table...)
	qPrimeInitial, qInitial := gkr.GetInitialQPrimeAndQAndInitialHash(cs, c.bN, 0, initialHash)
	c.Proof.AssertValid(cs, c.Circuit, c.VInput, c.VOutput, qPrimeInitial, qInitial)
	return nil
}
