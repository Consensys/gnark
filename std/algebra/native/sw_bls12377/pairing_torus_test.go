// Copyright 2020-2026 Consensys Software Inc.
// Licensed under the Apache License, Version 2.0. See the LICENSE file for details.

package sw_bls12377

import (
	"fmt"
	"testing"

	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/profile"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test"
)

type pairingCheckTorusBLS377 struct {
	P1, P2 G1Affine
	Q1, Q2 G2Affine
}

func (circuit *pairingCheckTorusBLS377) Define(api frontend.API) error {
	err := PairingCheckTorus(api, []G1Affine{circuit.P1, circuit.P2}, []G2Affine{circuit.Q1, circuit.Q2})
	if err != nil {
		return fmt.Errorf("pair: %w", err)
	}
	return nil
}

func TestPairingCheckTorusBLS377(t *testing.T) {
	// pairing test data
	P, Q := pairingCheckData()
	witness := pairingCheckTorusBLS377{
		P1: NewG1Affine(P[0]),
		P2: NewG1Affine(P[1]),
		Q1: NewG2Affine(Q[0]),
		Q2: NewG2Affine(Q[1]),
	}
	assert := test.NewAssert(t)
	assert.CheckCircuit(&pairingCheckTorusBLS377{}, test.WithValidAssignment(&witness), test.WithCurves(ecc.BW6_761), test.NoProverChecks())
}

// bench
func BenchmarkPairingCheckTorus(b *testing.B) {
	c := pairingCheckTorusBLS377{}
	p := profile.Start()
	_, _ = frontend.Compile(ecc.BLS12_377.ScalarField(), scs.NewBuilder, &c)
	p.Stop()
	fmt.Println("PairingCheckTorus(2): ", p.NbConstraints())
}
