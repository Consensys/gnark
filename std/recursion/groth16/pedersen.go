package groth16

import (
	"fmt"

	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra"
	"github.com/consensys/gnark/std/math/emulated"
)

type PedersenCommitmentKey[G2El algebra.G2ElementT] struct {
	G             G2El
	GRootSigmaNeg G2El
}

func FoldCommitments[FR emulated.FieldParams, G1El algebra.G1ElementT](api frontend.API, scalarApi *emulated.Field[FR], curve algebra.Curve[FR, G1El], commitments []G1El, fiatshamirSeeds ...[]frontend.Variable) (commitment G1El, err error) {
	if len(commitments) == 1 { // no need to fold
		commitment = commitments[0]
		return
	} else if len(commitments) == 0 { // nothing to do at all
		return
	}

	err = fmt.Errorf("folding with more than one commitment is not supported yet")
	return
}

func (v *Verifier[FR, G1El, G2El, GtEl]) AssertCommitment(vk VerifyingKey[G1El, G2El, GtEl], commitment, knowledgeProof G1El) {
	v.pairing.AssertIsOnG1(&commitment)
	v.pairing.AssertIsOnG1(&knowledgeProof)

	v.pairing.PairingCheck([]*G1El{&commitment, &knowledgeProof}, []*G2El{&vk.CommitmentKey.G, &vk.CommitmentKey.GRootSigmaNeg})
}
