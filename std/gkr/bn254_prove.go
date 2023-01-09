package gkr

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/gkr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/mimc"
	fiatshamir "github.com/consensys/gnark-crypto/fiat-shamir"
	"math/big"
)

func bn254FrToBigInts(dst []*big.Int, src []fr.Element) {
	for i := range src {
		src[i].BigInt(dst[i])
	}
}

func bn254ProveHint(data bn254CircuitData, ins []*big.Int, outs []*big.Int) error {
	if len(ins) != 0 {
		return fmt.Errorf("the prove hint takes no input")
	}

	proof, err := gkr.Prove(data.circuit, data.assignments, fiatshamir.WithHash(mimc.NewMiMC()), gkr.WithPool(&data.memoryPool)) // TODO: Do transcriptSettings properly
	if err != nil {
		return err
	}

	// serialize proof: TODO: In gnark-crypto?
	offset := 0
	for i := range proof {
		for _, poly := range proof[i].PartialSumPolys {
			bn254FrToBigInts(outs[offset:], poly)
			offset += len(poly)
		}
		if proof[i].FinalEvalProof != nil {
			finalEvalProof := proof[i].FinalEvalProof.([]fr.Element)
			bn254FrToBigInts(outs[offset:], finalEvalProof)
			offset += len(finalEvalProof)
		}
	}
	return nil
}
