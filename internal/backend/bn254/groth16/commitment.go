package groth16

import (
	curve "github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	c "github.com/consensys/gnark/internal/commitment"
	"math/big"
)

func solveCommitmentWire(commitmentInfo *c.Info, commitment *curve.G1Affine, publicCommitted []*big.Int) (fr.Element, error) {
	res, err := fr.Hash(commitmentInfo.SerializeCommitment(commitment.Marshal(), publicCommitted, (fr.Bits-1)/8+1), []byte(c.Dst), 1)
	return res[0], err
}
