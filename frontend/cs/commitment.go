package cs

import (
	"fmt"
	"github.com/consensys/gnark/constraint/solver"
	"github.com/consensys/gnark/debug"
	"github.com/consensys/gnark/logger"
	"math/big"
	"os"
	"strings"
)

func Bsb22CommitmentComputePlaceholder(_ *big.Int, _ []*big.Int, output []*big.Int) error {
	if (len(os.Args) > 0 && (strings.HasSuffix(os.Args[0], ".test") || strings.HasSuffix(os.Args[0], ".test.exe"))) || debug.Debug {
		// usually we only run solver without prover during testing
		log := logger.Logger()
		log.Error().Msg("Augmented groth16 commitment hint not replaced. Proof will not be sound!")
		output[0].SetInt64(0)
		return nil
	}
	return fmt.Errorf("placeholder function: to be replaced by commitment computation")
}

func init() {
	solver.RegisterHint(Bsb22CommitmentComputePlaceholder)
}
