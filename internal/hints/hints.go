package hints

import (
	"crypto/rand"
	"errors"
	"math/big"
)

func Randomize(mod *big.Int, ins, outs []*big.Int) error {
	if len(ins) != 0 {
		return errors.New("randomize takes no input")
	}
	var err error
	for i := range outs {
		if outs[i], err = rand.Int(rand.Reader, mod); err != nil {
			return err
		}
	}
	return nil
}
