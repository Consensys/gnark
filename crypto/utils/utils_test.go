package utils

import (
	"math/big"
	"testing"

	"github.com/consensys/gurvy/ecc/bn254/fr"
)

func TestFromInterfaceValidFormats(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("valid input should not panic")
		}
	}()

	var a fr.Element
	a.SetRandom()

	_ = FromInterface(a)
	_ = FromInterface(&a)
	_ = FromInterface(12)
	_ = FromInterface(big.NewInt(-42))
	_ = FromInterface(*big.NewInt(42))
	_ = FromInterface("8000")

}
