package backend

import (
	"math/big"
	"testing"

	"github.com/consensys/gurvy/bn256/fr"
)

func TestBigIntFromInterface(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("should not panic")
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
