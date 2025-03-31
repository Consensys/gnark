package smallfields

import (
	"math/big"

	"github.com/consensys/gnark-crypto/field/babybear"
	"github.com/consensys/gnark-crypto/field/koalabear"
	"github.com/consensys/gnark/internal/smallfields/tinyfield"
)

// IsSmallField returns true if the field is a small field. Small fields do not
// support pairing based backends, but are useful for testing and exporting to
// other proof systems.
func IsSmallField(field *big.Int) bool {
	if field.Cmp(tinyfield.Modulus()) == 0 {
		return true
	}
	if field.Cmp(babybear.Modulus()) == 0 {
		return true
	}
	if field.Cmp(koalabear.Modulus()) == 0 {
		return true
	}
	return false
}
