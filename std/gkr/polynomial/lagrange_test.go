package polynomial

import (
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/stretchr/testify/assert"
)

func TestLagrangeCoefficients(t *testing.T) {
	domain := 7
	value := 2

	var zero fr.Element
	var one fr.Element
	one.SetOne()

	lagrangePolynomial := GetLagrangePolynomial(domain)[value]
	for i := 0; i < domain; i++ {
		var x fr.Element
		x.SetUint64(uint64(i))
		y := EvaluatePolynomial(lagrangePolynomial, x)
		if i == value {
			assert.Equal(t, y, one, "Should have been one")
		} else {
			assert.Equal(t, y, zero, "Should have been zero")
		}
	}
}
