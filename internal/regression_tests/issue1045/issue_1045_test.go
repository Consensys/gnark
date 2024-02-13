package issue1045

import (
	"math/big"
	"testing"

	"github.com/consensys/gnark/constraint/solver"
)

const (
	explicitHintName  = "github.com/consensys/gnark/internal/regression_tests/issue1045.ExplicitHint"
	anonymousHintName = "github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1"
)

func ExplicitHint(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

var AnonymousHint = func(mod *big.Int, inputs []*big.Int, outputs []*big.Int) error {
	outputs[0].Set(inputs[0])
	return nil
}

func TestGetHintname(t *testing.T) {
	if resolvedExplicitHintName := solver.GetHintName(ExplicitHint); resolvedExplicitHintName != explicitHintName {
		t.Errorf("expected %s, got %s", explicitHintName, resolvedExplicitHintName)
	}
	if resolvedAnonymousHintName := solver.GetHintName(AnonymousHint); resolvedAnonymousHintName != anonymousHintName {
		t.Errorf("expected %s, got %s", anonymousHintName, resolvedAnonymousHintName)
	}
}
