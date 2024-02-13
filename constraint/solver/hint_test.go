package solver

import "testing"

func TestRegexpRename(t *testing.T) {
	input := "github.com/consensys/gnark/internal/regression_tests/issue1045.init.func1"
	expected := "github.com/consensys/gnark/internal/regression_tests/issue1045.glob..func1"
	if got := newToOldStyle(input); got != expected {
		t.Errorf("expected %s, got %s", expected, got)
	}
}
